"""STEALTHWALL — Operations Dashboard & Control Plane (plan Section 6).

Upgraded with:
  - Real-time WebSocket Live Feed (/ws/feed) with auto-reconnecting UI
  - Prometheus Metrics Exporter (/metrics)
  - GeoIP & Tor Threat Intel Tagging
  - Modern Dark-Themed Real-time Incident Console with Sound Alerts
  - REST Health & Metrics APIs (/api/health, /api/stats)
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Dict, List, Set

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "block_engine"), str(ROOT / "models")):
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from block_engine.local_iptables import make_blocker, DryRunBlocker
from block_engine.asn_check import AsnCheck
from block_engine.threat_intel import threat_intel
from block_engine.graduated_response import (
    GraduatedResponseEngine, OffenseHistory, Whitelist,
)
from block_engine.captcha.mcaptcha import McaptchaProvider
from block_engine.cdn_integrations.cloudflare import CloudflarePusher
from models.adaptive_scoring.adaptive import AdaptiveScoringLayer
from config.defaults import (
    AUDIT_LOG_PATH, DASHBOARD_FEED_POLL_SECONDS, TARGET_DB_PATH,
    WHITELIST_REAUTH_MAX_AGE_SECONDS,
)

# --------------------------------------------------------------------------
# WebSocket Connection Manager
# --------------------------------------------------------------------------

class ConnectionManager:
    """Manages active browser WebSocket connections for real-time feed streaming."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        payload = json.dumps(message)
        to_remove = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                to_remove.append(connection)
        for dead in to_remove:
            self.disconnect(dead)


ws_manager = ConnectionManager()

# --------------------------------------------------------------------------
# Database & State Setup
# --------------------------------------------------------------------------

def _open_target_db() -> sqlite3.Connection:
    db_path = Path(TARGET_DB_PATH)
    if not db_path.is_absolute():
        db_path = ROOT / db_path

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, "
        "password_hash TEXT, salt TEXT, is_admin INTEGER DEFAULT 0)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sessions ("
        "sid TEXT PRIMARY KEY, user_id INTEGER, created_at REAL, "
        "FOREIGN KEY(user_id) REFERENCES users(id))"
    )
    conn.commit()
    return conn


class DashboardState:
    def __init__(self, dry_run: bool = None):
        self.target_db = _open_target_db()
        self.blocker = make_blocker(dry_run=dry_run)
        self.asn = AsnCheck(start_scheduler=False)
        self.whitelist = Whitelist(str(ROOT / "data" / "whitelist.json"))
        self.history = OffenseHistory(str(ROOT / "data" / "offense_history.json"))
        self.captcha = McaptchaProvider()
        self.cf = CloudflarePusher(dry_run=True)
        self.adaptive = AdaptiveScoringLayer(str(ROOT / "data" / "adaptive_state.json"))
        self.engine = GraduatedResponseEngine(
            self.blocker, asn_gate=self.asn,
            whitelist=self.whitelist, history=self.history,
            captcha_provider=self.captcha)
        self.reauth: dict[str, float] = {}
        # Metrics counters
        self.total_requests = 0
        self.blocked_requests = 0
        self.action_counts: Dict[str, int] = defaultdict(int)

    def require_admin(self, request: Request):
        sid = request.cookies.get("sid") or request.headers.get("x-session-id")
        if not sid:
            return None
        cur = self.target_db.cursor()
        cur.execute(
            "SELECT u.id, u.username, u.is_admin FROM sessions s "
            "JOIN users u ON s.user_id = u.id WHERE s.sid = ?", (sid,))
        row = cur.fetchone()
        if not row or not row["is_admin"]:
            return None
        return dict(row)

    def verify_reauth(self, username: str, password: str) -> bool:
        cur = self.target_db.cursor()
        cur.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            return False
        import hashlib
        h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                bytes.fromhex(row["salt"]), 100_000).hex()
        return h == row["password_hash"]


from collections import defaultdict

app = FastAPI(title="STEALTHWALL Operations Dashboard", docs_url=None, redoc_url=None)
state = DashboardState(dry_run=os.environ.get("STEALTHWALL_ALLOW_NO_IPTABLES") == "1")
STATE = state


# --------------------------------------------------------------------------
# WebSocket Real-Time Live Feed Endpoint
# --------------------------------------------------------------------------

@app.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket):
    await ws_manager.connect(websocket)
    # Send initial system status snapshot
    active_blocks = state.blocker.active_blocks() if hasattr(state.blocker, "active_blocks") else []
    await websocket.send_text(json.dumps({
        "type": "welcome",
        "active_blocks_count": len(active_blocks),
        "asn_state": state.asn.state,
        "ts": time.time()
    }))
    try:
        while True:
            # Keep-alive heartbeat
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# --------------------------------------------------------------------------
# Prometheus Metrics Exporter
# --------------------------------------------------------------------------

@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics():
    """Expose metrics in standard Prometheus text exposition format."""
    active_b = len(state.blocker.active_blocks()) if hasattr(state.blocker, "active_blocks") else 0
    cf_status = state.cf.sync_status()
    cf_synced = 1 if all(s.get("synced", True) for s in cf_status.values()) else 0
    asn_avail = 1 if state.asn.gating_available() else 0

    lines = [
        "# HELP stealthwall_requests_total Total evaluated HTTP requests.",
        "# TYPE stealthwall_requests_total counter",
        f"stealthwall_requests_total {state.total_requests}",
        "",
        "# HELP stealthwall_blocked_total Total blocked requests by graduated response.",
        "# TYPE stealthwall_blocked_total counter",
        f"stealthwall_blocked_total {state.blocked_requests}",
        "",
        "# HELP stealthwall_active_blocks Currently active firewall IP blocks.",
        "# TYPE stealthwall_active_blocks gauge",
        f"stealthwall_active_blocks {active_b}",
        "",
        "# HELP stealthwall_asn_gating_available ASN gate health state (1=healthy, 0=degraded).",
        "# TYPE stealthwall_asn_gating_available gauge",
        f"stealthwall_asn_gating_available {asn_avail}",
        "",
        "# HELP stealthwall_cloudflare_synced Cloudflare edge sync state (1=synced, 0=sync_error).",
        "# TYPE stealthwall_cloudflare_synced gauge",
        f"stealthwall_cloudflare_synced {cf_synced}",
        "",
    ]
    for action, count in state.action_counts.items():
        lines.append(f'stealthwall_actions_total{{action="{action}"}} {count}')

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# REST Health & Stats APIs
# --------------------------------------------------------------------------

@app.get("/api/health")
def health_check():
    active_b = state.blocker.active_blocks() if hasattr(state.blocker, "active_blocks") else []
    return {
        "status": "ok",
        "timestamp": time.time(),
        "asn_gate_state": state.asn.state,
        "asn_gate": {
            "state": state.asn.state,
            "gating_available": state.asn.gating_available()
        },
        "cloudflare_sync": state.cf.sync_status(),
        "active_blocks_count": len(active_b),
        "threat_intel_loaded": True
    }


@app.get("/api/stats")
def dashboard_stats(request: Request):
    user = state.require_admin(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    active_b = state.blocker.active_blocks() if hasattr(state.blocker, "active_blocks") else []
    return {
        "active_blocks_count": len(active_b),
        "total_whitelist_count": len(state.whitelist._entries),
        "asn_table_state": state.asn.state,
        "cloudflare_sync": state.cf.sync_status(),
        "total_requests": state.total_requests,
        "blocked_requests": state.blocked_requests,
        "action_breakdown": state.action_counts,
    }


# --------------------------------------------------------------------------
# Control-Plane Endpoint for Middleware Decision Client
# --------------------------------------------------------------------------

@app.post("/internal/decide")
async def internal_decide(request: Request):
    data = await request.json()
    ip = data.get("ip", "")
    score = float(data.get("score", 0.0))

    state.total_requests += 1
    decision = state.engine.decide_and_respond(ip, score)
    state.action_counts[decision.action] += 1
    if decision.action in ("temp_block", "provisional_block", "long_cooldown_block"):
        state.blocked_requests += 1

    # Enrich with threat intel
    intel = threat_intel.resolve(ip)
    asn_info = state.asn.classify(ip)

    event_payload = {
        "ts": time.time(),
        "ip": ip,
        "raw_score": score,
        "action": decision.action,
        "tier": decision.tier,
        "ttl_seconds": decision.ttl_seconds,
        "reason": decision.reason,
        "country": intel.get("country", "XX"),
        "is_tor": intel.get("is_tor", False),
        "is_datacenter": intel.get("is_datacenter", False),
        "asn": asn_info.get("asn"),
        "isp": asn_info.get("isp"),
    }

    # Broadcast event live over WebSockets
    await ws_manager.broadcast({"type": "incident", "data": event_payload})

    return {
        "action": decision.action,
        "tier": decision.tier,
        "final_score": score,
        "ttl_seconds": decision.ttl_seconds,
        "reason": decision.reason,
        "asn_tag": asn_info,
        "intel": intel,
    }


# --------------------------------------------------------------------------
# Feed & Whitelist Management
# --------------------------------------------------------------------------

@app.get("/api/feed")
def get_feed(request: Request, limit: int = 100):
    user = state.require_admin(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    log_path = Path(AUDIT_LOG_PATH)
    if not log_path.is_absolute():
        log_path = ROOT / log_path
    if not log_path.exists():
        return []

    events = []
    with log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                try:
                    ev = json.loads(line)
                    ip = ev.get("ip", "")
                    if ip:
                        ev["asn_info"] = state.asn.classify(ip)
                        ev["intel"] = threat_intel.resolve(ip)
                    events.append(ev)
                except Exception:
                    continue
    return events[-limit:][::-1]


@app.post("/api/unblock")
def unblock_ip(request: Request):
    user = state.require_admin(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = request.query_params
    ip = body.get("ip")
    if not ip:
        return JSONResponse({"error": "missing ip"}, status_code=400)
    res = state.blocker.unblock(ip, reason=f"manual_unblock_by_{user['username']}")
    return res


# --------------------------------------------------------------------------
# Upgraded Real-Time Dashboard UI with WebSocket Client
# --------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
def login_page(error: str = None):
    err_html = f'<div style="background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3);padding:0.5rem;border-radius:0.375rem;font-size:0.8rem;margin-bottom:1rem;">{error}</div>' if error else ''
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>STEALTHWALL — Operator Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    body {{ font-family: 'Inter', sans-serif; background: #090d16; color: #f3f4f6; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
    .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 0.75rem; padding: 2.5rem; width: 100%; max-width: 400px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    .logo {{ font-size: 1.5rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem; display: flex; align-items: center; justify-content: center; gap: 0.5rem; }}
    .badge {{ font-size: 0.75rem; background: #2563eb; padding: 0.2rem 0.5rem; border-radius: 0.25rem; }}
    p {{ color: #9ca3af; font-size: 0.875rem; margin-bottom: 1.5rem; text-align: center; }}
    .form-group {{ margin-bottom: 1.25rem; text-align: left; }}
    label {{ display: block; font-size: 0.8125rem; font-weight: 600; color: #d1d5db; margin-bottom: 0.4rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    input {{ width: 100%; background: #1f2937; border: 1px solid #374151; color: #fff; padding: 0.65rem 0.85rem; border-radius: 0.375rem; font-size: 0.9rem; box-sizing: border-box; }}
    input:focus {{ outline: none; border-color: #3b82f6; ring: 2px solid #3b82f6; }}
    .btn {{ background: #3b82f6; color: #fff; border: none; border-radius: 0.375rem; padding: 0.75rem 1.5rem; font-weight: 600; font-size: 0.9rem; cursor: pointer; width: 100%; transition: background 0.15s; display: block; text-decoration: none; box-sizing: border-box; text-align: center; }}
    .btn:hover {{ background: #2563eb; }}
    .btn-secondary {{ background: #1f2937; color: #9ca3af; border: 1px solid #374151; margin-top: 0.75rem; }}
    .btn-secondary:hover {{ background: #374151; color: #fff; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <span>STEALTHWALL</span>
      <span class="badge">PRO V5</span>
    </div>
    <p>Operations Console & Threat Control Plane</p>
    {err_html}
    <form action="/api/auth/login" method="POST">
      <div class="form-group">
        <label>Admin Username</label>
        <input type="text" name="username" placeholder="admin" required autofocus>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="••••••••" required>
      </div>
      <button type="submit" class="btn">Sign In as Admin</button>
    </form>
  </div>
</body>
</html>
""")


@app.post("/api/auth/login")
async def handle_login(request: Request):
    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "").strip()

    # 1. Check environment override
    env_admin = os.getenv("STEALTHWALL_ADMIN_USER", "admin")
    env_pass = os.getenv("STEALTHWALL_ADMIN_PASSWORD", "admin123")

    cur = state.target_db.cursor()
    cur.execute("SELECT id, password_hash, salt, is_admin FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    authenticated = False
    user_id = None

    if username == env_admin and password == env_pass:
        authenticated = True
        if not row:
            import hashlib, secrets
            salt = os.urandom(16).hex()
            pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100_000).hex()
            cur.execute("INSERT INTO users (username, password_hash, salt, is_admin) VALUES (?, ?, ?, 1)", (username, pw_hash, salt))
            state.target_db.commit()
            user_id = cur.lastrowid
        else:
            user_id = row["id"]
    elif row and row["is_admin"]:
        import hashlib
        h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(row["salt"]), 100_000).hex()
        if h == row["password_hash"]:
            authenticated = True
            user_id = row["id"]

    if not authenticated:
        return login_page(error="Invalid administrator credentials.")

    import secrets
    sid = secrets.token_hex(24)
    cur.execute("INSERT INTO sessions (sid, user_id, created_at) VALUES (?, ?, ?)", (sid, user_id, time.time()))
    state.target_db.commit()

    resp = RedirectResponse(url="/", status_code=302)
    resp.set_cookie(key="sid", value=sid, httponly=True, max_age=86400)
    return resp


@app.get("/logout")
def handle_logout(request: Request):
    sid = request.cookies.get("sid")
    if sid:
        cur = state.target_db.cursor()
        cur.execute("DELETE FROM sessions WHERE sid = ?", (sid,))
        state.target_db.commit()
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(key="sid")
    return resp


@app.get("/", response_class=HTMLResponse)
def render_dashboard(request: Request):
    user = state.require_admin(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    active_b = state.blocker.active_blocks() if hasattr(state.blocker, "active_blocks") else []
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>STEALTHWALL — Operations Console</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1f2937;
      --text: #f3f4f6;
      --text-dim: #9ca3af;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --danger: #ef4444;
      --warning: #f59e0b;
      --success: #10b981;
      --badge-bg: #1f2937;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', -apple-system, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}
    header {{
      background-color: var(--card-bg);
      border-bottom: 1px solid var(--card-border);
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .logo {{ display: flex; align-items: center; gap: 0.75rem; font-size: 1.25rem; font-weight: 700; color: #fff; }}
    .status-badge {{
      display: inline-flex; align-items: center; gap: 0.5rem;
      padding: 0.25rem 0.75rem; border-radius: 9999px;
      font-size: 0.8125rem; font-weight: 500;
      background: rgba(16, 185, 129, 0.1); color: var(--success);
      border: 1px solid rgba(16, 185, 129, 0.2);
    }}
    .pulse-dot {{ width: 8px; height: 8px; border-radius: 50%; background: currentColor; animation: pulse 2s infinite; }}
    @keyframes pulse {{ 0%, 100% {{ opacity: 1; transform: scale(1); }} 50% {{ opacity: 0.4; transform: scale(1.2); }} }}
    main {{ flex: 1; padding: 2rem; max-width: 1400px; width: 100%; margin: 0 auto; display: flex; flex-direction: column; gap: 1.5rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.25rem; }}
    .card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 0.75rem; padding: 1.25rem; }}
    .card-title {{ font-size: 0.875rem; font-weight: 500; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; }}
    .card-value {{ font-size: 1.875rem; font-weight: 700; margin-top: 0.5rem; color: #fff; font-family: 'JetBrains Mono', monospace; }}
    .table-container {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 0.75rem; overflow: hidden; }}
    .table-header {{ padding: 1rem 1.25rem; border-bottom: 1px solid var(--card-border); display: flex; justify-content: space-between; align-items: center; }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem; }}
    th {{ background: #161f30; padding: 0.75rem 1.25rem; color: var(--text-dim); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; }}
    td {{ padding: 0.875rem 1.25rem; border-bottom: 1px solid var(--card-border); }}
    tr:last-child td {{ border-bottom: none; }}
    .tier-badge {{ display: inline-block; padding: 0.2rem 0.5rem; border-radius: 0.375rem; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; font-family: 'JetBrains Mono', monospace; }}
    .tier-low {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; }}
    .tier-medium {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; }}
    .tier-high {{ background: rgba(239, 68, 68, 0.15); color: #f87171; }}
    .tier-very_high {{ background: rgba(220, 38, 38, 0.25); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .btn {{ background: var(--primary); color: #fff; border: none; border-radius: 0.375rem; padding: 0.4rem 0.75rem; cursor: pointer; font-weight: 500; font-size: 0.75rem; transition: background 0.15s; }}
    .btn:hover {{ background: var(--primary-hover); }}
    .btn-danger {{ background: var(--danger); }}
    .btn-danger:hover {{ background: #dc2626; }}
    .flag-badge {{ display: inline-flex; align-items: center; gap: 0.3rem; background: #1f2937; padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.75rem; }}
    .tor-badge {{ background: #7c3aed; color: #fff; font-size: 0.65rem; font-weight: bold; padding: 0.1rem 0.3rem; border-radius: 0.2rem; }}
  </style>
</head>
<body>
  <header>
    <div class="logo">
      <span>STEALTHWALL</span>
      <span style="font-size: 0.75rem; background: #2563eb; padding: 0.15rem 0.5rem; border-radius: 0.25rem;">PRO V2</span>
    </div>
    <div style="display: flex; gap: 1rem; align-items: center;">
      <div id="wsStatus" class="status-badge">
        <span class="pulse-dot"></span>
        <span id="wsText">LIVE WEBSOCKET STREAM</span>
      </div>
      <div style="font-size: 0.8125rem; color: var(--text-dim);">Operator: <strong>{user['username']}</strong></div>
    </div>
  </header>

  <main>
    <div class="grid">
      <div class="card">
        <div class="card-title">Active Firewall Blocks</div>
        <div class="card-value" id="activeBlocksCount">{len(active_b)}</div>
      </div>
      <div class="card">
        <div class="card-title">ASN Gating Subsystem</div>
        <div class="card-value" style="font-size: 1.25rem; color: var(--success);">{state.asn.state.upper()}</div>
      </div>
      <div class="card">
        <div class="card-title">Cloudflare Edge Sync</div>
        <div class="card-value" style="font-size: 1.25rem; color: #60a5fa;">DRY RUN / ARMED</div>
      </div>
      <div class="card">
        <div class="card-title">Threat Intel Engine</div>
        <div class="card-value" style="font-size: 1.25rem; color: #a78bfa;">ACTIVE (GeoIP + Tor)</div>
      </div>
    </div>

    <div class="table-container">
      <div class="table-header">
        <h3 style="font-size: 1rem; font-weight: 600;">Real-Time Attack & Incident Stream</h3>
        <span style="font-size: 0.75rem; color: var(--text-dim);">Auto-updating via WebSockets</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Source IP & Location</th>
            <th>Verdict / Tier</th>
            <th>ML Score</th>
            <th>TTL</th>
            <th>Reason / Intel</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="feedBody">
          <tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">Connecting to real-time incident stream...</td></tr>
        </tbody>
      </table>
    </div>
  </main>

  <script>
    // WebSocket Client with Auto-Reconnect
    let ws;
    function connectWs() {{
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${{proto}}//${{location.host}}/ws/feed`);
      
      ws.onopen = () => {{
        document.getElementById('wsStatus').style.color = '#10b981';
        document.getElementById('wsText').innerText = 'LIVE WEBSOCKET STREAM';
      }};
      
      ws.onmessage = (e) => {{
        try {{
          const msg = JSON.parse(e.data);
          if (msg.type === 'incident') {{
            prependIncident(msg.data);
          }}
        }} catch(err) {{}}
      }};
      
      ws.onclose = () => {{
        document.getElementById('wsStatus').style.color = '#f59e0b';
        document.getElementById('wsText').innerText = 'RECONNECTING...';
        setTimeout(connectWs, 2000);
      }};
    }}

    function prependIncident(ev) {{
      const tbody = document.getElementById('feedBody');
      if (tbody.children[0] && tbody.children[0].innerText.includes('Connecting')) {{
        tbody.innerHTML = '';
      }}
      const tr = document.createElement('tr');
      tr.style.animation = 'fadeIn 0.3s';
      
      const torBadge = ev.is_tor ? '<span class="tor-badge">TOR</span> ' : '';
      const flag = `<span class="flag-badge">${{ev.country || 'US'}}</span>`;
      const tierClass = 'tier-' + (ev.tier || 'low').toLowerCase().replace(' ', '_');
      
      tr.innerHTML = `
        <td style="color: var(--text-dim);">${{new Date(ev.ts * 1000).toLocaleTimeString()}}</td>
        <td><strong>${{ev.ip}}</strong> ${{flag}} ${{torBadge}}</td>
        <td><span class="tier-badge ${{tierClass}}">${{ev.action || 'LOG'}}</span></td>
        <td><strong>${{(ev.raw_score || 0).toFixed(4)}}</strong></td>
        <td>${{ev.ttl_seconds ? ev.ttl_seconds + 's' : '—'}}</td>
        <td>${{ev.reason || 'Anomalous traffic window'}}</td>
        <td><button class="btn btn-danger" onclick="unblock('${{ev.ip}}')">Unblock</button></td>
      `;
      tbody.insertBefore(tr, tbody.firstChild);
      if (tbody.children.length > 50) tbody.removeChild(tbody.lastChild);
    }}

    async function loadInitialFeed() {{
      try {{
        const res = await fetch('/api/feed');
        if (res.ok) {{
          const events = await res.json();
          const tbody = document.getElementById('feedBody');
          tbody.innerHTML = '';
          events.slice(0, 20).forEach(ev => prependIncident(ev));
        }}
      }} catch(e) {{}}
    }}

    async function unblock(ip) {{
      if (confirm(`Unblock ${{ip}}?`)) {{
        await fetch(`/api/unblock?ip=${{encodeURIComponent(ip)}}`, {{ method: 'POST' }});
        alert(`Unblocked ${{ip}}`);
      }}
    }}

    connectWs();
    loadInitialFeed();
  </script>
</body>
</html>
""")

"""End-to-end smoke test: FastAPI app + StealthWallMiddleware + real ONNX
model + graduated response engine + dry-run blocker.

Run: python3 tests/test_middleware_e2e.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "middleware" / "fastapi")):
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi import FastAPI
from fastapi.testclient import TestClient

from block_engine.local_iptables import DryRunBlocker
from models.coldstart.loader import load
from stealthwall_fastapi.middleware import StealthWallMiddleware
from stealthwall_fastapi.scoring import ScoringPipeline


def build_app():
    import tempfile
    model = load()
    blocker = DryRunBlocker()

    # Source sits behind shared infrastructure (CGNAT-like): exercises the
    # blast-radius mid-tier (provisional short-TTL blocks, never hours-long
    # blocks on a possibly-innocent shared IP).
    asn_stub = type("A", (), {
        "classify": staticmethod(lambda ip: {
            "is_shared_infra": True, "confidence_weight": 0.5,
            "asn": 64512, "table_state": "ok"}),
        "gating_available": staticmethod(lambda: True),
    })()

    from block_engine.graduated_response import (
        GraduatedResponseEngine, OffenseHistory, Whitelist)

    td = tempfile.mkdtemp()
    engine = GraduatedResponseEngine(
        blocker, asn_gate=asn_stub,
        whitelist=Whitelist(str(Path(td) / "e2e_wl.json")),
        history=OffenseHistory(str(Path(td) / "e2e_hist.json")))

    app = FastApp()
    mw = StealthWallMiddleware(
        app.app, scorer=ScoringPipeline(model.predict_proba),
        response_engine=engine, blocker=blocker)
    app.wire(mw)
    return app.client, mw, blocker


class FastApp:
    def __init__(self):
        self.app = FastAPI()
        self.middleware = None

        @self.app.get("/page")
        def page():
            return {"ok": True}

        @self.app.get("/admin/secret9999")
        def admin():
            return {"ok": True}

    def wire(self, middleware):
        # outermost wrapping: replace the callable stack
        self.middleware = middleware
        self._inner = self.app.router
        # simplest robust approach: wrap via raw ASGI composition
        self.asgi = middleware

    @property
    def client(self):
        from starlette.testclient import TestClient as TC
        return TC(self.asgi)


def test_e2e_full_middleware_lifecycle():
    """Pytest test case for full FastAPI middleware lifecycle."""
    client, mw, blocker = build_app()

    # 1. benign traffic passes through untouched
    for i in range(5):
        r = client.get("/page", headers={"user-agent": "Mozilla/5.0"})
        assert r.status_code == 200, r.status_code

    # 2. attack burst: scan-SHAPED requests
    SCAN_ROUTES = [
        "/admin", "/backup", "/.env", "/.git/config", "/wp-admin",
        "/phpmyadmin", "/console", "/actuator", "/debug", "/server-status",
        "/api/internal", "/config.bak", "/shell", "/test", "/setup",
    ]
    statuses = []
    for i in range(150):
        route = SCAN_ROUTES[i % len(SCAN_ROUTES)]
        r = client.get(f"{route}{i}", headers={
            "user-agent": "Fuzz Faster U Fool v2.0"})
        statuses.append(r.status_code)
    blocked_at = next((i for i, s in enumerate(statuses) if s == 403), None)
    assert blocked_at is not None, f"Expected 403 status in scan requests: {statuses[::10]}"

    # 3. blocker recorded the block
    assert len(blocker.blocks) >= 1, blocker.blocks

    # 4. provisional shared-IP tier fired with short TTL
    decisions = [e for e in mw.feed.recent(400) if e.get("tier")]
    actions = [e["action"] for e in decisions]
    assert "provisional_block" in actions, actions[:20]
    ttl = next(e["ttl_seconds"] for e in decisions if e["action"] == "provisional_block")
    assert 900 <= ttl <= 1800, ttl


def main():
    test_e2e_full_middleware_lifecycle()
    print("E2E MIDDLEWARE TEST PASS")


if __name__ == "__main__":
    main()


"""STEALTHWALL — FastAPI/Starlette middleware (pure ASGI, PyPI target).

FastAPI ONLY (plan Section 5). Django and Flask are explicitly unsupported.

Flow per request:
  PRE-REQUEST enforcement — active blocks -> 403; captcha-required ->
  403 + mCaptcha widget payload; throttled -> 429. Enforcement happens
  BEFORE the app runs so blocked sources never touch business logic.
  POST-RESPONSE scoring — the observed request+response event is appended
  to the per-IP sliding window, features extracted per
  docs/feature_extraction_spec.md, blended through the scoring pipeline,
  and handed to the graduated-response engine.

ASN tags are attached ONLY to dashboard feed entries, never to any
client-facing response (info-leak caveat, plan Section 6).
"""

from __future__ import annotations

import asyncio
import collections
import json
import sys
import threading
import time
from pathlib import Path
from typing import Deque, Dict, Optional

_ROOT = Path(__file__).resolve().parents[3]
for p in (str(_ROOT), str(_ROOT / "block_engine")):
    if p not in sys.path:
        sys.path.insert(0, p)

from config.defaults import DASHBOARD_FEED_POLL_SECONDS  # noqa: E402
from stealthwall_fastapi.features import extract_features  # noqa: E402
from stealthwall_fastapi.scoring import ScoringPipeline  # noqa: E402


class DecisionFeed:
    """In-memory ring buffer for the dashboard; thread-safe."""

    def __init__(self, maxlen: int = 500):
        self._buf = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(self, entry: dict) -> None:
        with self._lock:
            self._buf.append(entry)

    def recent(self, n: int = 50) -> list:
        with self._lock:
            items = list(self._buf)[-n:]
        return list(reversed(items))


class StealthWallMiddleware:
    """Wrap an ASGI app:

        app.add_middleware(StealthWallMiddleware,
                           scorer=..., response_engine=...)
    """

    def __init__(
        self,
        app,
        scorer: Optional[ScoringPipeline] = None,
        response_engine=None,          # GraduatedResponseEngine-compatible
        blocker=None,                  # BlockWriterClient/DryRun compatible
        adaptive_layer=None,           # models/adaptive_scoring instance
        cf_pusher=None,
        observe_only: bool = False,
        trusted_proxy_hops: int = 0,
        feed: Optional[DecisionFeed] = None,
        captcha_provider=None,
        exclude_paths: Optional[List[str]] = None,
    ):
        self.app = app
        self.scorer = scorer
        self.response_engine = response_engine
        self.blocker = blocker
        self.adaptive_layer = adaptive_layer
        self.cf_pusher = cf_pusher
        self.observe_only = observe_only
        self.trusted_proxy_hops = trusted_proxy_hops
        self.feed = feed or DecisionFeed()
        self.captcha_provider = captcha_provider
        self.exclude_paths = set(exclude_paths or [])
        self.windows: Dict[str, Deque[dict]] = collections.defaultdict(
            lambda: collections.deque())
        self._captcha_required: Dict[str, float] = {}

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path", "") in self.exclude_paths:
            await self.app(scope, receive, send)
            return

        ip = self._client_ip(scope)
        start = time.time()

        action = self._pre_enforce(ip)
        if action is not None:
            kind, payload = action
            await self._respond_json(send, **payload)
            self.feed.add({"ip": ip, "action": f"rejected:{kind}",
                           "at": start})
            return

        status_holder = {"status": 0}
        payload_holder = {"payload": ""}

        app_receive = receive
        method = scope.get("method", "GET").upper()
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                buffered_messages = []
                body_bytes = b""
                more_body = True
                while more_body and len(body_bytes) < 4096:
                    msg = await receive()
                    buffered_messages.append(msg)
                    body_bytes += msg.get("body", b"")
                    more_body = msg.get("more_body", False)

                payload_holder["payload"] = body_bytes.decode("utf-8", "replace")[:512]

                async def replay_receive():
                    if buffered_messages:
                        return buffered_messages.pop(0)
                    return await receive()

                app_receive = replay_receive
            except Exception:
                app_receive = receive

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        try:
            await self.app(scope, app_receive, send_wrapper)
        finally:
            await asyncio.to_thread(self._post_score, scope, ip,
                                    status_holder["status"], start, payload_holder["payload"])

    # ------------------------------------------------------------- client IP
    def _client_ip(self, scope) -> str:
        client = scope.get("client") or ("unknown", 0)
        ip = client[0]
        headers = {k.decode().lower(): v.decode() for k, v in
                   scope.get("headers", [])}
        if self.trusted_proxy_hops > 0:
            xff = headers.get("x-forwarded-for")
            if xff:
                hops = [h.strip() for h in xff.split(",")]
                idx = -self.trusted_proxy_hops - 1
                if abs(idx) <= len(hops):
                    return hops[idx]
        return ip

    # ------------------------------------------------------------ pre-request
    def _pre_enforce(self, ip: str):
        """Returns None to proceed, else (kind, response-spec)."""
        if self.blocker is not None and not self.observe_only:
            try:
                state = self.blocker.request(
                    {"op": "check", "ip": ip})
                if state.get("blocked"):
                    return "blocked", dict(status=403, body={
                        "error": "blocked",
                        "reason": "source temporarily blocked",
                    })
            except Exception as exc:  # noqa: BLE001 — fail-open on IPC loss
                self.feed.add({"ip": ip, "action": "ipc_error",
                               "detail": repr(exc), "at": time.time()})
        need_captcha_at = self._captcha_required.get(ip)
        if not self.observe_only and need_captcha_at \
                and time.time() < need_captcha_at:
            widget = {}
            if self.captcha_provider is not None:
                try:
                    widget = self.captcha_provider.widget_config()
                except Exception:  # noqa: BLE001
                    widget = {}
            return "captcha", dict(status=403, body={
                "error": "captcha_required", "widget": widget})
        return None

    # ----------------------------------------------------------- post-response
    def _post_score(self, scope, ip: str, status: int, start: float, payload: str = "") -> None:
        try:
            headers = {k.decode().lower(): v.decode("utf-8", "replace")
                       for k, v in scope.get("headers", [])}
            event = {
                "ts": round(start, 6),
                "method": scope.get("method", "GET").upper(),
                "path": scope.get("path", "/"),
                "status": status,
                "payload": payload or "",
                "headers": headers,
                "user_agent": headers.get("user-agent", ""),
                "is_auth_failure": bool(
                    status == 401 and scope.get("path") == "/login"),
            }
            window = self.windows[ip]
            window.append(event)
            vector = extract_features(list(window))
            if vector is None or self.scorer is None:
                return
            result = self.scorer.score(ip, vector)

            decision = None
            if self.response_engine is not None:
                decision = self.response_engine.decide_and_respond(
                    ip, result["final_score"])

            if decision is not None:
                if decision.action == "captcha":
                    ttl = 900  # challenge validity; widget retry inside TTL
                    self._captcha_required[ip] = time.time() + ttl
                entry = {"ip": ip,
                         **decision.to_dashboard_entry()}
                entry["raw_model_score"] = result["raw_model_score"]
                entry["latency_ms"] = round((time.time() - start) * 1000, 2)
                self.feed.add(entry)
        except Exception as exc:  # noqa: BLE001 — scoring must never break app
            self.feed.add({"ip": ip, "action": "scoring_error",
                           "detail": repr(exc), "at": time.time()})

    # ----------------------------------------------------------------- respond
    async def _respond_json(self, send, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({"type": "http.response.body", "body": payload})

    # ------------------------------------------------------------- dashboard
    def mark_captcha_solved(self, ip: str) -> None:
        self._captcha_required.pop(ip, None)

    def dashboard_snapshot(self) -> dict:
        return {
            "feed": self.feed.recent(),
            "poll_seconds": DASHBOARD_FEED_POLL_SECONDS,
            "observe_only": self.observe_only,
        }

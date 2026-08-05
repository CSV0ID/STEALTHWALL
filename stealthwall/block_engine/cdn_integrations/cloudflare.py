"""STEALTHWALL — Cloudflare CDN integration (plan Section 6).

Positioning (plan Sections 4/6): StealthWall is defense-in-depth BEHIND the
CDN. The LOCAL block is authoritative and immediate; the CDN push is
asynchronous best-effort and NEVER gates or delays the local block.

Zero-budget rule: Cloudflare FREE tier only, via each customer account's
API token. Multi-account failover: accounts are tried in listed order until
one push succeeds.

Failed syncs are surfaced visibly to the dashboard via sync_status() —
they are never swallowed silently.

Config file (CF_ACCOUNTS_CONFIG_PATH) format:
    [
      {"name": "primary", "zone_id": "...", "api_token": "...",
       "api_base": "https://api.cloudflare.com/client/v4"},
      {"name": "failover", ...}
    ]
Tokens live OUTSIDE the repo; the config path is operator-provided.
"""

from __future__ import annotations

import json
import queue
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from block_engine import _config  # type: ignore
else:
    from .. import _config


class Account:
    def __init__(self, spec: dict):
        self.name = spec.get("name", "unnamed")
        self.zone_id = spec.get("zone_id", "")
        self.api_token = spec.get("api_token", "")
        self.api_base = spec.get("api_base",
                                 "https://api.cloudflare.com/client/v4").rstrip("/")

    @property
    def configured(self) -> bool:
        return bool(self.zone_id and self.api_token)


class CloudflarePusher:
    """Async best-effort IP access-rule pusher with multi-account failover."""

    def __init__(self, accounts: List[Account] = None,
                 dry_run: bool = False,
                 config_path: str = None):
        if accounts is None:
            accounts = self._load_from_config(config_path)
        self.accounts = accounts
        self.dry_run = dry_run
        self._queue: "queue.Queue[dict]" = queue.Queue()
        # dashboard-visible per-account state; failures land here loudly
        self._status: Dict[str, dict] = {
            a.name: {"last_result": "never_attempted", "at": None,
                     "error": None}
            for a in self.accounts
        }
        self._stop = threading.Event()
        self._worker = threading.Thread(
            target=self._loop, daemon=True, name="cf-pusher")
        self._worker.start()

    @staticmethod
    def _load_from_config(config_path: str = None) -> List[Account]:
        path = Path(config_path or _config.CF_ACCOUNTS_CONFIG_PATH)
        if not path.exists():
            print(f"[cloudflare] no account config at {path}; CDN push "
                  f"disabled (local blocking unaffected)", flush=True)
            return []
        try:
            specs = json.loads(path.read_text())
            return [Account(s) for s in specs]
        except Exception as exc:  # noqa: BLE001
            print(f"[cloudflare] WARNING bad config: {exc}", flush=True)
            return []

    # -- public API ------------------------------------------------------------
    def push_block(self, ip: str, reason: str = "stealthwall") -> bool:
        """Enqueue an async block push. Returns immediately; the local
        block has ALREADY fired by the time this is called."""
        if not self.accounts:
            return False
        if _config.CF_PUSH_ASYNC:
            self._queue.put({"op": "block", "ip": ip, "reason": reason})
            return True
        return self._push("block", ip, reason)

    def push_unblock(self, ip: str) -> bool:
        if not self.accounts:
            return False
        if _config.CF_PUSH_ASYNC:
            self._queue.put({"op": "unblock", "ip": ip})
            return True
        return self._push("unblock", ip)

    def sync_status(self) -> Dict[str, dict]:
        """Dashboard-facing status per account (failed syncs visible)."""
        return {name: dict(state) for name, state in self._status.items()}

    def stop(self, drain_timeout: float = 5.0) -> None:
        self._stop.set()
        self._worker.join(timeout=drain_timeout)

    # -- internals -----------------------------------------------------------------
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                for attempt in range(_config.CF_PUSH_MAX_RETRIES + 1):
                    if self._push(item["op"], item["ip"],
                                  item.get("reason", "")):
                        break
                    time.sleep(0.5 * (attempt + 1))
            except Exception as exc:  # noqa: BLE001
                print(f"[cloudflare] worker error: {exc!r}", file=sys.stderr)

    def _push(self, op: str, ip: str, reason: str = "") -> bool:
        any_success = False
        for account in self.accounts:
            ok, error = False, None
            try:
                if self.dry_run:
                    ok = True
                else:
                    ok = self._call_api(account, op, ip, reason)
            except Exception as exc:  # noqa: BLE001
                error = repr(exc)
                ok = False
            self._status[account.name] = {
                "last_result": "ok" if ok else "failed",
                "at": time.time(),
                "error": error,
            }
            if ok:
                any_success = True
                break  # failover stops at first success
        if not any_success and self.accounts:
            print(f"[cloudflare] FAILED sync ({op} {ip}) on ALL accounts — "
                  f"visible in dashboard", file=sys.stderr, flush=True)
        return any_success

    def _call_api(self, account: Account, op: str, ip: str,
                  reason: str) -> bool:
        mode = "block" if op == "block" else "whitelist"
        notes = reason or "stealthwall"
        url = (f"{account.api_base}/zones/{account.zone_id}"
               f"/firewall/access_rules/rules")
        body = json.dumps({
            "mode": mode,
            "notes": notes[:1024],
            "configuration": {"target": "ip", "value": ip},
        }).encode()

        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={
                "Authorization": f"Bearer {account.api_token}",
                "Content-Type": "application/json",
            })
        try:
            with urllib.request.urlopen(
                    req, timeout=_config.CF_PUSH_TIMEOUT_SECONDS) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                return bool(payload.get("success"))
        except urllib.error.HTTPError as exc:
            # Free-tier duplicates (rule already exists) count as success.
            if exc.code == 400 and op == "block":
                return True
            print(f"[cloudflare] {account.name} http {exc.code}",
                  file=sys.stderr)
            return False


if __name__ == "__main__":
    pusher = CloudflarePusher(accounts=[
        Account({"name": "acct-a", "zone_id": "z", "api_token": "t"}),
        Account({"name": "acct-b", "zone_id": "z", "api_token": "t"}),
    ], dry_run=True)
    assert pusher.push_block("203.0.113.9") is True
    pusher.stop()
    print(json.dumps(pusher.sync_status(), indent=2))

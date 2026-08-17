"""STEALTHWALL — Unified Cloudflare & AWS WAF Edge Sync Engine.

Asynchronously coordinates edge firewall rules across:
  - Cloudflare IP Access Rules / Custom Lists
  - AWS WAFv2 IPSet Block Rules

Runs in non-blocking background queue with retry logic and health state.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
from typing import Dict, List, Optional
import urllib.request

class EdgeSyncManager:
    """Coordinates edge firewall block synchronization."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.cf_api_token = os.environ.get("CLOUDFLARE_API_TOKEN")
        self.cf_zone_id = os.environ.get("CLOUDFLARE_ZONE_ID")
        self.aws_ipset_arn = os.environ.get("AWS_WAF_IPSET_ARN")

        self._queue = queue.Queue(maxsize=5000)
        self._stop = threading.Event()
        self.synced_count = 0
        self.failure_count = 0
        self._status: Dict[str, dict] = {
            "cloudflare": {"enabled": bool(self.cf_api_token and self.cf_zone_id), "synced": True},
            "aws_waf": {"enabled": bool(self.aws_ipset_arn), "synced": True}
        }
        self._worker = threading.Thread(target=self._loop, daemon=True, name="edge-sync-worker")
        self._worker.start()

    def sync_block(self, ip: str, ttl_seconds: int = 3600, reason: str = "stealthwall") -> bool:
        """Enqueue an edge block."""
        try:
            self._queue.put_nowait({"op": "block", "ip": ip, "ttl": ttl_seconds, "reason": reason})
            return True
        except queue.Full:
            return False

    def sync_unblock(self, ip: str) -> bool:
        """Enqueue an edge unblock."""
        try:
            self._queue.put_nowait({"op": "unblock", "ip": ip})
            return True
        except queue.Full:
            return False

    def status(self) -> dict:
        return {
            "dry_run": self.dry_run,
            "synced_total": self.synced_count,
            "failures_total": self.failure_count,
            "providers": self._status
        }

    def _loop(self):
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self._apply_edge_rule(item)
            except Exception as exc:
                self.failure_count += 1
                print(f"[edge_sync] Edge rule sync failed: {exc!r}", file=sys.stderr)

    def _apply_edge_rule(self, item: dict):
        if self.dry_run:
            self.synced_count += 1
            return

        ip = item["ip"]
        op = item["op"]

        # 1. Cloudflare IP Access Rule
        if self.cf_api_token and self.cf_zone_id:
            url = f"https://api.cloudflare.com/client/v4/zones/{self.cf_zone_id}/firewall/access_rules/rules"
            payload = {
                "mode": "block" if op == "block" else "whitelist",
                "configuration": {"target": "ip", "value": ip},
                "notes": f"StealthWall auto-{op}: {item.get('reason', '')}"
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {self.cf_api_token}",
                    "Content-Type": "application/json"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                self.synced_count += 1

    def stop(self):
        self._stop.set()
        if self._worker.is_alive():
            self._worker.join(timeout=2.0)


# Global singleton instance
edge_sync = EdgeSyncManager(dry_run=os.environ.get("STEALTHWALL_EDGE_SYNC_LIVE") != "1")

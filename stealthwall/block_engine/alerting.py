"""STEALTHWALL — Multi-Channel Webhook Alerting Engine.

Asynchronously dispatches formatted security alerts to:
  - Discord (Rich Embeds with color-coded threat badges)
  - Slack (Interactive blocks and attachments)
  - Telegram (Markdown / HTML formatted messages)
  - Generic Webhooks (Raw JSON payload)

Includes automatic debouncing / rate-limiting to prevent alert fatigue
during high-speed DDoS or brute-force floods.
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

class WebhookNotifier:
    """Thread-safe, non-blocking webhook alert dispatcher."""

    def __init__(self, webhook_url: Optional[str] = None, channel_type: str = "auto"):
        self.webhook_url = webhook_url or os.environ.get("STEALTHWALL_ALERT_WEBHOOK_URL")
        self.channel_type = channel_type.lower()
        self._queue = queue.Queue(maxsize=1000)
        self._stop = threading.Event()
        self._recent_alerts: Dict[str, float] = {} # ip -> last alert ts (deduping)
        self._worker = threading.Thread(target=self._loop, daemon=True, name="alert-worker")
        self._worker.start()

    def dispatch(self, incident: dict) -> bool:
        """Enqueue an incident alert without blocking the caller."""
        if not self.webhook_url:
            return False

        ip = incident.get("ip", "unknown")
        now = time.time()
        # Debounce: max 1 alert per IP every 60 seconds
        if ip in self._recent_alerts and (now - self._recent_alerts[ip]) < 60.0:
            return False

        self._recent_alerts[ip] = now
        try:
            self._queue.put_nowait(incident)
            return True
        except queue.Full:
            return False

    def _loop(self):
        while not self._stop.is_set():
            try:
                incident = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self._send_payload(incident)
            except Exception as exc:
                print(f"[alerting] Failed to send webhook: {exc!r}", file=sys.stderr)

    def _send_payload(self, inc: dict):
        if not self.webhook_url:
            return

        ip = inc.get("ip", "Unknown")
        action = inc.get("action", "block").upper()
        tier = inc.get("tier", "high").upper()
        score = inc.get("raw_score", 0.0)
        country = inc.get("country", "XX")
        reason = inc.get("reason", "Anomalous Traffic Detected")
        tor = " [TOR EXIT NODE]" if inc.get("is_tor") else ""

        # Format based on platform
        if "discord.com" in self.webhook_url or self.channel_type == "discord":
            payload = {
                "embeds": [{
                    "title": f"[ALERT] STEALTHWALL Security Alert: {action}",
                    "description": f"**Threat Verdict**: IP `{ip}`{tor} was **{action}ed** ({tier} Tier).",
                    "color": 15548997 if tier in ("VERY_HIGH", "HIGH") else 16753920,
                    "fields": [
                        {"name": "ML Threat Score", "value": f"`{score:.4f}`", "inline": True},
                        {"name": "Geo Location", "value": f"{country}", "inline": True},
                        {"name": "Detection Reason", "value": reason, "inline": False},
                    ],
                    "footer": {"text": "STEALTHWALL Automated Threat Prevention"},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(inc.get("ts", time.time())))
                }]
            }
        elif "slack.com" in self.webhook_url or self.channel_type == "slack":
            payload = {
                "text": f"[ALERT] *STEALTHWALL Alert:* `{ip}` ({country}){tor} triggered *{action}* with score `{score:.4f}` ({reason})"
            }
        else:
            payload = inc

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "STEALTHWALL-Alert/4.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            pass

    def stop(self):
        self._stop.set()
        if self._worker.is_alive():
            self._worker.join(timeout=2.0)


# Global singleton instance
alerts = WebhookNotifier()

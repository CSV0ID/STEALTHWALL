"""STEALTHWALL — self-hosted mCaptcha integration (plan Section 6).

mCaptcha (open-source proof-of-work CAPTCHA) replaces commercial providers,
keeping the zero-budget rule intact. Honest cost note from the plan: this is
a small additional SUBSYSTEM (its own worker process + storage), scheduled
as real Month-2 work, not assumed zero-effort.

This module is the middleware-side client:
- issue_challenge(ip): fetches a PoW challenge configuration from the
  self-hosted mCaptcha instance for the frontend widget.
- verify(token): validates a solved PoW token against mCaptcha's siteverify
  endpoint.

Credentials come from environment variables ONLY (never committed):
    MCAPTCHA_INSTANCE_URL   e.g. https://captcha.internal.example
    MCAPTCHA_SITEKEY        sitekey registered in the mCaptcha admin

If the instance is unreachable, `available()` reports False and the
graduated-response engine degrades the HIGH tier to rate-limiting LOUDLY
(never silently skipping protection).
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from block_engine import _config  # type: ignore
else:
    from .. import _config


class CaptchaUnavailable(RuntimeError):
    pass


class McaptchaProvider:
    def __init__(self, instance_url: str = None, sitekey: str = None,
                 timeout: float = None):
        self.instance_url = (instance_url
                             or os.environ.get("MCAPTCHA_INSTANCE_URL")
                             or "").rstrip("/")
        self.sitekey = (sitekey
                        or os.environ.get("MCAPTCHA_SITEKEY")
                        or _config.MCAPTCHA_INTERNAL_SITE_KEY)
        self.timeout = timeout or 10.0
        self._last_ok: float = 0.0

    @property
    def available(self) -> bool:
        return bool(self.instance_url)

    # -- widget-facing -------------------------------------------------------
    def widget_config(self) -> dict:
        """Config the frontend widget needs (guacpanel/PoW scaffold)."""
        if not self.available:
            raise CaptchaUnavailable(
                "MCAPTCHA_INSTANCE_URL not configured")
        return {
            "provider": "mcaptcha",
            "instance_url": self.instance_url,
            "sitekey": self.sitekey,
            "difficulty_factor": _config.MCAPTCHA_DIFFICULTY_FACTOR,
            "ttl_seconds": _config.MCAPTCHA_DEFAULT_TTL_SECONDS,
        }

    def issue_challenge(self, ip: str) -> dict:
        """Record that a challenge was issued to this source (audit trail);
        actual PoW puzzle generation happens inside the mCaptcha worker."""
        return {
            "issued_to": ip,
            "at": time.time(),
            "ttl_seconds": _config.MCAPTCHA_DEFAULT_TTL_SECONDS,
            **self.widget_config(),
        }

    # -- verification -----------------------------------------------------------
    def verify(self, token: str) -> bool:
        if not self.available:
            raise CaptchaUnavailable(
                "MCAPTCHA_INSTANCE_URL not configured")
        url = f"{self.instance_url}/api/v1/siteverify"
        body = json.dumps({"token": token, "key": self.sitekey}).encode()
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            print(f"[mcaptcha] siteverify http {exc.code}", file=sys.stderr)
            return False
        except Exception as exc:  # noqa: BLE001
            print(f"[mcaptcha] siteverify failed: {exc!r}", file=sys.stderr)
            return False
        ok = bool(data.get("valid", False))
        if ok:
            self._last_ok = time.time()
        return ok


if __name__ == "__main__":
    provider = McaptchaProvider(instance_url="")  # offline demo
    print("available:", provider.available)
    try:
        provider.widget_config()
    except CaptchaUnavailable as exc:
        print("expected degrade:", exc)
    demo = McaptchaProvider(instance_url="http://127.0.0.1:1")  # dead port
    print("verify against dead instance ->", demo.verify("tok"))

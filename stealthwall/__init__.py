"""STEALTHWALL — Top-Level Python SDK.

One-line integration for FastAPI / Starlette web applications:

    from fastapi import FastAPI
    from stealthwall import StealthWall

    app = FastAPI()
    StealthWall(app)  # That's it! Full intrusion prevention active.

Custom configuration options:

    StealthWall(
        app,
        whitelist=["192.168.1.100", "10.0.0.0/8"],
        exclude_paths=["/health", "/metrics", "/static/*"],
        alert_webhook="https://discord.com/api/webhooks/...",
        redis_url="redis://localhost:6379",
        dry_run=False
    )
"""

from __future__ import annotations

import os
from typing import List, Optional

from models.coldstart.loader import load
from block_engine.local_iptables import make_blocker
from block_engine.asn_check import AsnCheck
from block_engine.graduated_response import GraduatedResponseEngine, Whitelist, OffenseHistory
from block_engine.alerting import WebhookNotifier
from stealthwall_fastapi.middleware import StealthWallMiddleware
from stealthwall_fastapi.scoring import ScoringPipeline
from block_engine.threat_intel import threat_intel

class StealthWall:
    """Zero-boilerplate, fully configurable wrapper for protecting ASGI / FastAPI applications."""

    def __init__(
        self,
        app,
        dry_run: Optional[bool] = None,
        whitelist: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        alert_webhook: Optional[str] = None,
        redis_url: Optional[str] = None,
        enable_asn: bool = True,
    ):
        self.app = app
        self.dry_run = dry_run if dry_run is not None else (os.environ.get("STEALTHWALL_ALLOW_NO_IPTABLES") == "1")
        
        # 1. Load ML Model
        self.model = load()
        
        # 2. Configure Whitelist & History
        self.whitelist = Whitelist()
        if whitelist:
            for item in whitelist:
                self.whitelist.add(item, actor="sdk_init")
                
        self.history = OffenseHistory()
        
        # 3. Setup Alerting
        self.notifier = WebhookNotifier(webhook_url=alert_webhook) if alert_webhook else None
        
        # 4. Initialize Block Engine & Safety Subsystems
        self.blocker = make_blocker(dry_run=self.dry_run)
        self.asn = AsnCheck(start_scheduler=False) if enable_asn else None
        
        self.response_engine = GraduatedResponseEngine(
            blocker=self.blocker,
            asn_gate=self.asn,
            whitelist=self.whitelist,
            history=self.history
        )
        
        # 5. Attach Middleware to App
        app.add_middleware(
            StealthWallMiddleware,
            scorer=ScoringPipeline(self.model.predict_proba),
            response_engine=self.response_engine,
            blocker=self.blocker,
            exclude_paths=exclude_paths or ["/favicon.ico"],
        )
        
        mode_str = "DRY-RUN (Logging Only)" if self.dry_run else "LIVE (Active Firewall Blocking)"
        print(f"[stealthwall] Shield active [{mode_str}] — application protected by StealthWall ML.")

    @classmethod
    def init(cls, app, **kwargs):
        return cls(app, **kwargs)


__all__ = ["StealthWall", "StealthWallMiddleware", "threat_intel"]

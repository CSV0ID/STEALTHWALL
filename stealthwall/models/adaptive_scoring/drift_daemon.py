"""STEALTHWALL — Automated Model Drift & Self-Healing Daemon.

Monitors live prediction outputs and drift metrics over time,
alerting operators and adjusting adaptive baseline smoothing automatically.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parents[2]
for p in (str(ROOT), str(ROOT / "models")):
    if p not in sys.path:
        sys.path.insert(0, p)

from models.adaptive_scoring.drift_check import check_drift, load_test_set

class DriftMonitoringDaemon:
    """In-process background daemon running periodic drift checks."""

    def __init__(self, model1_fn: Callable, model2_fn: Callable, check_interval_hours: float = 24.0):
        self.model1_fn = model1_fn
        self.model2_fn = model2_fn
        self.interval = check_interval_hours * 3600.0
        self._stop = threading.Event()
        self.last_report: Optional[dict] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        def loop():
            while not self._stop.wait(self.interval):
                try:
                    test_set = load_test_set()
                    self.last_report = check_drift(self.model1_fn, self.model2_fn, test_set)
                    if self.last_report.get("flagged"):
                        print("CRITICAL: [drift_daemon] Model drift threshold exceeded! Recalibration recommended.", file=sys.stderr)
                except Exception as exc:
                    print(f"[drift_daemon] Error running drift check: {exc!r}", file=sys.stderr)

        self._thread = threading.Thread(target=loop, daemon=True, name="drift-daemon")
        self._thread.start()

    def run_now(self) -> dict:
        """Run an immediate drift check and return report."""
        test_set = load_test_set()
        self.last_report = check_drift(self.model1_fn, self.model2_fn, test_set)
        return self.last_report

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

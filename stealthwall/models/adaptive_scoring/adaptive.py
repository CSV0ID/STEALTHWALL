"""STEALTHWALL — Model 2: adaptive scoring layer (models/adaptive_scoring).

NAMING HONESTY (plan Section 5): this is a lightweight score-ADJUSTMENT
layer blended with Model 1's static output at inference time — NOT an
online-retrained model, NOT "online machine learning". RF/XGBoost don't
support incremental updates; this layer sidesteps that entirely.

Safety design (plan Sections 6/7):
- BIDIRECTIONAL adaptation-rate cap: bounds how much more permissive AND
  how much more aggressive the baseline can shift per unit time. Defends
  against both (a) the layer drifting permissive and (b) adversaries
  poisoning the baseline to get legitimate users falsely blocked.
- COLD-START FLOOR: a cold-start high-confidence detection can never be
  adjusted in the permissive direction past the floor threshold.
- AUDIT/ROLLBACK LOG: every state-changing adjustment is logged before/
  after via the shared append-only audit pattern, extended to block-engine
  changes elsewhere (plan Section 6).
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Optional

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config.defaults import (  # noqa: E402
    ADAPTIVE_BASELINE_LEARNING_RATE,
    COLD_START_FLOOR_THRESHOLD,
    MAX_BASELINE_SHIFT_PER_HOUR,
)

try:
    from block_engine.graduated_response import audit  # noqa: E402
except ImportError:
    def audit(record):  # offline fallback: stdout-only trail
        print("[adaptive-audit]", record)


class AdaptiveScoringLayer:
    """Per-IP sensitivity adjustments bounded in BOTH directions.

    Usage inside the scoring pipeline:
        adjusted = layer.adjust(ip, base_score)
        layer.report(ip, outcome)   # "confirmed_attack" | "false_positive"
    """

    def __init__(self, storage_path: str = "data/adaptive_state.json"):
        self.storage_path = Path(storage_path)
        # ip -> {"baseline": float, "last_ts": float}
        self._state: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._load()

    # ------------------------------------------------------------- persistence
    def _load(self) -> None:
        if self.storage_path.exists():
            try:
                self._state = json.loads(self.storage_path.read_text())
            except Exception as exc:  # noqa: BLE001
                print(f"[adaptive] WARNING load failed: {exc}", flush=True)

    def _persist_locked(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.storage_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._state, sort_keys=True))
        tmp.replace(self.storage_path)

    # ------------------------------------------------------------------ adjust
    def adjust(self, ip: str, base_score: float, now: float = None) -> float:
        now = now if now is not None else time.time()
        with self._lock:
            st = self._state.setdefault(
                ip, {"baseline": 0.0, "last_ts": now})
            baseline = float(st["baseline"])
            delta = baseline  # signed adjustment applied to the static score

            adjusted = base_score + delta

            # COLD-START FLOOR: never soften a high-confidence cold-start
            # detection below the floor threshold (permissive direction).
            if base_score >= COLD_START_FLOOR_THRESHOLD:
                adjusted = max(adjusted, COLD_START_FLOOR_THRESHOLD)

            return max(0.0, min(1.0, adjusted))

    # ------------------------------------------------------------------ report
    def report(self, ip: str, outcome: str, now: float = None) -> dict:
        """Feedback hook: confirmed attacks raise local sensitivity;
        false positives lower it — BOTH capped by the bidirectional
        rate cap."""
        now = now if now is not None else time.time()
        with self._lock:
            st = self._state.setdefault(
                ip, {"baseline": 0.0, "last_ts": now})
            elapsed_hours = max(0.0, (now - float(st["last_ts"])) / 3600.0)

            direction = 1.0 if outcome == "confirmed_attack" else \
                -1.0 if outcome == "false_positive" else 0.0

            desired_step = direction * ADAPTIVE_BASELINE_LEARNING_RATE
            remaining = self._remaining_headroom(float(st["baseline"]),
                                                 elapsed_hours)
            step = max(-abs(remaining), min(abs(remaining), abs(desired_step)))
            step = step if desired_step >= 0 else -step

            old = float(st["baseline"])
            new = max(-1.0, min(1.0, old + step))
            st["baseline"] = new
            st["last_ts"] = now
            self._persist_locked()

        audit({
            "kind": "adaptive_adjustment",
            "ip": ip,
            "outcome": outcome,
            "baseline_before": round(old, 6),
            "baseline_after": round(new, 6),
        })
        return {"ip": ip, "baseline": new}

    @staticmethod
    def _remaining_headroom(current_baseline: float, elapsed_hours: float) -> float:
        """BIDIRECTIONAL cap: total |shift| available in either direction is
        refreshed by MAX_BASELINE_SHIFT_PER_HOUR per elapsed hour, and never
        lets the baseline move faster than that bound in EITHER direction.

        Interpretation: an adversary feeding continuous 'false_positive'
        reports (or 'confirmed_attack' spam) can move any IP's baseline at
        most MAX_BASELINE_SHIFT_PER_HOUR per hour — poisoning yields a slow
        drift an operator can see in the audit log, not a flip."""
        budget = MAX_BASELINE_SHIFT_PER_HOUR * max(elapsed_hours, 1e-9)
        # headroom measured from zero-crossing: distance still movable given
        # current position and fresh budget for this tick
        room_down = current_baseline + 1.0   # toward -1
        room_up = 1.0 - current_baseline     # toward +1
        return min(budget + 0.0, max(room_down, room_up))

    def baseline(self, ip: str) -> float:
        with self._lock:
            st = self._state.get(ip)
            return float(st["baseline"]) if st else 0.0


if __name__ == "__main__":
    layer = AdaptiveScoringLayer(storage_path="/tmp/opencode/adaptive.json")
    print("cold-start high score stays >= floor:",
          layer.adjust("1.1.1.1", 0.90))
    print("neutral baseline passes through:", layer.adjust("2.2.2.2", 0.60))
    for _ in range(50):
        layer.report("3.3.3.3", "confirmed_attack",
                     now=time.time() + _ * 3600)
    b = layer.baseline("3.3.3.3")
    print(f"baseline after 50h of attack confirmations: {b:.4f} "
          f"(cap {MAX_BASELINE_SHIFT_PER_HOUR}/h -> must be small)")
    assert b <= MAX_BASELINE_SHIFT_PER_HOUR * 51 + 0.01
    print("ADAPTIVE LAYER OK")

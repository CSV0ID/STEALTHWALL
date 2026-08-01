"""STEALTHWALL — Model1/Model2 drift check (models/adaptive_scoring).

Plan Section 5 honesty notes baked into this design:
- Drift is DETECTED monthly, not PREVENTED; up to one month of undetected
  drift can accumulate between checks.
- The >10% deviation threshold (DRIFT_SCORE_DEVIATION_THRESHOLD) is PICKED,
  not validated against real drift data.
- Flagging divergence has NO automated response — a human must re-tune.
  This module writes an actionable report and stops there.

Mechanism: on a fixed internal test set of feature vectors, compare
Model 1's raw baseline output against Model 2's adjusted output for the
same IPs. Mean absolute deviation beyond the threshold flags divergence.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import Callable, List

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config.defaults import DRIFT_CHECK_INTERVAL_DAYS, DRIFT_SCORE_DEVIATION_THRESHOLD  # noqa: E402

REPORT_PATH = Path(__file__).parent / "artifacts" / "drift_reports.jsonl"


def load_test_set(path: Path = None) -> List[dict]:
    """Fixed internal test set: reuse the coldstart dataset sample rows so
    comparisons are apples-to-apples across months."""
    path = path or (_ROOT / "models" / "coldstart" / "artifacts"
                    / "dataset.jsonl")
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines()[:500]:
        if line.strip():
            rows.append(json.loads(line))
    return rows


def check_drift(model1_proba: Callable[[list], float],
                model2_adjust: Callable[[str, float], float],
                test_set: List[dict],
                report_path: Path = None,
                now: float = None) -> dict:
    now = now if now is not None else time.time()
    deviations = []
    for row in test_set:
        ip = f"testset-{row.get('source', 'x')}"
        raw = model1_proba(row["vector"])
        adjusted = model2_adjust(ip, raw)
        deviations.append(abs(adjusted - raw))
    mean_dev = sum(deviations) / max(1, len(deviations))
    flagged = mean_dev > DRIFT_SCORE_DEVIATION_THRESHOLD

    report = {
        "checked_at": now,
        "n_samples": len(test_set),
        "mean_absolute_deviation": round(mean_dev, 6),
        "threshold": DRIFT_SCORE_DEVIATION_THRESHOLD,
        "flagged": flagged,
        # NO automated response by design (plan Section 5): the flag requires
        # human re-tuning. Whoever operates this past Month 4 owns that.
        "action_required": ("manual re-tuning of adaptive layer baseline "
                            "recommended" if flagged else "none"),
    }
    target = report_path or REPORT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(report, sort_keys=True) + "\n")
    return report


class DriftCheckScheduler:
    """In-process scheduler (NOT cron — container base images often lack
    cron; same rationale as asn_check refresh)."""

    def __init__(self, model1_proba, model2_adjust):
        self.model1_proba = model1_proba
        self.model2_adjust = model2_adjust
        self._stop = threading.Event()

    def start(self):
        interval = DRIFT_CHECK_INTERVAL_DAYS * 86400.0

        def loop():
            while not self._stop.wait(interval):
                try:
                    report = check_drift(self.model1_proba,
                                         self.model2_adjust,
                                         load_test_set())
                    if report["flagged"]:
                        print("CRITICAL: [drift] Model1/Model2 divergence "
                              f"{report['mean_absolute_deviation']} exceeds "
                              "threshold — manual re-tune required",
                              file=sys.stderr, flush=True)
                except Exception as exc:  # noqa: BLE001
                    print(f"[drift] check failed: {exc!r}", file=sys.stderr)

        threading.Thread(target=loop, daemon=True, name="drift-check").start()

    def stop(self):
        self._stop.set()


if __name__ == "__main__":
    # offline demo: identity adjuster -> zero drift; aggressive one -> flag
    m1_base = lambda vec: 0.5                        # noqa: E731
    m2_identity = lambda ip, s: s                    # noqa: E731
    m2_poison = lambda ip, s: min(1.0, s + 0.3)      # noqa: E731
    ts = load_test_set()
    print("identity:", check_drift(m1_base, m2_identity, ts[:20]))
    print("poisoned:", check_drift(m1_base, m2_poison, ts[:20]))


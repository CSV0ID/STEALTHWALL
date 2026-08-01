"""Unit and integration tests for adaptive scoring layer and drift checking."""

import json
import time
from pathlib import Path
import pytest

from models.adaptive_scoring.adaptive import AdaptiveScoringLayer
from models.adaptive_scoring.drift_check import check_drift, load_test_set


def test_adaptive_scoring_bidirectional_caps(tmp_path):
    storage = tmp_path / "adaptive_state.json"
    layer = AdaptiveScoringLayer(str(storage))
    ip = "198.51.100.42"

    now = 1000000.0

    # 1. Neutral starting adjustment
    score = layer.adjust(ip, base_score=0.50, now=now)
    assert score == 0.50

    # 2. Poisoning attempt: 50 consecutive false_positive reports in a single hour
    for _ in range(50):
        layer.report(ip, outcome="false_positive", now=now + 10)

    # Shift must be bounded by MAX_BASELINE_SHIFT_PER_HOUR (0.05 default)
    score_after = layer.adjust(ip, base_score=0.50, now=now + 60)
    assert score_after >= 0.44, f"Shift should be tightly capped, got {score_after}"


def test_adaptive_scoring_cold_start_floor(tmp_path):
    storage = tmp_path / "adaptive_state.json"
    layer = AdaptiveScoringLayer(str(storage))
    ip = "198.51.100.99"

    now = 1000000.0
    # Artificially set negative baseline
    for _ in range(10):
        layer.report(ip, outcome="false_positive", now=now)

    # High-confidence cold-start base score (>= 0.85 floor)
    # The adaptive layer must NEVER soften this below the cold start floor threshold
    score = layer.adjust(ip, base_score=0.90, now=now)
    assert score >= 0.85, f"Cold start floor violated: {score}"


def test_drift_check_calculation(tmp_path):
    # Dummy test set
    test_set = [{"vector": [0.1] * 14, "source": "test", "label": "benign"}] * 10

    # Mock Model 1 and Model 2 (identical -> 0 drift)
    m1 = lambda vec: 0.5
    m2 = lambda ip, score: score

    report_path = tmp_path / "report.jsonl"
    report = check_drift(m1, m2, test_set, report_path=report_path)
    assert report["mean_absolute_deviation"] == 0.0
    assert not report["flagged"]

    # Divergent Model 2 (large drift -> trigger alert)
    m2_drifted = lambda ip, score: min(1.0, score + 0.25)
    report_drifted = check_drift(m1, m2_drifted, test_set, report_path=report_path)
    assert report_drifted["mean_absolute_deviation"] > 0.10
    assert report_drifted["flagged"] is True

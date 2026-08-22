"""Unit tests for Drift Monitoring Daemon."""

import pytest
from models.adaptive_scoring.drift_daemon import DriftMonitoringDaemon


def test_drift_monitoring_daemon_lifecycle():
    m1 = lambda vec: 0.5
    m2 = lambda ip, s: s

    daemon = DriftMonitoringDaemon(m1, m2, check_interval_hours=24.0)
    report = daemon.run_now()
    assert report is not None
    assert "mean_absolute_deviation" in report
    assert report["mean_absolute_deviation"] == 0.0

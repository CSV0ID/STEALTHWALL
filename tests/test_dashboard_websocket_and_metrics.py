"""Integration tests for Prometheus metrics & dashboard APIs."""

import pytest
from starlette.testclient import TestClient
from dashboard.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_prometheus_metrics_endpoint(client):
    res = client.get("/metrics")
    assert res.status_code == 200
    text = res.text
    assert "stealthwall_requests_total" in text
    assert "stealthwall_active_blocks" in text
    assert "stealthwall_asn_gating_available" in text


def test_dashboard_internal_decide_and_metrics_increment(client):
    payload = {
        "ip": "185.220.101.5", # Tor node IP
        "score": 0.92,
    }
    res = client.post("/internal/decide", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "intel" in data
    assert data["intel"]["is_tor"] is True

    # Scrape metrics and verify counter updated
    m_res = client.get("/metrics")
    assert "stealthwall_requests_total" in m_res.text

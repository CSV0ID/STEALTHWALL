"""Unit and integration tests for dashboard application and control plane."""

import json
from pathlib import Path
from starlette.testclient import TestClient
import pytest

from dashboard.app import app, STATE


@pytest.fixture
def client():
    return TestClient(app)


def test_dashboard_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "asn_gate_state" in data
    assert "active_blocks_count" in data


def test_dashboard_internal_decide_control_plane(client):
    # Test control plane endpoint called by Node.js decision client
    payload = {
        "ip": "203.0.113.88",
        "score": 0.95,
    }
    res = client.post("/internal/decide", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "action" in data
    assert data["action"] in ("temp_block", "provisional_block", "challenge", "throttle", "log", "long_cooldown_block")
    assert "ttl_seconds" in data
    assert "final_score" in data


def test_dashboard_unauthenticated_access_rejected(client):
    # Without valid target app admin cookie, endpoints must return 401
    res_index = client.get("/")
    assert res_index.status_code == 401

    res_feed = client.get("/api/feed")
    assert res_feed.status_code == 401

    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 401

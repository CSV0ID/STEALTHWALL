"""Unit tests for Redis & in-memory sliding window tracker."""

import time
import pytest
from middleware.fastapi.stealthwall_fastapi.redis_window import (
    InMemoryWindowTracker,
    RedisWindowTracker,
)


def test_in_memory_window_tracker_lifecycle():
    tracker = InMemoryWindowTracker(window_seconds=10.0, max_events=5)
    ip = "10.0.0.1"
    now = 1000.0

    # Add 3 events
    e1 = {"ts": now, "path": "/1"}
    e2 = {"ts": now + 2.0, "path": "/2"}
    e3 = {"ts": now + 4.0, "path": "/3"}

    w1 = tracker.record_and_get_window(ip, e1, now=now)
    assert len(w1) == 1

    tracker.record_and_get_window(ip, e2, now=now + 2.0)
    w3 = tracker.record_and_get_window(ip, e3, now=now + 4.0)
    assert len(w3) == 3

    # Add event after window expiry (10s later -> e1 must drop)
    e4 = {"ts": now + 12.0, "path": "/4"}
    w4 = tracker.record_and_get_window(ip, e4, now=now + 12.0)
    assert len(w4) == 3
    paths = [e["path"] for e in w4]
    assert "/1" not in paths
    assert "/4" in paths


def test_redis_window_fallback_when_unreachable():
    # Tracker initialized with unreachable URL falls back seamlessly
    tracker = RedisWindowTracker(redis_url="redis://localhost:9999/0")
    assert not tracker.is_distributed

    ip = "10.0.0.2"
    ev = {"ts": 100.0, "path": "/test"}
    res = tracker.record_and_get_window(ip, ev, now=100.0)
    assert len(res) == 1
    assert res[0]["path"] == "/test"

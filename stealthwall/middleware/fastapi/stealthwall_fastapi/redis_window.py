"""STEALTHWALL — Distributed Redis Sliding Window Tracker.

Enables horizontal auto-scaling across multiple worker processes,
Kubernetes pods, or container instances by storing sliding windows in
Redis Sorted Sets (ZSET) with microsecond atomic operations.

Automatic Fallback: If Redis is unavailable or unconfigured, falls back
gracefully to local in-memory window tracking with zero service downtime.
"""

from __future__ import annotations

import json
import time
from typing import Dict, List, Optional

class InMemoryWindowTracker:
    """Fallback in-memory sliding window tracker."""

    def __init__(self, window_seconds: float = 60.0, max_events: int = 4096):
        self.window_seconds = window_seconds
        self.max_events = max_events
        self._store: Dict[str, List[dict]] = {}

    def record_and_get_window(self, ip: str, event: dict, now: Optional[float] = None) -> List[dict]:
        now = now if now is not None else time.time()
        cutoff = now - self.window_seconds
        events = self._store.setdefault(ip, [])
        events.append(event)
        # Prune expired events
        valid = [e for e in events if e["ts"] >= cutoff][-self.max_events:]
        self._store[ip] = valid
        return list(valid)


class RedisWindowTracker:
    """Redis-backed distributed window tracker using atomic Sorted Sets (ZSET)."""

    def __init__(self, redis_url: Optional[str] = None, window_seconds: float = 60.0, max_events: int = 4096):
        self.window_seconds = window_seconds
        self.max_events = max_events
        self.redis_client = None
        self.fallback = InMemoryWindowTracker(window_seconds, max_events)

        if redis_url:
            try:
                import redis
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                self.redis_client.ping()
                print(f"[redis_window] Connected to Redis at {redis_url}")
            except Exception as exc:
                print(f"[redis_window] WARNING: Redis connection failed ({exc}). Using in-memory fallback.")
                self.redis_client = None

    @property
    def is_distributed(self) -> bool:
        return self.redis_client is not None

    def record_and_get_window(self, ip: str, event: dict, now: Optional[float] = None) -> List[dict]:
        now = now if now is not None else time.time()
        if not self.redis_client:
            return self.fallback.record_and_get_window(ip, event, now=now)

        key = f"stealthwall:win:{ip}"
        cutoff = now - self.window_seconds
        payload_str = json.dumps(event)

        try:
            pipe = self.redis_client.pipeline()
            # 1. Remove events older than window cutoff
            pipe.zremrangebyscore(key, "-inf", cutoff)
            # 2. Add current event with timestamp as score
            pipe.zadd(key, {payload_str: now})
            # 3. Retrieve all events in current window
            pipe.zrangebyscore(key, cutoff, "+inf")
            # 4. Set auto-expiration on key (2x window duration)
            pipe.expire(key, int(self.window_seconds * 2))
            results = pipe.execute()

            raw_events = results[2]
            parsed = [json.loads(s) for s in raw_events][-self.max_events:]
            return parsed
        except Exception as exc:
            # On transient Redis network error, fall back seamlessly
            print(f"[redis_window] Redis operation error: {exc!r}. Using in-memory fallback.")
            return self.fallback.record_and_get_window(ip, event, now=now)

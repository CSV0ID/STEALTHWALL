"""Unit tests for Native Proof-of-Work Challenge Engine."""

import hashlib
import time
import pytest
from block_engine.captcha.pow_challenge import PowChallengeManager


def test_pow_challenge_issuance_and_solving():
    # Set low difficulty (2 leading zeros) for ultra-fast unit test execution
    mgr = PowChallengeManager(difficulty=2, ttl_seconds=60.0)
    ip = "192.0.2.77"

    challenge = mgr.issue_challenge(ip)
    assert challenge["ip"] == ip
    assert "seed" in challenge
    assert challenge["difficulty"] == 2
    assert "signature" in challenge

    # Solve the puzzle (client-side simulation)
    seed = challenge["seed"]
    nonce = None
    for i in range(100000):
        h = hashlib.sha256(f"{seed}{i}".encode("utf-8")).hexdigest()
        if h.startswith("00"):
            nonce = str(i)
            break

    assert nonce is not None

    # Verify correct solution
    ok, msg = mgr.verify_solution(
        ip=ip,
        seed=seed,
        difficulty=challenge["difficulty"],
        expires_at=challenge["expires_at"],
        signature=challenge["signature"],
        nonce=nonce
    )
    assert ok is True
    assert msg == "Challenge passed"

    # Replay protection: same nonce cannot be reused
    ok_replay, msg_replay = mgr.verify_solution(
        ip=ip,
        seed=seed,
        difficulty=challenge["difficulty"],
        expires_at=challenge["expires_at"],
        signature=challenge["signature"],
        nonce=nonce
    )
    assert ok_replay is False
    assert "replay attack" in msg_replay


def test_pow_challenge_tamper_detection():
    mgr = PowChallengeManager(difficulty=2)
    challenge = mgr.issue_challenge("10.0.0.1")

    # Tampered IP
    ok, msg = mgr.verify_solution(
        ip="10.0.0.2", # tampered
        seed=challenge["seed"],
        difficulty=challenge["difficulty"],
        expires_at=challenge["expires_at"],
        signature=challenge["signature"],
        nonce="123"
    )
    assert ok is False
    assert "Invalid challenge signature" in msg

"""STEALTHWALL — Native Proof-of-Work (PoW) Challenge Engine.

A 100% free, privacy-preserving client-side verification system.
Requires ZERO external APIs (no Google reCAPTCHA or Cloudflare keys).

How it Works:
  1. Server issues a cryptographic puzzle: seed + difficulty + HMAC signature.
  2. The visitor's browser calculates SHA-256 hashes until finding a nonce
     where SHA256(seed + nonce) starts with N leading zeros (~0.8 seconds).
  3. Server verifies the nonce in < 1 millisecond and issues a temporary
     clearance token.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Dict, Optional, Tuple

SECRET_KEY = secrets.token_bytes(32)

class PowChallengeManager:
    """Issues and verifies cryptographic Proof-of-Work puzzles."""

    def __init__(self, difficulty: int = 4, ttl_seconds: float = 300.0, secret_key: Optional[bytes] = None):
        self.difficulty = difficulty # number of leading hex zeros required
        self.ttl_seconds = ttl_seconds
        self.secret_key = secret_key or SECRET_KEY
        self._used_nonces: Dict[str, float] = {} # replay attack protection

    def issue_challenge(self, ip: str) -> dict:
        """Create a new PoW challenge for an IP."""
        seed = secrets.token_hex(16)
        expires_at = time.time() + self.ttl_seconds
        raw_msg = f"{ip}:{seed}:{self.difficulty}:{expires_at}"
        sig = hmac.new(self.secret_key, raw_msg.encode("utf-8"), hashlib.sha256).hexdigest()

        return {
            "ip": ip,
            "seed": seed,
            "difficulty": self.difficulty,
            "expires_at": expires_at,
            "signature": sig,
        }

    def verify_solution(self, ip: str, seed: str, difficulty: int, expires_at: float, signature: str, nonce: str) -> Tuple[bool, str]:
        """Verify the client's computed nonce."""
        now = time.time()
        if now > expires_at:
            return False, "Challenge expired"

        # 1. Verify HMAC signature integrity
        raw_msg = f"{ip}:{seed}:{difficulty}:{expires_at}"
        expected_sig = hmac.new(self.secret_key, raw_msg.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return False, "Invalid challenge signature"

        # 2. Prevent replay attacks
        replay_key = f"{seed}:{nonce}"
        if replay_key in self._used_nonces:
            return False, "Nonce already consumed (replay attack detected)"
        self._used_nonces[replay_key] = now

        # 3. Verify SHA-256 proof-of-work
        check_str = f"{seed}{nonce}".encode("utf-8")
        h = hashlib.sha256(check_str).hexdigest()
        target_prefix = "0" * difficulty

        if not h.startswith(target_prefix):
            return False, f"Proof-of-work invalid: hash {h[:8]}... does not meet difficulty {difficulty}"

        return True, "Challenge passed"


# Global singleton instance
pow_manager = PowChallengeManager()

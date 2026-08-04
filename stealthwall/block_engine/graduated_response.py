"""STEALTHWALL — graduated auto-block response engine (plan Section 6).

Response is graduated, never binary:

| Confidence                        | Action                                   |
|-----------------------------------|------------------------------------------|
| Low                               | Log only                                 |
| Medium                            | Rate-limit / throttle                    |
| Medium — unidentified shared IP   | Provisional short-TTL block (15–30 min)  |
| High                              | mCaptcha challenge                       |
| Very high / repeated              | Temporary IP block (hours-range TTL)     |
| Confirmed repeat offender         | Long-cooldown block (days-range TTL)     |

Mandatory on EVERY tier: whitelist/allowlist check and a manual unblock path.

Offense history (plan Section 6):
- Persists per IP PAST the block's own TTL expiry; a returning offender is
  escalated automatically — shorter grace, faster re-block.
- Decays on a LONGER window than any block TTL (blocks expire in days,
  history decays in months) so recycled dynamic/residential IPs are not
  penalized forever.

Blast-radius protections wired here:
- ASN gate (asn_check.py) runs BEFORE any block fires; known cloud/proxy/
  CGNAT ranges get their escalation confidence reduced.
- Unidentified-shared-IP mid-tier keeps worst-case wrong blocks short.
- If the ASN gate is DEGRADED (stale-list hard cap tripped), escalation
  decisions gated on it are refused down to provisional/rate-limit — fail
  loud, never pretend the list is fresh.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from block_engine import _config  # type: ignore
else:
    from . import _config


# ---------------------------------------------------------------------------
# Audit log — append-only, covers adaptive-layer AND block-engine changes
# (whitelist edits, executed responses, reconcile merges share this format).
# Honest limit (plan Section 6): same-box, same-admin logging is a small
# deterrent, not a barrier against a fully compromised admin.
# ---------------------------------------------------------------------------

def audit(record: dict, path: Optional[str] = None) -> None:
    target = Path(path or _config.AUDIT_LOG_PATH)
    target.parent.mkdir(parents=True, exist_ok=True)
    entry = {"ts": time.time(), **record}
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# Whitelist with re-auth-gated edits (plan Section 6: whitelist as an attack
# surface). Every edit requires a fresh re-auth token on the SAME admin
# session and is logged with timestamp + actor.
# ---------------------------------------------------------------------------

class Whitelist:
    def __init__(self, storage_path: str = "data/whitelist.json"):
        self.storage_path = Path(storage_path)
        self._ips: set = set()
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if self.storage_path.exists():
            try:
                self._ips = set(json.loads(self.storage_path.read_text()))
            except Exception as exc:  # noqa: BLE001
                print(f"[whitelist] WARNING load failed: {exc}", flush=True)

    def _persist(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_path.write_text(json.dumps(sorted(self._ips), indent=2))

    def contains(self, ip: str) -> bool:
        with self._lock:
            return ip in self._ips

    def add(self, ip: str, actor: str, reauth_age_seconds: float,
            now: float = None) -> dict:
        return self._edit("add", ip, actor, reauth_age_seconds, now)

    def remove(self, ip: str, actor: str, reauth_age_seconds: float,
               now: float = None) -> dict:
        return self._edit("remove", ip, actor, reauth_age_seconds, now)

    def _edit(self, op: str, ip: str, actor: str, reauth_age_seconds: float,
              now: float = None) -> dict:
        if _config.WHITELIST_REQUIRE_REAUTH:
            if reauth_age_seconds < 0:
                raise PermissionError("re-authentication required")
            if reauth_age_seconds > _config.WHITELIST_REAUTH_MAX_AGE_SECONDS:
                # stale re-auth forces password re-entry before editing
                raise PermissionError(
                    "re-auth token expired; password re-entry required"
                )
        before = sorted(self._ips)
        with self._lock:
            if op == "add":
                self._ips.add(ip)
            else:
                self._ips.discard(ip)
            after = sorted(self._ips)
            self._persist()
        audit({
            "kind": "whitelist_edit",
            "actor": actor,
            "op": op,
            "ip": ip,
            "before": before,
            "after": after,
        })
        return {"ok": True, "op": op, "ip": ip}

# ---------------------------------------------------------------------------
# Offense history with decay
# ---------------------------------------------------------------------------

@dataclass
class IpHistory:
    offenses: List[float] = field(default_factory=list)
    blocks: int = 0


class OffenseHistory:
    """Per-IP memory that OUTLIVES each block's TTL and decays slowly."""

    def __init__(self, storage_path: str = "data/offense_history.json"):
        self.storage_path = Path(storage_path)
        self._data: Dict[str, IpHistory] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if self.storage_path.exists():
            try:
                raw = json.loads(self.storage_path.read_text())
                self._data = {
                    ip: IpHistory(offenses=e.get("offenses", []),
                                  blocks=e.get("blocks", 0))
                    for ip, e in raw.items()
                }
            except Exception as exc:  # noqa: BLE001
                print(f"[offense_history] WARNING load failed: {exc}",
                      flush=True)

    def _persist_locked(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_path.write_text(json.dumps(
            {ip: {"offenses": h.offenses, "blocks": h.blocks}
             for ip, h in self._data.items()}
        ))

    @staticmethod
    def _decayed(count_ts: List[float], now: float) -> float:
        half_life = _config.OFFENSE_HISTORY_DECAY_HALF_LIFE_DAYS * 86400.0
        return sum(0.5 ** ((now - t) / half_life) for t in count_ts)

    def record_block(self, ip: str, now: float = None) -> None:
        now = now if now is not None else time.time()
        with self._lock:
            h = self._data.setdefault(ip, IpHistory())
            h.blocks += 1
            h.offenses.append(now)
            self._persist_locked()

    def effective_offenses(self, ip: str, now: float = None) -> int:
        """Decay-weighted count, floored to int. Returns 0 for unknown IPs;
        months-old history contributes ~nothing (recycled-IP fairness)."""
        now = now if now is not None else time.time()
        with self._lock:
            h = self._data.get(ip)
            if not h:
                return 0
            return int(self._decayed(h.offenses, now))

    def total_blocks(self, ip: str) -> int:
        with self._lock:
            h = self._data.get(ip)
            return h.blocks if h else 0


# ---------------------------------------------------------------------------
# Response engine
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    action: str          # none|log_only|rate_limit|provisional_block|
                         # captcha|temp_block|long_cooldown_block
    tier: str            # none|low|medium|medium_shared|high|very_high|repeat
    score: float
    ttl_seconds: int = 0
    reason: str = ""
    asn_tag: dict = field(default_factory=dict)

    def to_dashboard_entry(self) -> dict:
        """Dashboard-facing serialization (ASN tags allowed HERE only)."""
        return {
            "action": self.action, "tier": self.tier, "score": self.score,
            "ttl_seconds": self.ttl_seconds, "reason": self.reason,
            "asn": self.asn_tag, "at": time.time(),
        }


class RateLimiter:
    """In-process sliding-window throttle for the MEDIUM tier."""

    def __init__(self):
        self._hits: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def check(self, ip: str, now: float = None) -> bool:
        """True => within limit; False => throttled."""
        now = now if now is not None else time.time()
        with self._lock:
            window_start = now - _config.RATE_LIMIT_WINDOW_SECONDS
            hits = [t for t in self._hits.get(ip, []) if t > window_start]
            if len(hits) >= _config.RATE_LIMIT_MAX_REQUESTS:
                self._hits[ip] = hits
                return False
            hits.append(now)
            self._hits[ip] = hits
            return True

    def throttle_delay(self) -> float:
        return _config.RATE_LIMIT_THROTTLE_DELAY_SECONDS


class GraduatedResponseEngine:
    def __init__(
        self,
        blocker,                     # BlockWriterClient-compatible (or DryRun)
        asn_gate=None,               # asn_check.AsnCheck instance
        whitelist: Whitelist = None,
        history: OffenseHistory = None,
        rate_limiter: RateLimiter = None,
        captcha_provider=None,       # mcaptcha.CaptchaProvider-compatible
        clock_skew_auditor=None,     # optional callable(ip, ctx) hook
    ) -> None:
        self.blocker = blocker
        self.asn_gate = asn_gate
        self.whitelist = whitelist or Whitelist()
        self.history = history or OffenseHistory()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.captcha_provider = captcha_provider

    # -- main entry ----------------------------------------------------------
    def decide_and_respond(self, ip: str, raw_score: float,
                           now: float = None) -> Decision:
        now = now if now is not None else time.time()

        if self.whitelist.contains(ip):
            return Decision("none", "whitelisted", raw_score,
                            reason="allowlisted source")

        asn_tag = (self.asn_gate.classify(ip)
                   if self.asn_gate else
                   {"is_shared_infra": False, "confidence_weight": 1.0,
                    "asn": None, "table_state": "absent"})
        gating_ok = (self.asn_gate.gating_available()
                     if self.asn_gate else True)

        # Returning offenders escalate faster: additive boost while history
        # is alive, shrinking as it decays away.
        eff = self.history.effective_offenses(ip, now)
        boosted = min(1.0, raw_score + _config.RETURNING_OFFENDER_SCORE_BOOST
                      * min(eff, 3))

        # Tier classification uses the UNWEIGHTED boosted score so the
        # medium-tier provisional path stays reachable for shared sources.
        # The ASN confidence weight is applied BEFORE ESCALATION (block
        # tiers) inside _execute — known cloud/proxy/CGNAT ranges get their
        # blocking escalation reduced rather than erased.
        tier = self._tier_name(boosted, eff)

        # Shared-like = known shared infra, OR unknown to the ASN table
        # (could be CGNAT behind nobody's list), OR the gate is degraded.
        # These are capped at provisional blocks by design: shrink the
        # blast-radius duration of a wrong block (plan Section 6).
        shared_like = (
            bool(asn_tag.get("is_shared_infra"))
            or asn_tag.get("asn") is None
            or asn_tag.get("table_state") == "degraded"
            or not gating_ok
        )

        decision = self._execute(ip, boosted, tier, eff, asn_tag,
                                 shared_like, now)
        return decision

    @staticmethod
    def _tier_name(score: float, effective_offenses: int) -> str:
        if (effective_offenses >= _config.ESCALATE_TO_LONG_COOLDOWN_OFFENSES
                and score >= _config.TIER_MEDIUM_THRESHOLD):
            return "repeat"
        if score >= _config.TIER_VERY_HIGH_THRESHOLD:
            return "very_high"
        if score >= _config.TIER_HIGH_THRESHOLD:
            return "high"
        if score >= _config.TIER_MEDIUM_THRESHOLD:
            return "medium"
        if score >= _config.TIER_LOW_THRESHOLD:
            return "low"
        return "none"

    # -- action execution ------------------------------------------------------
    def _execute(self, ip: str, score: float, tier: str, eff: int,
                 asn_tag: dict, shared_like: bool, now: float) -> Decision:
        if tier == "none":
            return Decision("none", tier, score)
        if tier == "low":
            return Decision("log_only", tier, score, reason="below throttle")

        if tier == "medium":
            # Response-table row: "Medium — unidentified shared IP" gets the
            # short-TTL provisional block BEFORE any escalation.
            if shared_like:
                ttl = _config.ttl_for_provisional_shared_ip()
                self.blocker.block(ip, ttl)
                self.history.record_block(ip, now)
                audit({"kind": "response", "action": "provisional_block",
                       "ip": ip, "score": score, "ttl": ttl})
                return Decision("provisional_block", "medium_shared", score,
                                ttl, "unidentified/shared source", asn_tag)
            self.rate_limiter.check(ip, now)
            audit({"kind": "response", "action": "rate_limit", "ip": ip,
                   "score": score})
            return Decision("rate_limit", tier, score,
                            reason="identified non-shared source")

        if tier == "high":
            if self.captcha_provider is not None:
                self.captcha_provider.issue_challenge(ip)
                audit({"kind": "response", "action": "captcha",
                       "ip": ip, "score": score})
                return Decision("captcha", tier, score, 0,
                                "challenge issued", asn_tag)
            # No CAPTCHA subsystem available: degrade to throttle, loudly.
            print("[graduated] WARNING: high tier without captcha provider;"
                  " degrading to rate_limit", flush=True)
            self.rate_limiter.check(ip, now)
            return Decision("rate_limit", tier, score,
                            reason="captcha unavailable")

        if tier == "very_high":
            # Reduced-confidence escalation for shared-like sources: they
            # are capped at the short provisional TTL (blast radius), never
            # jumped straight to hours/days on first evidence.
            if shared_like:
                ttl = _config.ttl_for_provisional_shared_ip()
                self.blocker.block(ip, ttl)
                self.history.record_block(ip, now)
                audit({"kind": "response", "action": "provisional_block",
                       "ip": ip, "score": score, "ttl": ttl,
                       "note": "shared-like capped before escalation"})
                return Decision("provisional_block", "medium_shared", score,
                                ttl, "shared-like: reduced-confidence cap",
                                asn_tag)
            ttl = _config.ttl_for_temp_block(max(1, eff))
            self.blocker.block(ip, ttl)
            self.history.record_block(ip, now)
            audit({"kind": "response", "action": "temp_block", "ip": ip,
                   "score": score, "ttl": ttl})
            return Decision("temp_block", tier, score, ttl,
                            "very high confidence", asn_tag)

        if tier == "repeat":
            ttl = _config.ttl_for_repeat_offender(
                max(eff, self.history.total_blocks(ip)))
            self.blocker.block(ip, ttl)
            self.history.record_block(ip, now)
            audit({"kind": "response", "action": "long_cooldown_block",
                   "ip": ip, "score": score, "ttl": ttl})
            return Decision("long_cooldown_block", tier, score, ttl,
                            f"repeat offender ({eff} decayed offenses)",
                            asn_tag)

        return Decision("none", tier, score)

    # -- mandatory manual path ---------------------------------------------
    def manual_unblock(self, ip: str, actor: str) -> dict:
        result = self.blocker.unblock(ip, reason=f"manual:{actor}")
        audit({"kind": "manual_unblock", "ip": ip, "actor": actor})
        return result

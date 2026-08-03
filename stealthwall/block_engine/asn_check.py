"""STEALTHWALL — ASN-aware blast-radius protection (plan Section 6).

Loads a free static IP2ASN-lite flat file (zero-budget rule) at startup and
refreshes it via an IN-PROCESS scheduled task — deliberately NOT cron, since
many container base images lack cron and a cron job can silently never run.

Behaviors mandated by the plan:
- Refresh-failure fallback: keep last-known-good list in cache, log a
  warning, continue.
- HARD CAP on stale fallback: after ASN_MAX_CONSECUTIVE_REFRESH_FAILURES
  consecutive failures, escalate from "log warning" to REFUSING further
  ASN-gated blocking decisions (fails loud) rather than silently serving an
  arbitrarily stale list forever.
- Known cloud/proxy/CGNAT ranges get reduced confidence weight before
  escalation.
- The same lookup tags dashboard entries. ASN info is dashboard-ONLY and is
  never included in client-facing responses (info-leak caveat: not
  exhaustively audited for timing/status side channels — plan Section 6).

Stdlib-only: urllib for download, gzip + bisect over a sorted array of
(start_int, end_int) ranges for O(log n) lookup.
"""

from __future__ import annotations

import bisect
import gzip
import shutil
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from block_engine import _config  # type: ignore
else:
    from . import _config


@dataclass(frozen=True)
class AsnRecord:
    start: int
    end: int
    asn: int
    country: str
    isp: str

    @property
    def is_shared_infra(self) -> bool:
        """Keyword classification of known cloud/proxy/CGNAT operators."""
        name = self.isp.lower()
        return any(
            kw in name
            for kw in (
                "amazon", "aws", "google cloud", "microsoft", "azure",
                "digitalocean", "linode", "ovh", "hetzner", "vultr",
                "cloudflare", "oracle cloud", "alibaba", "tencent",
                "proxy", "hosting", "data center", "datacenter", "cgnat",
                "carrier-grade nat", "vpn",
            )
        )


def ip_to_int(ip: str) -> Optional[int]:
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return None
    value = 0
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return None
        value = (value << 8) | int(p)
    return value


class AsnTable:
    """Sorted flat-file table with O(log n) range lookup."""

    def __init__(self) -> None:
        self._starts: List[int] = []
        self._records: List[AsnRecord] = []

    def load_tsv(self, text: str) -> None:
        starts: List[int] = []
        records: List[AsnRecord] = []
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) < 5:
                continue
            try:
                start, end, asn = int(fields[0]), int(fields[1]), int(fields[2])
            except ValueError:
                continue
            rec = AsnRecord(start, end, asn, fields[3], fields[4])
            starts.append(start)
            records.append(rec)
        order = sorted(range(len(starts)), key=lambda i: starts[i])
        self._starts = [starts[i] for i in order]
        self._records = [records[i] for i in order]

    def lookup(self, ip_int: int) -> Optional[AsnRecord]:
        if not self._starts:
            return None
        idx = bisect.bisect_right(self._starts, ip_int) - 1
        if idx < 0:
            return None
        rec = self._records[idx]
        if rec.start <= ip_int <= rec.end:
            return rec
        return None

    def __len__(self) -> int:
        return len(self._records)


class AsnCheck:
    """Public API used by graduated_response + dashboard."""

    STATE_OK = "ok"
    STATE_STALE_WARNING = "stale_warning"
    STATE_DEGRADED = "degraded"

    def __init__(
        self,
        cache_path: str = None,
        url: str = None,
        start_scheduler: bool = True,
    ) -> None:
        self.url = url or _config.ASN_LIST_URL
        self.cache_path = Path(cache_path or _config.ASN_CACHE_PATH)
        self.table = AsnTable()
        self.consecutive_failures = 0
        self.last_refresh_attempt: float = 0.0
        self.last_success: float = 0.0
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._load_cache()
        if start_scheduler:
            self.start_scheduler()

    # -- loading ------------------------------------------------------------
    def _load_cache(self) -> bool:
        """Load last-known-good cache at startup (refresh-failure fallback)."""
        if not self.cache_path.exists():
            return False
        try:
            self.table.load_tsv(self.cache_path.read_text(encoding="utf-8"))
            print(f"[asn_check] loaded cached table ({len(self.table)} ranges)",
                  flush=True)
            return True
        except Exception as exc:  # noqa: BLE001
            print(f"[asn_check] WARNING: cache load failed: {exc}", flush=True)
            return False

    def refresh(self) -> bool:
        """One refresh attempt. Updates consecutive-failure accounting and
        enforces the hard-cap escalation."""
        self.last_refresh_attempt = time.time()
        ok = False
        tmp_text: Optional[str] = None
        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": "stealthwall"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            if self.url.endswith(".gz"):
                data = gzip.decompress(data)
            tmp_text = data.decode("utf-8")
            probe = AsnTable()
            probe.load_tsv(tmp_text)
            if len(probe) == 0:
                raise RuntimeError("downloaded ASN table parsed to zero rows")
            ok = True
        except Exception as exc:  # noqa: BLE001
            print(f"[asn_check] WARNING: refresh failed: {exc}", flush=True)

        with self._lock:
            if ok:
                self.table.load_tsv(tmp_text)
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                self.cache_path.write_text(tmp_text, encoding="utf-8")
                self.consecutive_failures = 0
                self.last_success = time.time()
            else:
                self.consecutive_failures += 1
                if self.consecutive_failures >= _config.ASN_MAX_CONSECUTIVE_REFRESH_FAILURES:
                    # FAIL LOUD: refuse further ASN-gated decisions rather
                    # than serving an arbitrarily stale list forever.
                    # The last-known-good cache stays on disk so a restart
                    # can still serve dashboard tags; gating_available()
                    # returning False is what blocks escalation decisions.
                    print(
                        "CRITICAL: [asn_check] "
                        f"{self.consecutive_failures} consecutive refresh "
                        "failures — refusing further ASN-gated blocking "
                        "decisions until a refresh succeeds.",
                        file=sys.stderr, flush=True,
                    )

        return ok

    # -- scheduler ------------------------------------------------------------
    def start_scheduler(self) -> None:
        interval = _config.ASN_REFRESH_INTERVAL_HOURS * 3600.0

        def loop():
            while not self._stop.wait(interval):
                try:
                    self.refresh()
                except Exception as exc:  # noqa: BLE001
                    print(f"[asn_check] scheduler error: {exc}", flush=True)

        threading.Thread(target=loop, daemon=True, name="asn-refresh").start()

    def stop(self) -> None:
        self._stop.set()

    # -- queries --------------------------------------------------------------
    @property
    def state(self) -> str:
        if self.consecutive_failures >= _config.ASN_MAX_CONSECUTIVE_REFRESH_FAILURES:
            return self.STATE_DEGRADED
        if self.consecutive_failures > 0:
            return self.STATE_STALE_WARNING
        return self.STATE_OK

    def gating_available(self) -> bool:
        """False once the hard cap trips — callers must NOT make ASN-gated
        escalation decisions while degraded (fail loud, plan Section 6)."""
        return self.state != self.STATE_DEGRADED

    def classify(self, ip: str) -> dict:
        """Dashboard-facing tag. NEVER include this payload in any
        client-facing response (info-leak caveat, plan Section 6)."""
        ip_int = ip_to_int(ip)
        rec = self.table.lookup(ip_int) if ip_int is not None else None
        shared = bool(rec and rec.is_shared_infra)
        return {
            "ip": ip,
            "asn": rec.asn if rec else None,
            "isp": rec.isp if rec else None,
            "country": rec.country if rec else None,
            "is_shared_infra": shared,
            # reduced confidence weight applied before escalation when the
            # source is known shared infrastructure
            "confidence_weight": (
                _config.ASN_REDUCED_CONFIDENCE_WEIGHT if shared else 1.0
            ),
            "table_state": self.state,
        }


if __name__ == "__main__":
    checker = AsnCheck(url="", start_scheduler=False)  # offline demo mode
    checker.refresh()
    for probe_ip in ("8.8.8.8", "13.32.0.1", "999.1.1.1"):
        print(probe_ip, "->", checker.classify(probe_ip))

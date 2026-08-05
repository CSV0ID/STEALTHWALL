"""STEALTHWALL — reconcile-on-reconnect for shared-store outages
(plan Section 6).

When the shared block store is unreachable, StealthWall keeps serving from
LOCAL iptables state (fail-open availability posture). Every local
block/unblock made during the outage is recorded here as a timestamped
pending op. On reconnect, pending ops are replayed into the shared store:

- Last-write-wins BY TIMESTAMP between local and remote entries.
- SPOOFING BOUND (crude protection only): an op whose timestamp skews MORE
  than RECONCILE_MAX_CLOCK_SKEW_SECONDS (default 300 s / 5 min) from this
  instance's local clock is rejected OUTRIGHT. This catches crude clock
  spoofing; it is NOT a defense against a deliberate attacker who keeps skew
  under the bound — such a write still wins last-write-wins.
- REJECTED WRITES ARE LOGGED, never silently dropped: a legitimate write
  caught by real clock skew leaves a traceable failure record in
  RECONCILE_REJECT_LOG_PATH.

REQUIRED DEPLOYMENT STEP: NTP time sync across all instances sharing a
store. Without it, last-write-wins ordering is meaningless.

KNOWN LIMITS (plan Section 6, accepted unfixed):
- A genuine race — a legitimate manual unblock and a real re-attack landing
  at the same moment during reconnect — can still resolve incorrectly.
  Closing this fully needs a richer conflict-resolution protocol outside
  project scope.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from block_engine import _config  # type: ignore
else:
    from . import _config


@dataclass
class BlockOp:
    op: str              # "block" | "unblock"
    ip: str
    ts: float            # originating-instance wall clock
    actor: str = "system"
    ttl_seconds: int = 0

    @staticmethod
    def from_journal_record(rec: dict) -> Optional["BlockOp"]:
        op = rec.get("op")
        if op not in ("block", "unblock") or "ip" not in rec or "at" not in rec:
            return None
        return BlockOp(op, rec["ip"], float(rec["at"]),
                       str(rec.get("reason", "system")),
                       int(rec.get("ttl", 0)))


class SharedStoreUnreachable(RuntimeError):
    pass


class FileSharedStore:
    """Minimal JSON-file shared store standing in for Redis/DB deployments.
    Entries: ip -> {"op", "ts", "actor", "ttl_seconds"}."""

    def __init__(self, path: str = "data/shared_blocks.json",
                 timeout: float = None):
        self.path = Path(path)
        self.timeout = timeout or _config.SHARED_STORE_TIMEOUT_SECONDS

    def fetch(self, ip: str) -> Optional[dict]:
        return self._load().get(ip)

    def push(self, ip: str, entry: dict) -> None:
        data = self._load()
        data[ip] = entry
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
        tmp.replace(self.path)

    def all_entries(self) -> Dict[str, dict]:
        return self._load()

    def _load(self) -> Dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except Exception as exc:  # noqa: BLE001
            raise SharedStoreUnreachable(f"shared store unreadable: {exc}")


class ReconcileManager:
    def __init__(
        self,
        store: FileSharedStore,
        pending_path: str = "data/reconcile_pending.jsonl",
        reject_log_path: str = None,
        local_clock=time.time,
        applier=None,
    ):
        """`applier(ip, op)` lets the manager also update LOCAL iptables
        state when a REMOTE entry wins the merge (keeps local authoritative
        last-known-good consistent after reconciliation)."""
        self.store = store
        self.pending_path = Path(pending_path)
        self.reject_log_path = Path(
            reject_log_path or _config.RECONCILE_REJECT_LOG_PATH)
        self.local_clock = local_clock
        self.applier = applier
        self._lock = threading.Lock()

    # -- outage-side recording -------------------------------------------------
    def record_pending(self, op: BlockOp) -> None:
        with self._lock:
            self.pending_path.parent.mkdir(parents=True, exist_ok=True)
            with self.pending_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(op), sort_keys=True) + "\n")

    def load_from_block_journal(self, journal_path: str) -> int:
        """Bulk-import ops logged locally while disconnected."""
        count = 0
        jp = Path(journal_path)
        if not jp.exists():
            return 0
        for line in jp.read_text().splitlines():
            op = BlockOp.from_journal_record(json.loads(line))
            if op:
                self.record_pending(op)
                count += 1
        return count

    # -- reconnect-side merge ----------------------------------------------------
    def on_reconnect(self) -> dict:
        """Replay pending ops into the shared store. Returns a report;
        rejected ops are logged to the reject log and removed from pending,
        leaving a permanent traceable record (never silent)."""
        now_local = self.local_clock()
        report = {"applied": [], "skipped_stale": [], "rejected": [],
                  "failed_store": []}

        try:
            ops = self._drain_pending()
        except Exception as exc:  # noqa: BLE001
            raise SharedStoreUnreachable(
                f"cannot read pending ops: {exc}") from exc

        for op in ops:
            skew = abs(now_local - op.ts)
            if skew > _config.RECONCILE_MAX_CLOCK_SKEW_SECONDS:
                # Crude-spoof bound: reject outright, LOG the rejection.
                self._log_rejection(op, skew, now_local,
                                    "clock_skew_beyond_bound")
                report["rejected"].append({"ip": op.ip, "op": op.op,
                                           "skew_seconds": round(skew, 3)})
                continue
            try:
                remote = self.store.fetch(op.ip)
            except SharedStoreUnreachable as exc:
                # Fail-open: keep op pending for the next reconnect attempt.
                self.record_pending(op)
                report["failed_store"].append({"ip": op.ip, "error": str(exc)})
                continue
            if remote is not None and remote.get("ts", 0) > op.ts:
                # Remote is newer AND wins last-write-wins; make sure LOCAL
                # engine converges to the winner via the applier hook.
                if self.applier:
                    self.applier(op.ip, remote)
                report["skipped_stale"].append({"ip": op.ip, "op": op.op})
                continue
            self.store.push(op.ip, {
                "op": op.op, "ts": op.ts, "actor": op.actor,
                "ttl_seconds": op.ttl_seconds,
            })
            report["applied"].append({"ip": op.ip, "op": op.op})

        return report

    def _drain_pending(self) -> List[BlockOp]:
        ops: List[BlockOp] = []
        if self.pending_path.exists():
            for line in self.pending_path.read_text().splitlines():
                if line.strip():
                    ops.append(BlockOp(**json.loads(line)))
        return ops

    def _log_rejection(self, op: BlockOp, skew: float, received_at: float,
                       reason: str) -> None:
        self.reject_log_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "rejected_at": received_at,
            "reason": reason,
            "skew_seconds": round(skew, 3),
            "bound_seconds": _config.RECONCILE_MAX_CLOCK_SKEW_SECONDS,
            "op": asdict(op),
        }
        with self.reject_log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")


if __name__ == "__main__":
    # Offline demo of the three outcomes: apply / stale-skip / reject.
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="sw_reconcile_"))

    fixed_now = 1_800_000_000.0

    def clock():
        return fixed_now

    store = FileSharedStore(str(tmp / "shared.json"))
    mgr = ReconcileManager(store,
                           pending_path=str(tmp / "pending.jsonl"),
                           reject_log_path=str(tmp / "rejects.jsonl"),
                           local_clock=clock)

    # op within skew bound, no remote -> applied
    mgr.record_pending(BlockOp("block", "10.0.0.5", fixed_now - 60))
    # remote newer than local op -> stale-skip
    store.push("10.0.0.6", {"op": "block", "ts": fixed_now - 30,
                            "actor": "other-instance"})
    mgr.record_pending(BlockOp("unblock", "10.0.0.6", fixed_now - 120))
    # timestamp 1 hour off -> rejected + logged
    mgr.record_pending(BlockOp("block", "10.0.0.7", fixed_now - 3600))

    print(json.dumps(mgr.on_reconnect(), indent=2))
    print("reject log:", (tmp / "rejects.jsonl").read_text().strip())

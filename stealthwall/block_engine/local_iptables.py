"""STEALTHWALL — local iptables block engine (plan Section 6).

Two components:

1. `BlockWriterServer` — the SINGLE-WRITER QUEUE. Exactly one dedicated
   process owns ALL `iptables` writes; every other worker (Node cluster,
   uvicorn workers, dashboard) submits block/unblock requests over a unix
   socket via `BlockWriterClient`. This closes the concurrency race where
   multiple workers clobber each other's rules.

2. `BlockWriterClient` — thin IPC client used by middleware workers.
   It NEVER shells out to iptables itself.

Startup discipline (plan Section 6, "Deployment OS assumption"):
`verify_environment()` checks that iptables exists and is callable BEFORE
the system starts. If unavailable the engine FAILS LOUD: raises
IptablesUnavailable unless the operator explicitly sets
STEALTHWALL_ALLOW_NO_IPTABLES=1 (dev/test only) — and even then logs an
unmissable CRITICAL banner instead of failing silently.

Deployment assumption: Linux host where iptables operates on the host
network namespace directly. Container/orchestrated deployments where local
iptables does not reach the traffic path are explicitly UNSUPPORTED by this
mechanism (plan Section 0/14 Known Limit).

All rules live in the dedicated chain config.IPTABLES_CHAIN — built-in
chains are never modified except one idempotent jump rule from INPUT.
"""

from __future__ import annotations

import heapq
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from block_engine import _config  # type: ignore
else:
    from . import _config


class IptablesUnavailable(RuntimeError):
    """Raised when iptables cannot be found/executed at startup."""


def verify_environment(require_root: bool = False) -> None:
    """Fail-loud startup check (plan Section 6).

    Raises IptablesUnavailable when iptables is missing/broken unless the
    explicit dev override STEALTHWALL_ALLOW_NO_IPTABLES=1 is set — in which
    case we log a CRITICAL banner so the degraded state is impossible to
    miss, never silent.
    """
    path = shutil.which("iptables")
    problems = []
    if path is None:
        problems.append("iptables binary not found on PATH")
    else:
        try:
            proc = subprocess.run(
                [path, "--version"], capture_output=True, text=True, timeout=10
            )
            if proc.returncode != 0:
                problems.append(f"iptables --version failed rc={proc.returncode}")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"iptables --version raised {exc!r}")
    if require_root and os.geteuid() != 0:
        problems.append("not running as root; iptables writes will fail")

    if not problems:
        return

    if os.environ.get("STEALTHWALL_ALLOW_NO_IPTABLES") == "1":
        print("=" * 72, file=sys.stderr, flush=True)
        print("CRITICAL: STEALTHWALL RUNNING WITH BLOCKING DEGRADED:", file=sys.stderr, flush=True)
        for p in problems:
            print(f"CRITICAL:   - {p}", file=sys.stderr, flush=True)
        print(
            "CRITICAL: detection will run but NO IP BLOCKS WILL BE APPLIED.",
            file=sys.stderr,
            flush=True,
        )
        print("=" * 72, file=sys.stderr, flush=True)
        return

    raise IptablesUnavailable("; ".join(problems))


def _run_iptables(args):
    cmd = ["iptables", "-w", *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if proc.returncode != 0:
        raise RuntimeError(f"iptables {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


class BlockWriterServer:
    """Single-writer queue: owns every iptables mutation (plan Section 6)."""

    def __init__(self, socket_path: str = None, journal_path: str = None):
        self.socket_path = socket_path or _config.BLOCK_WRITER_SOCKET_PATH
        self.journal_path = Path(
            journal_path or "data/block_journal.jsonl"
        )
        self._lock = threading.Lock()
        self._ttl_heap = []  # (expire_ts, ip, seq)
        self._seq = 0
        self._stop = threading.Event()
        self._active_blocks: Dict[str, float] = {}

    # -- chain management ---------------------------------------------------
    def ensure_chain(self) -> None:
        _run_iptables(["-N", _config.IPTABLES_CHAIN]) if not self._chain_exists() else None
        jumps = _run_iptables(["-S", "INPUT"])
        jump_rule = f"-j {_config.IPTABLES_CHAIN}"
        if jump_rule not in jumps:
            _run_iptables(["-A", "INPUT", "-j", _config.IPTABLES_CHAIN])

    def _chain_exists(self) -> bool:
        out = _run_iptables(["-S"])
        return f"-N {_config.IPTABLES_CHAIN}" in out

    # -- core operations ----------------------------------------------------
    def apply_block(self, ip: str, ttl_seconds: int) -> dict:
        now = time.time()
        with self._lock:
            already = self._active_blocks.get(ip)
            if already is not None and already > now:
                # extend to the LONGER of existing/new expiry (never shorten)
                ttl_seconds = max(int(already - now), int(ttl_seconds))
            _run_iptables([
                "-A", _config.IPTABLES_CHAIN, "-s", ip, "-j", "DROP",
                "-m", "comment", "--comment", "stealthwall",
            ])
            expire = now + int(ttl_seconds)
            self._seq += 1
            self._active_blocks[ip] = expire
            heapq.heappush(self._ttl_heap, (expire, ip, self._seq))
            self._journal({"op": "block", "ip": ip, "at": now,
                           "expires": expire})
        return {"ok": True, "ip": ip, "expires_at": expire}

    def apply_unblock(self, ip: str, reason: str = "manual") -> dict:
        with self._lock:
            # remove ALL stealthwall rules for this IP (idempotent)
            while True:
                check = _run_iptables([
                    "-C", _config.IPTABLES_CHAIN, "-s", ip, "-j", "DROP",
                    "-m", "comment", "--comment", "stealthwall",
                ]) if self._rule_exists(ip) else None
                if check is None:
                    break
                _run_iptables([
                    "-D", _config.IPTABLES_CHAIN, "-s", ip, "-j", "DROP",
                    "-m", "comment", "--comment", "stealthwall",
                ])
            self._active_blocks.pop(ip, None)
            self._journal({"op": "unblock", "ip": ip, "at": time.time(),
                           "reason": reason})
        return {"ok": True, "ip": ip}

    def _rule_exists(self, ip: str) -> bool:
        try:
            _run_iptables(["-c", "0", "0", "-C", _config.IPTABLES_CHAIN,
                           "-s", ip, "-j", "DROP", "-m", "comment",
                           "--comment", "stealthwall"])
            return True
        except RuntimeError:
            return False

    def _journal(self, record: dict) -> None:
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    # -- TTL sweeper ---------------------------------------------------------
    def sweep_expired(self) -> int:
        now = time.time()
        removed = 0
        while self._ttl_heap and self._ttl_heap[0][0] <= now:
            expire, ip, _seq = heapq.heappop(self._ttl_heap)
            if self._active_blocks.get(ip) == expire:
                self.apply_unblock(ip, reason="ttl_expired")
                removed += 1
        return removed

    def serve_forever(self) -> None:
        """Run the single writer: unix socket IPC + TTL sweeper."""
        verify_environment()
        self.ensure_chain()
        sock_path = Path(self.socket_path)
        sock_path.parent.mkdir(parents=True, exist_ok=True)
        if sock_path.exists():
            sock_path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(64)

        def sweeper():
            while not self._stop.wait(5.0):
                try:
                    self.sweep_expired()
                except Exception as exc:  # noqa: BLE001
                    print(f"[block_writer] sweeper error: {exc}", flush=True)

        threading.Thread(target=sweeper, daemon=True, name="ttl-sweeper").start()

        def shutdown(_sig, _frm):
            self._stop.set()
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)

        print(f"[block_writer] single-writer queue listening on "
              f"{sock_path} (chain {_config.IPTABLES_CHAIN})", flush=True)
        server.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            with conn:
                try:
                    req = json.loads(conn.recv(65536).decode("utf-8"))
                    resp = self._handle(req)
                except Exception as exc:  # noqa: BLE001
                    resp = {"ok": False, "error": repr(exc)}
                conn.sendall(json.dumps(resp).encode("utf-8"))
        server.close()

    def _handle(self, req: dict) -> dict:
        op = req.get("op")
        if op == "block":
            return self.apply_block(req["ip"], int(req["ttl_seconds"]))
        if op == "unblock":
            return self.apply_unblock(req["ip"], req.get("reason", "manual"))
        if op == "check":
            ip = req["ip"]
            now = time.time()
            expire = self._active_blocks.get(ip)
            blocked = expire is not None and expire > now
            return {"ok": True, "ip": ip, "blocked": blocked,
                    "expires_at": expire if blocked else None}
        if op == "status":
            return {"ok": True, "active_blocks": len(self._active_blocks)}
        return {"ok": False, "error": f"unknown op {op!r}"}


class BlockWriterClient:
    """Worker-side client. Submits requests over IPC; NEVER calls iptables."""

    def __init__(self, socket_path: str = None, timeout: float = 5.0):
        self.socket_path = socket_path or _config.BLOCK_WRITER_SOCKET_PATH
        self.timeout = timeout

    def request(self, payload: dict) -> dict:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
            sock.sendall(json.dumps(payload).encode("utf-8"))
            data = sock.recv(65536)
            return json.loads(data.decode("utf-8"))
        finally:
            sock.close()

    def block(self, ip: str, ttl_seconds: int) -> dict:
        return self.request({"op": "block", "ip": ip, "ttl_seconds": ttl_seconds})

    def unblock(self, ip: str, reason: str = "manual") -> dict:
        return self.request({"op": "unblock", "ip": ip, "reason": reason})


class DryRunBlocker:
    """Dev/test stand-in with the same interface as the client+server pair.
    Records blocks in memory; applies nothing. The CRITICAL startup banner
    printed by verify_environment() is what keeps this honest in production.
    """

    def __init__(self):
        self.blocks: Dict[str, float] = {}
        self.unblocks: list = []

    def block(self, ip: str, ttl_seconds: int) -> dict:
        expires = time.time() + ttl_seconds
        prev = self.blocks.get(ip)
        if prev is not None and prev > time.time():
            expires = max(expires, prev)
        self.blocks[ip] = expires
        return {"ok": True, "ip": ip, "expires_at": expires, "dry_run": True}

    def unblock(self, ip: str, reason: str = "manual") -> dict:
        self.blocks.pop(ip, None)
        self.unblocks.append((ip, reason, time.time()))
        return {"ok": True, "ip": ip, "dry_run": True}

    def request(self, payload: dict) -> dict:
        """Same wire protocol as BlockWriterClient.request() so middleware
        pre-enforcement code is identical in dev and production."""
        op = payload.get("op")
        now = time.time()
        if op == "check":
            expire = self.blocks.get(payload["ip"])
            blocked = expire is not None and expire > now
            return {"ok": True, "blocked": blocked,
                    "expires_at": expire if blocked else None}
        if op == "block":
            return self.block(payload["ip"], int(payload["ttl_seconds"]))
        if op == "unblock":
            return self.unblock(payload["ip"])
        if op == "status":
            return {"ok": True, "active_blocks": len(self.blocks)}
        return {"ok": False, "error": f"unknown op {op!r}"}


def make_blocker(dry_run: bool | None = None):
    """Factory used by middleware wiring. Production default: fail-loud
    verification then IPC client. Dev override env var flips to dry-run
    AFTER printing the unmissable CRITICAL banner."""
    if dry_run is None:
        try:
            verify_environment()
            dry_run = False
        except IptablesUnavailable as exc:
            print(f"CRITICAL: {exc}", file=sys.stderr, flush=True)
            print(
                "CRITICAL: set STEALTHWALL_ALLOW_NO_IPTABLES=1 to run with "
                "blocking disabled (dev only).",
                file=sys.stderr, flush=True,
            )
            raise
    if dry_run:
        verify_environment()  # prints the CRITICAL banner under the env var
        return DryRunBlocker()
    return BlockWriterClient()


if __name__ == "__main__":
    BlockWriterServer().serve_forever()

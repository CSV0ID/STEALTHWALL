"""STEALTHWALL — Model 1 training dataset generator (models/coldstart).

HONEST STATUS (plan Section 8): until real attack passes are logged into
data/voidstrike_scans and data/supplementary_scans, this generator produces
SYNTHETIC stand-in windows modeling each tool family's behavior. It exists
so the full train -> export -> serve pipeline works end-to-end from day one.
Real logged traffic replaces these samples in Month 1 Week 2+; the schema
(vector + label + family + source) stays identical either way.

Environment-monoculture mitigation (plan Section 8): timing/jitter profiles
are varied synthetically per sample. This is a patch, NOT real environmental
diversity.

Output JSONL rows:
    {"vector": [14 floats], "label": "attack"|"benign",
     "family": "scan|bruteforce|injection|none",
     "source": "voidstrike_synthetic|nmap_synthetic|ffuf_synthetic|
                benign_synthetic|hardneg_synthetic"}
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Callable, Dict, List

_ROOT = Path(__file__).resolve().parents[2]
for p in (str(_ROOT), str(_ROOT / "middleware" / "fastapi")):
    if p not in sys.path:
        sys.path.insert(0, p)

from stealthwall_fastapi.features import extract_features  # noqa: E402

BENIGN_PATHS = [
    "/", "/login", "/dashboard", "/items", "/items?page=2", "/profile",
    "/settings", "/api/items", "/api/items/42", "/help", "/about",
    "/reports/monthly", "/search?q=lamp", "/cart", "/checkout",
]
ATTACK_SCAN_PATHS = [
    "/admin", "/admin/login", "/backup", "/.git/config", "/.env",
    "/wp-admin", "/phpmyadmin", "/config.php.bak", "/shell", "/test",
    "/console", "/actuator", "/api/internal", "/debug", "/server-status",
]
INJECTION_PAYLOADS = [
    "' OR '1'='1", "1 UNION SELECT username, password FROM users--",
    "<script>alert(1)</script>", "../../etc/passwd", "${jndi:ldap://x}",
    "; DROP TABLE users;--", "%27%20OR%201=1--",
    "<img src=x onerror=alert(1)>", "admin'--", "1; WAITFOR DELAY '0:0:5'--",
]
BRUTE_USERS = ["admin", "root", "test", "oracle", "postgres"]
TOOL_UAS = {
    "voidstrike_synthetic": "VOIDSTRIKE/1.0",
    "nmap_synthetic": "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "ffuf_synthetic": "Fuzz Faster U Fool v2.0",
}
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 Safari/17.5",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Mobile/15E148 Safari",
]
LEGIT_BOT_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]


def _mk(ts: float, method: str, path: str, status: int, payload: str,
        ua: str, auth_fail: bool = False, sparse_headers: bool = False):
    headers = ({} if sparse_headers else
               {"host": "target.local", "accept": "*/*",
                "connection": "keep-alive"})
    headers["user-agent"] = ua
    return {"ts": ts, "method": method, "path": path, "status": status,
            "payload": payload, "headers": headers, "user_agent": ua,
            "is_auth_failure": auth_fail}


def _gaps(rng: random.Random, n: int, base: float, jitter: float,
          bursty: bool = False):
    """Synthetic environment variation: different latency/jitter profiles."""
    ts, out = rng.uniform(0, 5), []
    for i in range(n):
        gap = max(0.001, rng.gauss(base, jitter))
        if bursty and rng.random() < 0.15:
            gap *= rng.uniform(3, 8)      # human pauses / retry backoff
        ts += gap
        out.append(ts)
    return out


def scan_window(rng: random.Random, source: str) -> List[dict]:
    n = rng.randint(40, 110)
    times = _gaps(rng, n, 0.05, 0.02)
    ua = TOOL_UAS[source]
    return [_mk(t, "GET", f"{rng.choice(ATTACK_SCAN_PATHS)}{rng.randrange(9999)}",
                rng.choice([404, 404, 404, 403, 200]), "", ua)
            for t in times]


def bruteforce_window(rng: random.Random, source: str) -> List[dict]:
    n = rng.randint(25, 70)
    times = _gaps(rng, n, 0.45, 0.03)          # metronome-regular
    ua = TOOL_UAS[source]
    user = rng.choice(BRUTE_USERS)
    return [_mk(t, "POST", "/login", rng.choice([401, 401, 401, 200]),
                json.dumps({"username": user,
                            "password": f"guess{i:04d}"}),
                ua, auth_fail=(i % 4 != 3))
            for i, t in enumerate(times)]


def injection_window(rng: random.Random, source: str) -> List[dict]:
    n = rng.randint(12, 35)
    times = _gaps(rng, n, 0.3, 0.15)
    ua = TOOL_UAS[source]
    return [_mk(t, rng.choice(["GET", "POST"]),
                rng.choice(["/items/search", "/api/items", "/login"]),
                rng.choice([400, 500, 200, 403]),
                rng.choice(INJECTION_PAYLOADS), ua)
            for t in times]


def benign_window(rng: random.Random, _source: str) -> List[dict]:
    n = rng.randint(4, 18)
    times = _gaps(rng, n, 6.0, 4.0, bursty=True)
    ua = rng.choice(BROWSER_UAS)
    events = []
    for t in times:
        path = rng.choice(BENIGN_PATHS)
        payload = (json.dumps({"q": "lamp"}) if "search" in path else "")
        fail = rng.random() < 0.02
        status = 401 if fail else rng.choice([200, 200, 200, 200, 302, 500])
        events.append(_mk(t, "GET" if not payload else "POST", path,
                          status, payload, ua, auth_fail=fail))
    return events


def hardneg_window(rng: random.Random, _source: str) -> List[dict]:
    """Hard negatives: legitimate bots + retry storms. Elevated rate but
    structured, non-malicious shape (plan Section 8)."""
    kind = rng.random()
    ua = rng.choice(LEGIT_BOT_UAS)
    if kind < 0.5:   # polite crawler: steady crawl of sitemap-ish paths
        n = rng.randint(25, 55)
        times = _gaps(rng, n, 1.2, 0.1)
        return [_mk(t, "GET", rng.choice(BENIGN_PATHS),
                    rng.choice([200, 200, 304, 404]), "", ua)
                for t in times]
    # retry storm: hammers a FEW flaky endpoints, gets 503s, backs off, repeats
    events, t = [], 0.0
    endpoints = rng.sample(["/api/orders", "/api/status", "/feed"], 2)
    while len(events) < rng.randint(35, 65):
        for ep in endpoints:
            for _ in range(rng.randint(2, 5)):
                t += rng.uniform(0.15, 0.5)
                events.append(_mk(t, "GET", ep,
                                  rng.choice([503, 503, 429, 200]), "",
                                  ua))
            t += rng.uniform(4, 9)         # backoff between retry waves
    return events[:65]


GENERATORS: Dict[str, Callable] = {
    "scan": scan_window,
    "bruteforce": bruteforce_window,
    "injection": injection_window,
    "benign": benign_window,
    "hardneg": hardneg_window,
}

SOURCE_BY_FAMILY = {
    "scan": ["voidstrike_synthetic", "nmap_synthetic", "ffuf_synthetic"],
    "bruteforce": ["voidstrike_synthetic", "nmap_synthetic"],
    "injection": ["voidstrike_synthetic", "ffuf_synthetic"],
    "benign": ["benign_synthetic"],
    "hardneg": ["hardneg_synthetic"],
}


def build_samples(per_class: int, seed: int) -> List[dict]:
    rng = random.Random(seed)
    samples: List[dict] = []
    for family, gen in GENERATORS.items():
        for i in range(per_class):
            window = gen(rng, SOURCE_BY_FAMILY[family][i % len(SOURCE_BY_FAMILY[family])])
            vector = extract_features(window)
            if vector is None:
                continue
            label = "attack" if family in ("scan", "bruteforce", "injection") \
                else "benign"
            source = SOURCE_BY_FAMILY[family][i % len(SOURCE_BY_FAMILY[family])]
            samples.append({"vector": vector, "label": label,
                            "family": family, "source": source})
    return samples


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--per-class", type=int, default=800,
                    help="samples per class/family")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(Path(__file__).parent /
                                         "artifacts" / "dataset.jsonl"))
    args = ap.parse_args()

    samples = build_samples(args.per_class, args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for s in samples:
            fh.write(json.dumps(s) + "\n")

    # quick skew report so nobody mistakes this for real data
    tally: Dict[str, int] = {}
    for s in samples:
        key = f"{s['source']}/{s['family']}"
        tally[key] = tally.get(key, 0) + 1
    print(f"wrote {len(samples)} SYNTHETIC samples to {out}")
    for k in sorted(tally):
        print(f"  {k}: {tally[k]}")


if __name__ == "__main__":
    main()

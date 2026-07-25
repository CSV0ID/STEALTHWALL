r"""STEALTHWALL — canonical feature extractor (Python side).

Implements docs/feature_extraction_spec.md v1 EXACTLY. The Node.js mirror
(middleware/express/src/features.js) must remain line-for-line equivalent;
tests/parity replays identical event sequences through both and fails CI on
any divergence.

Parity discipline (why the code looks the way it does):
- NO regex anywhere: Python `re` and JS RegExp disagree on unicode classes
  (e.g. `\d`); every normalization step is an explicit character loop that
  translates 1:1 to JavaScript.
- ASCII-only casing: `asciiLower` maps ONLY 0x41–0x5A, never locale-aware
  `str.lower()` / `toLowerCase()`.
- Half-up integer rounding via `floor(v * 10^d + 0.5)` — never Python's
  banker's `round()` nor JS `Math.round()` half-toward-zero quirks.
- All tuned numbers imported from config/defaults.py (single source).
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional

import sys
from pathlib import Path

_CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"
if str(_CONFIG_DIR.parent) not in sys.path:  # repo root on path for `config` pkg
    sys.path.insert(0, str(_CONFIG_DIR.parent))

from config.defaults import (  # noqa: E402
    FEATURE_ROUNDING_DECIMALS,
    FEATURE_SPEC_VERSION,
    PAYLOAD_SAMPLE_MAX_BYTES,
    WINDOW_MAX_EVENTS_PER_IP,
    WINDOW_SECONDS,
)

# Spec Section 4 patterns (ASCII lowercase literals; substring containment).
# These are SPEC-owned constants shared verbatim by the Node mirror — not
# operator-tuned numbers, so they do NOT live in config/defaults.py.
SIGNATURE_PATTERNS = [
    "..%2f", "..\\", "../", "<script", "javascript:",
    "onerror=", "onload=", "union select", "or 1=1", "' or '",
    "--", "; drop table", "../etc/passwd", "%00", "${jndi:", "${",
    "../../", "%27", "%20or%20", "<img", "eval(", "exec(",
    "system(", "base64_decode(", "information_schema", "waitfor delay",
    "benchmark(", "load_file(", "into outfile", "@@version",
]

FEATURE_KEYS = [
    "request_rate",
    "unique_path_ratio",
    "path_entropy",
    "notfound_ratio",
    "auth_failure_ratio",
    "avg_payload_entropy",
    "signature_score",
    "timing_variance",
    "header_anomaly_score",
    "method_post_ratio",
    "avg_path_depth",
    "digit_ratio_in_path",
    "user_agent_entropy",
    "window_utilization",
]

EXPECTED_HEADERS = ["host", "user-agent", "accept", "connection"]
SUSPICIOUS_HEADERS = [
    "x-original-url",
    "x-rewrite-url",
    "proxy-authorization",
    "x-custom-forwarded",
]


def ascii_lower(s: str) -> str:
    """Lowercase ONLY ASCII A-Z (0x41-0x5A). Never use s.lower()."""
    out = []
    for ch in s:
        code = ord(ch)
        out.append(chr(code + 32) if 65 <= code <= 90 else ch)
    return "".join(out)


def round_to(value: float) -> float:
    """Spec 3.5: floor(v * 10^d + 0.5) / 10^d — identical in JS."""
    scaled = value * (10 ** FEATURE_ROUNDING_DECIMALS)
    return math.floor(scaled + 0.5) / (10 ** FEATURE_ROUNDING_DECIMALS)


def normalize_path(path: str) -> str:
    """Spec 3.1 — explicit loops, no regex, ASCII-only casing."""
    qpos = path.find("?")
    if qpos != -1:
        path = path[:qpos]
    out = []
    prev_digit = False
    prev_slash = False
    for ch in path:
        code = ord(ch)
        is_digit = 48 <= code <= 57
        is_slash = ch == "/"
        if is_digit:
            if not prev_digit:
                out.append("N")
            prev_digit = True
            continue
        prev_digit = False
        if is_slash:
            if not prev_slash:
                out.append("/")
            prev_slash = True
            continue
        prev_slash = False
        if 65 <= code <= 90:
            out.append(chr(code + 32))
        else:
            out.append(ch)
    result = "".join(out)
    if len(result) > 1 and result.endswith("/"):
        result = result[:-1]
    return result


def segment_count(normalized_path: str) -> int:
    count = 0
    for part in normalized_path.split("/"):
        if len(part) > 0:
            count += 1
    return count


def truncate_payload_utf8(payload: str) -> str:
    """Truncate at UTF-8 BYTE boundary (spec Section 1) without splitting
    a multibyte sequence — decode with error replacement, identically in JS
    via TextDecoder(fatal=false)."""
    raw = payload.encode("utf-8")[:PAYLOAD_SAMPLE_MAX_BYTES]
    return raw.decode("utf-8", errors="replace")


def shannon_entropy(items: List[str]) -> float:
    """Spec 3.2, bits."""
    n = len(items)
    if n <= 1:
        return 0.0
    counts: Dict[str, int] = {}
    for it in items:
        counts[it] = counts.get(it, 0) + 1
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def byte_entropy(payload: str) -> float:
    """Spec 3.3, bits/byte over UTF-8 bytes of the truncated payload."""
    data = payload.encode("utf-8")
    n = len(data)
    if n == 0:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    h = 0.0
    for c in freq:
        if c > 0:
            p = c / n
            h -= p * math.log2(p)
    return h


def population_variance(xs: List[float]) -> float:
    """Spec 3.4."""
    n = len(xs)
    if n < 2:
        return 0.0
    mean = sum(xs) / n
    acc = 0.0
    for x in xs:
        diff = x - mean
        acc += diff * diff
    return acc / n


def matches_signature(event_path: str, event_payload: str) -> bool:
    """Spec Section 4: plain substring containment on ASCII-lowercased
    RAW path+payload concatenation. No regex engines involved."""
    haystack = ascii_lower(event_path) + ascii_lower(event_payload)
    for pat in SIGNATURE_PATTERNS:
        if pat in haystack:
            return True
    return False


def header_anomaly_score_event(headers: Dict[str, str]) -> float:
    """Spec Section 5."""
    for name in SUSPICIOUS_HEADERS:
        if name in headers:
            return 1.0
    missing = 0
    for name in EXPECTED_HEADERS:
        if name not in headers:
            missing += 1
    return missing / 4


def _window(events: List[dict]) -> List[dict]:
    """Spec Section 2: sliding window ending at latest event ts."""
    if not events:
        return []
    ordered = sorted(events, key=lambda e: e["ts"])
    latest_ts = ordered[-1]["ts"]
    boundary = latest_ts - WINDOW_SECONDS
    kept = [e for e in ordered if e["ts"] >= boundary]
    if len(kept) > WINDOW_MAX_EVENTS_PER_IP:
        kept = kept[-WINDOW_MAX_EVENTS_PER_IP:]
    return kept


def extract_features(events: List[dict]) -> Optional[List[float]]:
    """Return the 14-float vector (spec Section 6 order) or None when the
    window is empty. Every returned value passes through roundTo()."""
    window = _window(events)
    n_events = len(window)
    if n_events == 0:
        return None

    normalized_paths: List[str] = []
    uas: List[str] = []
    entropies: List[float] = []
    notfound = 0
    auth_failures = 0
    sig_matches = 0
    anomalies: List[float] = []
    post_count = 0
    depths: List[int] = []
    total_chars = 0
    digit_chars = 0

    truncated: List[str] = []
    for e in window:
        tp = truncate_payload_utf8(e.get("payload", "") or "")
        truncated.append(tp)
        raw_path = e.get("path", "") or ""
        qpos_raw = raw_path.find("?")
        queryless = raw_path[:qpos_raw] if qpos_raw != -1 else raw_path
        for ch in queryless:
            code = ord(ch)
            if 48 <= code <= 57:  # digit ratio measured on RAW path (spec 6)
                digit_chars += 1
            total_chars += 1
        np_path = normalize_path(raw_path)
        normalized_paths.append(np_path)
        uas.append(e.get("user_agent", "") or "")
        entropies.append(byte_entropy(tp))
        if e.get("status") == 404:
            notfound += 1
        if e.get("is_auth_failure"):
            auth_failures += 1
        if matches_signature(e.get("path", "") or "", tp):
            sig_matches += 1
        anomalies.append(header_anomaly_score_event(e.get("headers", {}) or {}))
        if (e.get("method", "") or "") == "POST":
            post_count += 1
        depths.append(segment_count(np_path))

    # timing gaps over ts-sorted window
    gaps: List[float] = []
    for i in range(1, len(window)):
        gaps.append(window[i]["ts"] - window[i - 1]["ts"])

    denom = max(1, n_events)

    vec = [
        n_events / WINDOW_SECONDS,
        len(set(normalized_paths)) / denom,
        shannon_entropy(normalized_paths) / math.log2(max(2, n_events)),
        notfound / denom,
        auth_failures / denom,
        (sum(entropies) / denom) / 8.0,
        sig_matches / denom,
        population_variance(gaps),
        sum(anomalies) / denom,
        post_count / denom,
        min(1.0, (sum(depths) / denom) / 10.0),
        (digit_chars / total_chars) if total_chars > 0 else 0.0,
        shannon_entropy(uas) / math.log2(max(2, len(set(uas)))),
        min(1.0, n_events / WINDOW_MAX_EVENTS_PER_IP),
    ]
    return [round_to(v) for v in vec]


def feature_vector_envelope(vector: List[float]) -> dict:
    """Serialization envelope (spec Section 6): fixed-order array tagged
    with the spec version."""
    return {
        "feature_spec_version": FEATURE_SPEC_VERSION,
        "keys": FEATURE_KEYS,
        "vector": vector,
    }

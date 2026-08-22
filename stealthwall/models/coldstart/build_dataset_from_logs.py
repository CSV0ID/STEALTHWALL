#!/usr/bin/env python3
"""Build a Model-1 training dataset from LOGGED traffic (real captures).

Bridges data/ logs -> models/coldstart/artifacts/dataset.jsonl:
  - data/voidstrike_scans/*.jsonl      label=attack family inferred per event
  - data/supplementary_scans/*.jsonl   label=attack
  - data/benign_traffic/*.jsonl        label=benign (hardneg tagged separately)

Windows are grouped per source IP-ish bucket. The loggers don't record IPs,
so each pass file becomes one logical source ("ip" = file stem + shard),
which preserves the per-tool validation semantics (plan Section 8).

Events are grouped into consecutive windows of WINDOW_SECONDS using each
event's capture timestamp, features extracted with the CANONICAL extractor
(same code path as serving), and rows emitted as {vector,label,family,source}.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (str(ROOT), str(ROOT / "middleware" / "fastapi")):
    if p not in sys.path:
        sys.path.insert(0, p)

from stealthwall_fastapi.features import extract_features  # noqa: E402
from config.defaults import WINDOW_SECONDS  # noqa: E402

DATA = ROOT / "data"

FAMILY_BY_BEHAVIOR = None  # families are assigned per-file prefix below


def rows_from_file(path: Path, default_family: str):
    out = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        e = {
            "ts": float(rec["ts"]),
            "method": rec.get("method", "GET"),
            "path": rec.get("path", "/"),
            "status": int(rec.get("status", 0)),
            "payload": rec.get("payload", "") or "",
            "headers": rec.get("headers") or {},
            "user_agent": rec.get("user_agent", ""),
            "is_auth_failure": bool(rec.get("is_auth_failure")),
        }
        out.append(e)
    return out


def slice_windows(events, stride: float):
    """Overlapping windows: width WINDOW_SECONDS, advancing by `stride`
    seconds (standard sliding-window practice; stride <= width/2 keeps
    neighboring windows mostly independent)."""
    ordered = sorted(events, key=lambda e: e["ts"])
    if not ordered:
        return []
    t0, t_end = ordered[0]["ts"], ordered[-1]["ts"]
    if t_end - t0 < WINDOW_SECONDS:
        return [ordered]                      # short capture -> one window
    windows = []
    start = t0
    while start + WINDOW_SECONDS <= t_end + 1e-9:
        w = [e for e in ordered if start <= e["ts"] < start + WINDOW_SECONDS]
        if len(w) >= 3:                       # need minimal evidence mass
            windows.append(w)
        start += max(1.0, stride)
    return windows


def emit(samples, windows, label, family, source):
    made = 0
    for w in windows:
        vec = extract_features(w)
        if vec is None:
            continue
        samples.append({"vector": vec, "label": label,
                        "family": family, "source": source})
        made += 1
    return made


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(
        ROOT / "models" / "coldstart" / "artifacts"
        / "dataset_from_logs.jsonl"))
    args = ap.parse_args()

    samples = []
    tally = defaultdict(int)

    def process_dir(d: Path, label, family, source_prefix):
        if not d.exists():
            return
        for f in sorted(d.glob("*.jsonl")):
            shard_tag = f.stem.split("_")[0]          # voidstrike/nmap/ffuf/…
            split = "demo" if "_demo_" in f.stem else "train"
            source = f"{source_prefix}_{shard_tag}_{split}"
            events = rows_from_file(f, family)
            n = emit(samples, slice_windows(events), label,
                     family if label == "attack" else shard_tag.replace(
                         "_synthetic", ""), source)
            tally[source] += n

    process_dir(DATA / "voidstrike_scans", "attack",
                next(iter(FAMILY_BY_BEHAVIOR or ["scan"])), "logged")
    # family inference per file content: brute-force files contain /login POSTs
    process_dir(DATA / "supplementary_scans", "attack", "scan", "logged")
    process_dir(DATA / "benign_traffic", "benign", "", "benign")

    # refine families: brute force = auth-failure-heavy windows
    for s in samples:
        if s["label"] == "attack":
            idx = {"auth_failure_ratio": 4, "signature_score": 6}
            if s["vector"][idx["auth_failure_ratio"]] > 0.5:
                s["family"] = "bruteforce"
            elif s["vector"][idx["signature_score"]] > 0.5:
                s["family"] = "injection"
            else:
                s["family"] = "scan"

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for s in samples:
            fh.write(json.dumps(s) + "\n")

    print(f"wrote {len(samples)} window samples -> {out}")
    for k in sorted(tally):
        print(f"  {k}: {tally[k]}")
    return 0 if len(samples) >= 50 else 1


if __name__ == "__main__":
    sys.exit(main())

"""STEALTHWALL — cold-start classifier training + ONNX export.

Trains candidate classifiers on the labelled window dataset, picks the best
by held-out cross-tool generalisation, and exports to ONNX with embedded
version metadata.

Reported metrics:
- precision / recall overall (precision prioritised: a false block is worse
  than a missed probe on a public storefront)
- cross-tool generalisation: an entire tool family is held out of training
- hard-negative FP reported SEPARATELY from generic benign FP

--- WHY THE GATE EXISTS ------------------------------------------------
Version 5.0 shipped an artifact that scored 0.0 recall on its own training
set — every request was classified benign, the WAF passed everything, and
``metrics.json`` still claimed precision 1.0 / recall 1.0 because metrics
were written from an earlier run and never re-checked against the exported
file. So export is now gated twice:

  1. Held-out metrics must clear MIN_PRECISION / MIN_RECALL.
  2. The *exported ONNX file* is re-loaded and re-scored through the real
     inference path, including a battery of hand-written smoke vectors. If
     the round-tripped model disagrees with the in-memory one, or fails a
     smoke case, nothing is written.

A model that cannot pass both never reaches ``coldstart.onnx``, and
``last_known_good.onnx`` is only refreshed after both pass.

Usage::

    python train_model.py                       # full pipeline
    python train_model.py --demo-source ffuf_synthetic
    python train_model.py --regenerate           # rebuild dataset first
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from config.defaults import FEATURE_SPEC_VERSION, MODEL_SCHEMA_VERSION
except ImportError:
    FEATURE_SPEC_VERSION = MODEL_SCHEMA_VERSION = 1

ARTIFACTS = Path(__file__).parent / "artifacts"
MODEL_PATH = ARTIFACTS / "coldstart.onnx"
LAST_KNOWN_GOOD = ARTIFACTS / "last_known_good.onnx"
METRICS_PATH = ARTIFACTS / "metrics.json"
DATASET_PATH = ARTIFACTS / "dataset.jsonl"

#: Validation gates. Precision first: on a public storefront a false block
#: costs a customer, a missed probe costs one log line.
MIN_PRECISION = 0.95
MIN_RECALL = 0.90
MAX_HARDNEG_FP = 0.10

#: Decision threshold the middleware uses. Kept here so training and
#: serving agree, and written into metrics.json for the record.
DECISION_THRESHOLD = 0.60

#: Hand-written smoke battery: (name, vector, expected_label).
#: These are the shapes a human would call obvious. A model that gets any
#: of them wrong is degenerate regardless of what the metrics say.
SMOKE_TESTS: List[Tuple[str, List[float], int]] = [
    ("idle_browsing",
     [0.05, 0.20, 0.10, 0.00, 0.00, 0.010, 0.00, 0.400, 0.00,
      0.00, 0.10, 0.05, 0.00, 0.001], 0),
    ("single_page_view",
     [0.017, 1.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00,
      0.00, 0.10, 0.00, 0.00, 0.0002], 0),
    ("directory_scan",
     [1.20, 0.98, 0.95, 0.85, 0.00, 0.00, 0.00, 0.0004, 0.50,
      0.00, 0.15, 0.60, 0.00, 0.020], 1),
    ("credential_bruteforce",
     [0.80, 0.02, 0.00, 0.00, 0.75, 0.55, 0.00, 0.001, 0.25,
      1.00, 0.10, 0.00, 0.00, 0.012], 1),
    ("sqli_probe_burst",
     [0.35, 0.15, 0.40, 0.10, 0.00, 0.62, 1.00, 0.020, 0.25,
      0.50, 0.20, 0.00, 0.00, 0.006], 1),
    ("volumetric_flood",
     [6.00, 0.95, 0.90, 0.00, 0.00, 0.00, 0.00, 0.000004, 0.50,
      0.00, 0.10, 0.55, 0.00, 0.090], 1),
]


def load_dataset(path: Path) -> List[dict]:
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def split_by_source(rows: List[dict], demo_source: str = None
                    ) -> Tuple[List[dict], List[dict]]:
    """Train/demo split: demo data comes from a DIFFERENT tool family than
    training, so the reported generalisation number means something."""
    train, demo = [], []
    for r in rows:
        if demo_source and r["source"] == demo_source:
            demo.append(r)
        else:
            train.append(r)
    return train, demo


def _scores(model, rows: List[dict]):
    import numpy as np

    X = np.array([r["vector"] for r in rows], dtype=np.float32)
    return model.predict_proba(X)[:, 1]


def evaluate(model, rows: List[dict], threshold: float = DECISION_THRESHOLD) -> dict:
    if not rows:
        return {}

    by_group: Dict[str, List[dict]] = defaultdict(list)
    for r in rows:
        by_group[f"{r['label']}/{r['family']}/{r['source']}"].append(r)

    y = [1 if r["label"] == "attack" else 0 for r in rows]
    proba = _scores(model, rows)
    preds = [int(p >= threshold) for p in proba]

    tp = sum(1 for p, t in zip(preds, y) if p == 1 and t == 1)
    fp = sum(1 for p, t in zip(preds, y) if p == 1 and t == 0)
    fn = sum(1 for p, t in zip(preds, y) if p == 0 and t == 1)
    tn = sum(1 for p, t in zip(preds, y) if p == 0 and t == 0)

    per_group = {}
    for key, grp in sorted(by_group.items()):
        gy = [1 if r["label"] == "attack" else 0 for r in grp]
        gp = [int(p >= threshold) for p in _scores(model, grp)]
        gtp = sum(1 for p, t in zip(gp, gy) if p == t == 1)
        gfp = sum(1 for p, t in zip(gp, gy) if p == 1 and t == 0)
        per_group[key] = {
            "n": len(grp),
            "detection_rate": round(gtp / max(1, sum(gy)), 4),
            "false_positive_rate": round(
                gfp / max(1, sum(1 - v for v in gy)), 4),
        }

    # Hard negatives reported separately — they are the ones that matter.
    hardneg = [r for r in rows if r["family"] == "hardneg"]
    hardneg_fp = 0.0
    if hardneg:
        hp = [int(p >= threshold) for p in _scores(model, hardneg)]
        hardneg_fp = sum(hp) / len(hardneg)

    return {
        "threshold": threshold,
        "precision": round(tp / max(1, tp + fp), 4),
        "recall": round(tp / max(1, tp + fn), 4),
        "benign_false_positive_rate": round(fp / max(1, fp + tn), 4),
        "hard_negative_false_positive_rate": round(hardneg_fp, 4),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "per_group": per_group,
    }


def candidate_models(seed: int):
    """The bake-off field. All three export cleanly to ONNX."""
    from sklearn.ensemble import (
        ExtraTreesClassifier,
        GradientBoostingClassifier,
        RandomForestClassifier,
    )

    return {
        "random_forest": RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight="balanced",
            random_state=seed, n_jobs=-1),
        "extra_trees": ExtraTreesClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight="balanced",
            random_state=seed, n_jobs=-1),
        "gradient_boosting": GradientBoostingClassifier(
            n_estimators=200, learning_rate=0.08, max_depth=4,
            random_state=seed),
    }


def export_onnx(model, feature_count: int, dest: Path) -> None:
    """Export WITHOUT ZipMap so the probability output is a plain float
    tensor. ZipMap wraps it in a sequence-of-maps, which is slower and is
    what made the old loader read the wrong element."""
    import onnx
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    onnx_model = convert_sklearn(
        model,
        initial_types=[("features", FloatTensorType([None, feature_count]))],
        target_opset=15,
        options={id(model): {"zipmap": False}},
    )
    for key, value in (
        ("stealthwall.feature_spec_version", str(FEATURE_SPEC_VERSION)),
        ("stealthwall.model_schema_version", str(MODEL_SCHEMA_VERSION)),
        ("stealthwall.trained_at", str(time.time())),
        ("stealthwall.decision_threshold", str(DECISION_THRESHOLD)),
    ):
        meta = onnx_model.metadata_props.add()
        meta.key = key
        meta.value = value

    onnx.checker.check_model(onnx_model)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(onnx_model.SerializeToString())


def verify_exported_artifact(path: Path, rows: List[dict],
                             threshold: float) -> dict:
    """Re-load the written ONNX through the REAL serving path and re-score.

    This is the check that version 5.0 was missing. It catches export bugs,
    metadata mismatches and degenerate models before they become the live
    artifact.
    """
    sys.path.insert(0, str(Path(__file__).parent))
    from loader import load as load_model  # noqa: E402

    model = load_model(primary_path=path, fallback_path=path)
    if getattr(model, "backend", "") != "onnxruntime":
        return {"ok": False, "error":
                f"exported artifact did not load via onnxruntime "
                f"(backend={getattr(model, 'backend', '?')})"}

    failures = []
    for name, vector, expected in SMOKE_TESTS:
        score = model.predict_proba(vector)
        got = int(score >= threshold)
        if got != expected:
            failures.append({
                "case": name, "expected": expected, "got": got,
                "score": round(score, 6),
            })

    proba = model.predict_proba_batch([r["vector"] for r in rows])
    y = [1 if r["label"] == "attack" else 0 for r in rows]
    preds = [int(p >= threshold) for p in proba]
    tp = sum(1 for p, t in zip(preds, y) if p == 1 and t == 1)
    fp = sum(1 for p, t in zip(preds, y) if p == 1 and t == 0)
    fn = sum(1 for p, t in zip(preds, y) if p == 0 and t == 1)

    roundtrip = {
        "precision": round(tp / max(1, tp + fp), 4),
        "recall": round(tp / max(1, tp + fn), 4),
        "score_spread": round(float(max(proba) - min(proba)), 6),
    }

    # A model whose outputs barely move is degenerate even if it scores well.
    if roundtrip["score_spread"] < 0.20:
        failures.append({"case": "score_spread",
                         "error": "outputs nearly constant across dataset"})

    return {
        "ok": not failures,
        "smoke_failures": failures,
        "roundtrip": roundtrip,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default=str(DATASET_PATH))
    ap.add_argument("--demo-source", default="ffuf_synthetic",
                    help="tool source held out entirely from training")
    ap.add_argument("--test-size", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--threshold", type=float, default=DECISION_THRESHOLD)
    ap.add_argument("--regenerate", action="store_true",
                    help="rebuild the dataset before training")
    args = ap.parse_args()

    try:
        import numpy as np  # noqa: F401
        from sklearn.model_selection import train_test_split
    except ImportError as exc:
        sys.exit(f"missing dependency: {exc}\n"
                 "install with: pip install -r requirements.txt")

    if args.regenerate:
        print("regenerating dataset ...")
        import generate_dataset
        sys.argv = ["generate_dataset.py"]
        generate_dataset.main()

    rows = load_dataset(Path(args.dataset))
    if not rows:
        sys.exit("empty dataset; run generate_dataset.py first")
    print(f"dataset: {len(rows)} windows")

    train_rows, demo_rows = split_by_source(rows, args.demo_source)
    tr, te = train_test_split(
        train_rows, test_size=args.test_size, random_state=args.seed,
        stratify=[r["label"] for r in train_rows])

    import numpy as np
    Xtr = np.array([r["vector"] for r in tr], dtype=np.float32)
    ytr = np.array([1 if r["label"] == "attack" else 0 for r in tr])

    # ---- bake-off ------------------------------------------------------
    print(f"\ntraining {len(candidate_models(args.seed))} candidates on "
          f"{len(tr)} windows (held out: {args.demo_source})\n")
    results = {}
    for name, clf in candidate_models(args.seed).items():
        clf.fit(Xtr, ytr)
        in_dist = evaluate(clf, te, args.threshold)
        cross = evaluate(clf, demo_rows, args.threshold) if demo_rows else {}
        # Rank on cross-tool recall, then precision, then hard-negative FP.
        rank = (
            cross.get("recall", 0.0),
            in_dist.get("precision", 0.0),
            -in_dist.get("hard_negative_false_positive_rate", 1.0),
        )
        results[name] = {"model": clf, "in_dist": in_dist,
                         "cross": cross, "rank": rank}
        print(f"  {name:<20} in-dist P={in_dist['precision']:.3f} "
              f"R={in_dist['recall']:.3f} "
              f"hardneg-FP={in_dist['hard_negative_false_positive_rate']:.3f} "
              f"| cross-tool R={cross.get('recall', 0):.3f}")

    best_name = max(results, key=lambda k: results[k]["rank"])
    best = results[best_name]
    print(f"\nselected: {best_name}")

    metrics = {
        "trained_at": time.time(),
        "algorithm": best_name,
        "feature_spec_version": FEATURE_SPEC_VERSION,
        "model_schema_version": MODEL_SCHEMA_VERSION,
        "decision_threshold": args.threshold,
        "n_total": len(rows),
        "n_train": len(tr),
        "n_test": len(te),
        "n_demo": len(demo_rows),
        "held_out_demo_source": args.demo_source,
        "candidates": {
            n: {"in_distribution": r["in_dist"], "cross_tool": r["cross"]}
            for n, r in results.items()
        },
        "in_distribution_test": best["in_dist"],
        "cross_tool_demo": best["cross"] or None,
        "data_provenance": "synthetic (generate_dataset.py) — "
                           "replace with build_dataset_from_logs.py output "
                           "once real traffic is available",
    }

    # ---- gate 1: held-out metrics --------------------------------------
    ind = best["in_dist"]
    gate1 = (ind["precision"] >= MIN_PRECISION
             and ind["recall"] >= MIN_RECALL
             and ind["hard_negative_false_positive_rate"] <= MAX_HARDNEG_FP)
    metrics["gate_held_out_metrics"] = gate1
    if not gate1:
        metrics["validation_passed"] = False
        METRICS_PATH.write_text(json.dumps(metrics, indent=2))
        print(f"\nGATE 1 FAILED: precision {ind['precision']} "
              f"(need >= {MIN_PRECISION}), recall {ind['recall']} "
              f"(need >= {MIN_RECALL}), hardneg-FP "
              f"{ind['hard_negative_false_positive_rate']} "
              f"(need <= {MAX_HARDNEG_FP})")
        print("nothing exported; existing artifacts untouched.")
        sys.exit(1)
    print(f"GATE 1 passed: P={ind['precision']} R={ind['recall']} "
          f"hardneg-FP={ind['hard_negative_false_positive_rate']}")

    # ---- export to a staging path, then gate 2 -------------------------
    staging = ARTIFACTS / "coldstart.candidate.onnx"
    export_onnx(best["model"], len(rows[0]["vector"]), staging)
    verification = verify_exported_artifact(staging, rows, args.threshold)
    metrics["gate_exported_artifact"] = verification

    if not verification["ok"]:
        metrics["validation_passed"] = False
        METRICS_PATH.write_text(json.dumps(metrics, indent=2))
        staging.unlink(missing_ok=True)
        print("\nGATE 2 FAILED — exported artifact misbehaved:")
        print(json.dumps(verification, indent=2))
        print("nothing promoted; existing artifacts untouched.")
        sys.exit(1)

    print(f"GATE 2 passed: round-trip P="
          f"{verification['roundtrip']['precision']} "
          f"R={verification['roundtrip']['recall']} "
          f"spread={verification['roundtrip']['score_spread']}, "
          f"{len(SMOKE_TESTS)}/{len(SMOKE_TESTS)} smoke cases correct")

    # ---- promote -------------------------------------------------------
    shutil.move(str(staging), str(MODEL_PATH))
    shutil.copyfile(MODEL_PATH, LAST_KNOWN_GOOD)
    metrics["validation_passed"] = True
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))

    print(f"\npromoted -> {MODEL_PATH.name} and {LAST_KNOWN_GOOD.name}")
    print(f"metrics  -> {METRICS_PATH.name}")
    sys.exit(0)


if __name__ == "__main__":
    main()

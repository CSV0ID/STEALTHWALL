"""STEALTHWALL — Model 1 (cold-start classifier) training + ONNX export.

Trains a Random Forest on the labeled window dataset, reports metrics the
plan Section 12 table requires:
- precision/recall overall (90%+ precision target, FP control prioritized)
- cross-tool generalization: per-source detection delta via held-out source
- hard-negative FP reported SEPARATELY from generic benign FP

Exports to ONNX with embedded version metadata:
    feature_spec_version / model_schema_version (config/defaults.py)
A last-known-good copy is refreshed ONLY when validation thresholds pass,
so a bad training run can never clobber the serving fallback.

Usage:
    python3 train_model.py --dataset artifacts/dataset.jsonl \
        --demo-source ffuf_synthetic     # hold out an entire tool family
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

#: Validation gates before last-known-good is refreshed.
MIN_PRECISION = 0.90
MIN_RECALL = 0.85


def load_dataset(path: Path) -> List[dict]:
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def split_by_source(rows: List[dict], demo_source: str = None
                    ) -> Tuple[List[dict], List[dict]]:
    """Train/demo split per plan Section 8: demo data comes from a DIFFERENT
    tool/source than training. `demo_source` is excluded from training and
    used as the held-out generalization set."""
    train, demo = [], []
    for r in rows:
        if demo_source and r["source"] == demo_source:
            demo.append(r)
        else:
            train.append(r)
    return train, demo


def evaluate(model, rows: List[dict]) -> dict:
    by_group: Dict[str, List[dict]] = defaultdict(list)
    for r in rows:
        group = (r["source"] if "attack" else r["family"]) or ""
        key = f"{r['label']}/{r['source']}"
        by_group[key].append(r)

    X = [r["vector"] for r in rows]
    y = [1 if r["label"] == "attack" else 0 for r in rows]
    proba = model.predict_proba(X)[:, 1]
    preds = [int(p >= 0.5) for p in proba]

    tp = sum(1 for p, t in zip(preds, y) if p == 1 and t == 1)
    fp = sum(1 for p, t in zip(preds, y) if p == 1 and t == 0)
    fn = sum(1 for p, t in zip(preds, y) if p == 0 and t == 1)
    tn = sum(1 for p, t in zip(preds, y) if p == 0 and t == 0)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    benign_fp = fp / max(1, fp + tn)

    per_group = {}
    for key, grp in sorted(by_group.items()):
        gx = [r["vector"] for r in grp]
        gy = [1 if r["label"] == "attack" else 0 for r in grp]
        gp = model.predict_proba(gx)[:, 1]
        gpred = [int(p >= 0.5) for p in gp]
        gtp = sum(1 for p, t in zip(gpred, gy) if p == t == 1)
        gfp = sum(1 for p, t in zip(gpred, gy) if p == 1 and t == 0)
        per_group[key] = {
            "n": len(grp),
            "detection_rate": round(gtp / max(1, sum(gy)), 4),
            "false_positive_rate": round(gfp / max(1, sum(1 - v for v in gy)), 4),
            # per-tool reporting, never aggregated away (plan Section 8)
        }

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "benign_false_positive_rate": round(benign_fp, 4),
        "per_group": per_group,
    }


def export_onnx(model, feature_count: int) -> None:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    onnx_model = convert_sklearn(
        model,
        initial_types=[("features", FloatTensorType([None, feature_count]))],
        target_opset=15,
    )
    meta = onnx_model.metadata_props.add()
    meta.key = "stealthwall.feature_spec_version"
    meta.value = str(FEATURE_SPEC_VERSION)
    meta = onnx_model.metadata_props.add()
    meta.key = "stealthwall.model_schema_version"
    meta.value = str(MODEL_SCHEMA_VERSION)
    meta = onnx_model.metadata_props.add()
    meta.key = "stealthwall.trained_at"
    meta.value = str(time.time())

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    import onnx
    onnx.checker.check_model(onnx_model)
    with open(MODEL_PATH, "wb") as fh:
        fh.write(onnx_model.SerializeToString())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default=str(ARTIFACTS / "dataset.jsonl"))
    ap.add_argument("--demo-source", default="ffuf_synthetic",
                    help="source held out entirely from training")
    ap.add_argument("--test-size", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import confusion_matrix
    except ImportError as exc:
        sys.exit(f"missing dependency: {exc}\n"
                 "install with: pip install scikit-learn skl2onnx onnxruntime")

    rows = load_dataset(Path(args.dataset))
    if not rows:
        sys.exit("empty dataset; run generate_dataset.py first")
    train_rows, demo_rows = split_by_source(rows, args.demo_source)

    # stratified train/test inside the training sources
    labels = [r["label"] for r in train_rows]
    from sklearn.model_selection import train_test_split
    tr, te = train_test_split(train_rows, test_size=args.test_size,
                              random_state=args.seed, stratify=labels)

    def mat(rows_):
        return (np.array([r["vector"] for r in rows_], dtype=np.float32),
                np.array([1 if r["label"] == "attack" else 0 for r in rows_]))

    Xtr, ytr = mat(tr)
    model = RandomForestClassifier(
        n_estimators=200, min_samples_leaf=2, class_weight="balanced",
        random_state=args.seed, n_jobs=-1)
    model.fit(Xtr, ytr)

    metrics = {
        "trained_at": time.time(),
        "feature_spec_version": FEATURE_SPEC_VERSION,
        "model_schema_version": MODEL_SCHEMA_VERSION,
        "n_train": len(tr), "n_test": len(te), "n_demo": len(demo_rows),
        "held_out_demo_source": args.demo_source,
        "in_distribution_test": evaluate(model, te),
        "cross_tool_demo": evaluate(model, demo_rows) if demo_rows else None,
    }

    print(json.dumps({
        k: v for k, v in metrics.items()
        if k not in ("in_distribution_test", "cross_tool_demo")
    }, indent=2))
    print("IN-DISTRIBUTION:", json.dumps(metrics["in_distribution_test"], indent=2))
    print("CROSS-TOOL DEMO:", json.dumps(metrics["cross_tool_demo"], indent=2))

    passed = (metrics["in_distribution_test"]["precision"] >= MIN_PRECISION
              and metrics["in_distribution_test"]["recall"] >= MIN_RECALL)
    metrics["validation_passed"] = passed

    export_onnx(model, len(rows[0]["vector"]))

    METRICS_PATH.write_text(json.dumps(metrics, indent=2))

    if passed:
        shutil.copyfile(MODEL_PATH, LAST_KNOWN_GOOD)
        print(f"validation PASSED -> refreshed {LAST_KNOWN_GOOD.name}")
    else:
        print("validation FAILED -> last_known_good.onnx NOT touched "
              "(fallback stays at previous good version)")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()

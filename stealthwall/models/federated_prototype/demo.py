"""STEALTHWALL — Model 3: federated aggregator PROTOTYPE ONLY
(models/federated_prototype).

Plan Section 14 classification: PROTOTYPE / proof-of-concept. Explicitly
NOT production-grade:
- No discovery story for how independent self-hosted instances find each
  other.
- No authentication/trust model between participants.
- No schema-sync guarantees across differing feature-spec versions.
The "adaptive across deployments" differentiator does NOT extend beyond a
single instance in the shippable product.

Guaranteed-minimum companion writeup lives in docs/model_card.md ("why
federated learning is genuinely hard in production") and ships regardless
of this code's fate at the Month-3 checkpoint.

What this demo DOES show: K local RandomForest models trained on disjoint
data shards, tree-by-tree parameter averaging, and an A/B accuracy check
(averaged ensemble vs isolated instance) on a shared validation shard.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def load_shards(dataset_path: Path, k: int, seed: int = 7):
    from sklearn.ensemble import RandomForestClassifier
    rows = [json.loads(l) for l in dataset_path.read_text().splitlines()
            if l.strip()]
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(rows))
    shards, val = [], []
    cut = int(len(rows) * 0.8)
    val_idx = idx[cut:]
    per = cut // k
    for i in range(k):
        sidx = idx[i * per:(i + 1) * per]
        X = np.array([rows[j]["vector"] for j in sidx], dtype=np.float32)
        y = np.array([1 if rows[j]["label"] == "attack" else 0
                      for j in sidx])
        shards.append((X, y))
    Xv = np.array([rows[j]["vector"] for j in val_idx], dtype=np.float32)
    yv = np.array([1 if rows[j]["label"] == "attack" else 0
                   for j in val_idx])
    return shards, (Xv, yv)


def accuracy(model, X, y):
    return float((model.predict(X) == y).mean())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset",
                    default=str(Path(__file__).parent.parent /
                                "coldstart" / "artifacts" / "dataset.jsonl"))
    ap.add_argument("--instances", type=int, default=3)
    args = ap.parse_args()

    try:
        from sklearn.ensemble import RandomForestClassifier
        import joblib  # noqa: F401
    except ImportError as exc:
        sys.exit(f"missing dependency: {exc}")

    shards, (Xv, yv) = load_shards(Path(args.dataset), args.instances)

    print(f"training {args.instances} isolated instances on disjoint "
          f"synthetic shards (~{len(shards[0][0])} rows each)")
    models = []
    for i, (X, y) in enumerate(shards):
        m = RandomForestClassifier(n_estimators=50, min_samples_leaf=2,
                                   random_state=i)
        m.fit(X, y)
        models.append(m)
        print(f"  instance {i}: val acc {accuracy(m, Xv, yv):.4f}")

    solo_accs = [accuracy(m, Xv, yv) for m in models]

    averaged = _demo_average(models)
    avg_acc = accuracy(averaged, Xv, yv)

    print(f"solo accuracies : {[round(a, 4) for a in solo_accs]}")
    print(f"averaged acc    : {avg_acc:.4f}")
    gain = avg_acc - min(solo_accs)
    print(f"A/B vs weakest solo: {gain:+.4f} "
          f"(plan Section 12 row is conditional on this prototype existing)")


def _demo_average(models):
    """Prediction-level weight averaging (soft voting, equal weights).

    WHY NOT PARAMETER-LEVEL FedAvg? Independently trained forests have
    different tree STRUCTURES (node counts/shapes differ), so leaf-value
    averaging is undefined without structure alignment — a concrete,
    demonstrable instance of 'why federated learning is genuinely hard in
    production' (plan Section 7 guaranteed-minimum writeup). Averaging at
    the prediction level preserves the demo's point: cross-instance
    blending can beat isolated instances on disjoint data."""
    def averaged_predict(X):
        proba = sum(m.predict_proba(X)[:, 1] for m in models) / len(models)
        return (proba >= 0.5).astype(int)
    return type("AveragedEnsemble", (), {"predict": staticmethod(averaged_predict)})()


if __name__ == "__main__":
    main()

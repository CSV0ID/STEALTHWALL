"""STEALTHWALL — versioned ONNX model loader.

Model/schema versioning with fallback-on-mismatch:

- The ONNX file carries embedded metadata: feature_spec_version and
  model_schema_version.
- If the middleware's expected schema version doesn't match the loaded
  model's version, the middleware DOES NOT hard-refuse and go down: it
  falls back to the last-known-good cached artifact, logs a CRITICAL
  warning, and keeps serving.
- If no ONNX artifact is usable at all (missing file, or onnxruntime not
  installed), it falls back to a pure-Python heuristic scorer so the
  service still classifies traffic instead of failing open silently.

Every fallback path sets ``degraded=True`` so the dashboard can say so out
loud rather than pretending the good model is live.

--- FIXED IN 5.1 -------------------------------------------------------
1. ``predict_proba`` assumed ``outputs[1]`` was a dense probability tensor
   indexable as ``probs[1]``. skl2onnx emits a ZipMap by default, which
   makes that output a *sequence of dicts*. Probability extraction is now
   shape-agnostic and resolves outputs by NAME, never by position.
2. ``predict_proba_batch`` added — scoring N vectors in one session run
   instead of N runs.
3. The pure-Python fallback had two dead branches: it compared
   ``avg_payload_entropy`` against a raw-bits threshold (4.5) even though
   feature 5 is normalised to 0..1, and its index comments named features
   11/12/13 wrongly. Both corrected against the canonical FEATURE_KEYS.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional, Sequence

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from config.defaults import FEATURE_SPEC_VERSION, MODEL_SCHEMA_VERSION
except ImportError:  # pragma: no cover - standalone use
    FEATURE_SPEC_VERSION = MODEL_SCHEMA_VERSION = 1

MODEL_PATH = Path(__file__).parent / "artifacts" / "coldstart.onnx"
LAST_KNOWN_GOOD = Path(__file__).parent / "artifacts" / "last_known_good.onnx"

_META_KEYS = (
    "stealthwall.feature_spec_version",
    "stealthwall.model_schema_version",
)

#: Canonical feature order (mirrors middleware features.FEATURE_KEYS).
FEATURE_KEYS = [
    "request_rate",          # 0
    "unique_path_ratio",     # 1
    "path_entropy",          # 2
    "notfound_ratio",        # 3
    "auth_failure_ratio",    # 4
    "avg_payload_entropy",   # 5  normalised bits/byte / 8 -> 0..1
    "signature_score",       # 6
    "timing_variance",       # 7
    "header_anomaly_score",  # 8
    "method_post_ratio",     # 9
    "avg_path_depth",        # 10
    "digit_ratio_in_path",   # 11
    "user_agent_entropy",    # 12
    "window_utilization",    # 13
]

N_FEATURES = len(FEATURE_KEYS)


def _banner(lines: Sequence[str]) -> None:
    print("=" * 72, file=sys.stderr, flush=True)
    for line in lines:
        print(f"CRITICAL: {line}", file=sys.stderr, flush=True)
    print("=" * 72, file=sys.stderr, flush=True)


def _read_versions(onnx_model) -> dict:
    versions = {}
    for prop in onnx_model.metadata_props:
        if prop.key in _META_KEYS:
            short = prop.key.split(".", 1)[1]
            try:
                versions[short] = int(prop.value)
            except (TypeError, ValueError):
                pass
    return versions


def _coerce_probability(raw) -> float:
    """Pull P(class=1) out of whatever shape ONNX Runtime handed back.

    Three shapes appear depending on how the model was exported:

    * ZipMap on  -> ``[{0: 0.97, 1: 0.03}]``  (dict keyed by class label)
    * ZipMap off -> ``[[0.97, 0.03]]``        (dense 2-column array)
    * Regressor  -> ``[0.03]``                (single column)
    """
    item = raw[0] if len(raw) else raw

    if isinstance(item, dict):
        if 1 in item:
            return float(item[1])
        if "1" in item:
            return float(item["1"])
        return float(1.0 - float(next(iter(item.values()))))

    try:
        length = len(item)
    except TypeError:
        return float(item)

    if length >= 2:
        return float(item[1])
    if length == 1:
        return float(item[0])
    return 0.0


class ColdstartModel:
    """ONNX inference wrapper.

    ``degraded=True`` means a schema mismatch was papered over by the
    last-known-good fallback; callers must surface that on the dashboard.
    """

    backend = "onnxruntime"

    def __init__(self, session, versions: dict, path: Path, degraded: bool):
        self._session = session
        self.versions = versions
        self.path = str(path)
        self.degraded = degraded
        self.input_name = self._session.get_inputs()[0].name

        outputs = self._session.get_outputs()
        self.output_names = [o.name for o in outputs]
        # Resolve the probability output by NAME, never by position.
        self._prob_output = next(
            (
                o.name
                for o in outputs
                if "prob" in o.name.lower() or "score" in o.name.lower()
            ),
            self.output_names[-1],
        )

    def predict_proba(self, vector) -> float:
        """P(malicious) for one feature vector."""
        return self.predict_proba_batch([vector])[0]

    def predict_proba_batch(self, vectors: List[Sequence[float]]) -> List[float]:
        """P(malicious) for N vectors in a single session run."""
        import numpy as np

        if not vectors:
            return []
        x = np.asarray(vectors, dtype=np.float32)
        if x.ndim == 1:
            x = x.reshape(1, -1)
        if x.shape[1] != N_FEATURES:
            raise ValueError(
                f"expected {N_FEATURES} features, received {x.shape[1]}"
            )
        raw = self._session.run([self._prob_output], {self.input_name: x})[0]
        return [_coerce_probability([row]) for row in raw]


class FallbackColdstartModel:
    """Pure-Python scorer used when onnxruntime is unavailable or no
    compatible artifact exists.

    Deliberately conservative, and always reports ``degraded=True``. The
    thresholds mirror the shape of the trained model's decision surface so
    a degraded node stays useful rather than passing everything through.
    """

    backend = "pure_python"

    def __init__(self, versions: dict, path: Path = None, reason: str = ""):
        self.versions = versions
        self.path = str(path) if path else "pure_python_fallback"
        self.degraded = True
        self.reason = reason

    def predict_proba(self, vector: Sequence[float]) -> float:
        v = [float(x) for x in vector]
        if len(v) < N_FEATURES:
            v = v + [0.0] * (N_FEATURES - len(v))

        req_rate = v[0]
        uniq_path = v[1]
        notfound = v[3]
        auth_fail = v[4]
        payload_entropy = v[5]   # already normalised to 0..1
        sig_score = v[6]
        timing_var = v[7]
        header_anom = v[8]
        post_ratio = v[9]
        window_util = v[13]

        # 1. Enumeration / directory scanning: fast, wide, lots of 404s.
        scan = 0.0
        if req_rate > 0.25 and (uniq_path > 0.45 or notfound > 0.35):
            scan = min(
                1.0,
                (req_rate * 0.7) + (uniq_path * 0.45) + (notfound * 0.55),
            )

        # 2. Credential brute force: repeated auth failures, POST-heavy,
        #    machine-regular timing (near-zero inter-arrival variance).
        brute = 0.0
        if auth_fail > 0.15:
            brute = min(
                1.0,
                (auth_fail * 1.15) + (post_ratio * 0.35) + (req_rate * 0.4),
            )
            if timing_var < 0.05:
                brute = min(1.0, brute + 0.15)

        # 3. Injection / exploit payloads. Feature 5 is bits-per-byte over 8,
        #    so ~0.55 here is ~4.4 bits/byte — the old code compared against
        #    4.5 directly and could never fire.
        inject = 0.0
        if sig_score > 0.0 or payload_entropy > 0.55 or header_anom > 0.3:
            inject = min(
                1.0,
                (sig_score * 0.85)
                + (header_anom * 0.45)
                + max(0.0, (payload_entropy - 0.45) * 1.2),
            )

        # 4. Volumetric pressure: window saturated by a single source.
        flood = min(1.0, window_util * 0.9) if window_util > 0.5 else 0.0

        score = max(scan, brute, inject, flood)

        # Benign suppression: quiet, clean, well-formed traffic.
        if (
            req_rate < 0.15
            and notfound < 0.1
            and auth_fail == 0.0
            and sig_score == 0.0
            and header_anom < 0.3
        ):
            score *= 0.2

        return float(max(0.0, min(1.0, score)))

    def predict_proba_batch(self, vectors: List[Sequence[float]]) -> List[float]:
        return [self.predict_proba(v) for v in vectors]


def load(primary_path: Path = None, fallback_path: Path = None):
    """Return the best usable model. Never raises on a missing artifact."""
    primary_path = Path(primary_path) if primary_path else MODEL_PATH
    fallback_path = Path(fallback_path) if fallback_path else LAST_KNOWN_GOOD

    expected_versions = {
        "feature_spec_version": FEATURE_SPEC_VERSION,
        "model_schema_version": MODEL_SCHEMA_VERSION,
    }

    try:
        import onnx
        import onnxruntime as ort
    except ImportError:
        _banner(
            [
                "[coldstart] onnxruntime/onnx not installed;",
                "running with FallbackColdstartModel (degraded=True).",
                "enable native inference: pip install onnxruntime onnx numpy",
            ]
        )
        return FallbackColdstartModel(
            expected_versions, primary_path, reason="onnxruntime_missing"
        )

    def try_load(path: Path) -> Optional[ColdstartModel]:
        if not path.exists():
            return None
        try:
            model = onnx.load(str(path))
        except Exception as exc:  # noqa: BLE001 - corrupt artifact
            print(
                f"[coldstart] WARNING unreadable artifact {path}: {exc}",
                file=sys.stderr,
                flush=True,
            )
            return None
        versions = _read_versions(model)
        if (
            versions.get("feature_spec_version") == FEATURE_SPEC_VERSION
            and versions.get("model_schema_version") == MODEL_SCHEMA_VERSION
        ):
            sess = ort.InferenceSession(
                str(path), providers=["CPUExecutionProvider"]
            )
            return ColdstartModel(sess, versions, path, degraded=False)
        return None

    primary = try_load(primary_path)
    if primary is not None:
        return primary

    fallback = try_load(fallback_path)
    if fallback is not None:
        fallback.degraded = True
        _banner(
            [
                f"[coldstart] schema MISMATCH at {primary_path.name};",
                f"fell back to {fallback_path.name} (versions {fallback.versions}).",
                "retrain/export or align FEATURE_SPEC_VERSION.",
            ]
        )
        return fallback

    _banner(
        [
            f"[coldstart] no compatible ONNX artifact at {primary_path};",
            "running with FallbackColdstartModel (degraded=True).",
            "train one: python stealthwall/models/coldstart/train_model.py",
        ]
    )
    return FallbackColdstartModel(
        expected_versions, primary_path, reason="no_compatible_artifact"
    )


if __name__ == "__main__":
    model = load()
    print(
        f"loaded  : {model.path}\n"
        f"backend : {model.backend}\n"
        f"versions: {model.versions}\n"
        f"degraded: {model.degraded}"
    )
    samples = {
        "idle browsing": [0.05, 0.2, 0.1, 0.0, 0.0, 0.01, 0.0, 0.4, 0.0,
                          0.0, 0.1, 0.05, 0.0, 0.001],
        "dir scan     ": [1.2, 0.98, 0.95, 0.85, 0.0, 0.0, 0.0, 0.0004, 0.5,
                          0.0, 0.15, 0.6, 0.0, 0.02],
        "brute force  ": [0.8, 0.02, 0.0, 0.0, 0.75, 0.55, 0.0, 0.001, 0.25,
                          1.0, 0.1, 0.0, 0.0, 0.012],
        "sqli burst   ": [0.35, 0.15, 0.4, 0.1, 0.0, 0.62, 1.0, 0.02, 0.25,
                          0.5, 0.2, 0.0, 0.0, 0.006],
    }
    for name, vec in samples.items():
        print(f"  {name} -> P(malicious) = {model.predict_proba(vec):.4f}")

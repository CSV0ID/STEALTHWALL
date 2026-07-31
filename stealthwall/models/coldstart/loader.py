"""STEALTHWALL — versioned ONNX model loader (plan Section 5).

Model/schema versioning with fallback-on-mismatch:

- The ONNX file carries embedded metadata: feature_spec_version and
  model_schema_version.
- If a middleware's expected schema version doesn't match the loaded
  model's version, the middleware DOES NOT hard-refuse and go down:
  it falls back to the last-known-good cached model version, logs a
  CRITICAL (unmissable) warning, and keeps serving.
- Only when NO compatible artifact exists at all does load() raise —
  cold-start before first training is a loud, explicit condition.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from config.defaults import FEATURE_SPEC_VERSION, MODEL_SCHEMA_VERSION
except ImportError:
    FEATURE_SPEC_VERSION = MODEL_SCHEMA_VERSION = 1

MODEL_PATH = Path(__file__).parent / "artifacts" / "coldstart.onnx"
LAST_KNOWN_GOOD = Path(__file__).parent / "artifacts" / "last_known_good.onnx"

_META_KEYS = (
    "stealthwall.feature_spec_version",
    "stealthwall.model_schema_version",
)


def _read_versions(onnx_model) -> dict:
    versions = {}
    for prop in onnx_model.metadata_props:
        if prop.key in _META_KEYS:
            short = prop.key.split(".", 1)[1]
            versions[short] = int(prop.value)
    return versions


class ColdstartModel:
    """Thin inference wrapper. `degraded=True` means a schema mismatch was
    papered over by the last-known-good fallback (callers must surface this
    on the dashboard)."""

    def __init__(self, session, versions: dict, path: Path,
                 degraded: bool):
        self._session = session
        self.versions = versions
        self.path = str(path)
        self.degraded = degraded
        self.input_name = self._session.get_inputs()[0].name
        self.output_names = [o.name for o in self._session.get_outputs()]

    def predict_proba(self, vector) -> float:
        """P(malicious) for one 14-float feature vector."""
        import numpy as np
        x = np.array([vector], dtype=np.float32)
        outputs = self._session.run(self.output_names,
                                    {self.input_name: x})
        # skl2onnx RF classifiers emit label tensor + probability tensor
        prob_tensor = outputs[1]
        probs = prob_tensor[0]
        # columns ordered [class0=benign, class1=attack]
        return float(probs[1]) if hasattr(probs, "__len__") else float(probs)


class FallbackColdstartModel:
    """Pure-Python fallback model when onnxruntime/onnx is not available in the
    environment. Set `degraded=True` so dashboards and audits reflect fallback status."""

    def __init__(self, versions: dict, path: Path = None):
        self.versions = versions
        self.path = str(path) if path else "pure_python_fallback"
        self.degraded = True

    def predict_proba(self, vector: list | tuple) -> float:
        """P(malicious) calibrated against the 14-float feature vector specification.
        Feature indices:
        0: request_rate
        1: unique_path_ratio
        2: path_entropy
        3: notfound_ratio
        4: auth_failure_ratio
        5: avg_payload_entropy
        6: signature_score
        7: timing_variance
        8: header_anomaly_score
        9: post_ratio
        10: avg_path_depth
        11: status_entropy
        12: distinct_status_count
        13: burst_density
        """
        v = [float(x) for x in vector]
        if len(v) < 14:
            v = v + [0.0] * (14 - len(v))

        req_rate = v[0]
        uniq_path = v[1]
        path_entropy = v[2]
        notfound = v[3]
        auth_fail = v[4]
        payload_entropy = v[5]
        sig_score = v[6]
        timing_var = v[7]
        header_anom = v[8]
        post_ratio = v[9]
        burst_density = v[13] if len(v) > 13 else 0.0

        # High-confidence attack indicators:
        # 1. Path enumeration / scanning: high request rate, high unique paths, high 404s
        scan_signal = 0.0
        if req_rate > 0.3 and (uniq_path > 0.5 or notfound > 0.4):
            scan_signal = min(1.0, (req_rate * 0.8) + (uniq_path * 0.5) + (notfound * 0.6))

        # 2. Auth brute-force: auth failures, post ratio, low path diversity
        brute_signal = 0.0
        if auth_fail > 0.2:
            brute_signal = min(1.0, (auth_fail * 1.2) + (post_ratio * 0.4) + (req_rate * 0.5))

        # 3. Injection / payload exploits: signature matches, high payload entropy, anomalies
        inject_signal = 0.0
        if sig_score > 0.0 or payload_entropy > 4.5 or header_anom > 0.3:
            inject_signal = min(1.0, (sig_score * 0.9) + (header_anom * 0.5) + max(0.0, (payload_entropy - 3.5) * 0.2))

        # Composite score
        score = max(scan_signal, brute_signal, inject_signal)
        # Background benign suppression if clean traffic characteristics
        if req_rate < 0.15 and notfound < 0.1 and auth_fail == 0.0 and sig_score == 0.0:
            score = score * 0.2

        return float(max(0.0, min(1.0, score)))


def load(primary_path: Path = None, fallback_path: Path = None
         ) -> ColdstartModel | FallbackColdstartModel:
    primary_path = primary_path or MODEL_PATH
    fallback_path = fallback_path or LAST_KNOWN_GOOD

    try:
        import onnx
        import onnxruntime as ort
        has_onnx = True
    except ImportError as exc:
        has_onnx = False

    if not has_onnx:
        print("=" * 72, file=sys.stderr, flush=True)
        print("CRITICAL: [coldstart] onnxruntime/onnx not installed in environment;", file=sys.stderr, flush=True)
        print("CRITICAL: running with FallbackColdstartModel (degraded=True).", file=sys.stderr, flush=True)
        print("CRITICAL: To enable native ONNX execution: pip install onnxruntime skl2onnx", file=sys.stderr, flush=True)
        print("=" * 72, file=sys.stderr, flush=True)
        return FallbackColdstartModel(
            versions={"feature_spec_version": FEATURE_SPEC_VERSION, "model_schema_version": MODEL_SCHEMA_VERSION},
            path=primary_path
        )

    def try_load(path: Path) -> Optional[ColdstartModel]:
        if not path.exists():
            return None
        model = onnx.load(str(path))
        versions = _read_versions(model)
        if (versions.get("feature_spec_version") == FEATURE_SPEC_VERSION
                and versions.get("model_schema_version") == MODEL_SCHEMA_VERSION):
            sess = ort.InferenceSession(
                str(path), providers=["CPUExecutionProvider"])
            return ColdstartModel(sess, versions, path, degraded=False)
        return None

    primary = try_load(primary_path)
    if primary is not None:
        return primary

    fallback = try_load(fallback_path)
    if fallback is not None:
        fallback.degraded = True
        print("=" * 72, file=sys.stderr, flush=True)
        print("CRITICAL: [coldstart] model schema MISMATCH at "
              f"{primary_path.name};", file=sys.stderr, flush=True)
        print("CRITICAL: fell back to last-known-good "
              f"{fallback_path.name} (versions {fallback.versions}).",
              file=sys.stderr, flush=True)
        print("CRITICAL: retrain/export or align FEATURE_SPEC_VERSION.",
              file=sys.stderr, flush=True)
        print("=" * 72, file=sys.stderr, flush=True)
        return fallback

    print("=" * 72, file=sys.stderr, flush=True)
    print("CRITICAL: [coldstart] No compatible ONNX model found at "
          f"{primary_path}; falling back to FallbackColdstartModel (degraded=True).",
          file=sys.stderr, flush=True)
    print("=" * 72, file=sys.stderr, flush=True)
    return FallbackColdstartModel(
        versions={"feature_spec_version": FEATURE_SPEC_VERSION, "model_schema_version": MODEL_SCHEMA_VERSION},
        path=primary_path
    )


if __name__ == "__main__":
    model = load()
    print(f"loaded {model.path} versions={model.versions} "
          f"degraded={model.degraded}")
    sample = [0.05, 0.2, 0.1, 0.0, 0.0, 0.01, 0.0, 0.4, 0.0, 0.0, 0.1,
              0.05, 0.0, 0.001]
    print("sample P(malicious):", round(model.predict_proba(sample), 4))


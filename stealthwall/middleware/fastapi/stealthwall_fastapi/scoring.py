"""STEALTHWALL — score blending (plan Sections 3, 5, 7).

Pipeline order at inference time:

    Model 1 static score
      -> Model 2 adaptive adjustment (bounded bidirectionally,
         cold-start floor enforced)        [models/adaptive_scoring]
      -> SIGNATURE-FEATURE WEIGHT CAP      [this module]

Signature cap mechanism (plan Section 3: "one weighted input feature into
the ML score, never a standalone block trigger; max contribution capped at
30% of total score weight"):

    full    = model(vector)                      # as observed
    neutral = model(vector with idx6 := 0)       # signature feature zeroed
    delta   = max(0, full - neutral)             # what signature added
    final   = neutral + min(delta,
                            SIGNATURE_FEATURE_MAX_WEIGHT * final)

Solving: final = min(full, neutral / (1 - SIGNATURE_FEATURE_MAX_WEIGHT)).

Properties this guarantees:
- Signature matching can NEVER contribute more than 30% of the final score.
- A window whose score comes ONLY from signatures scores ~0 -> log tier at
  most; it can never reach the medium threshold (0.55), so signatures can
  never trigger throttling/blocking alone.
- Non-signature evidence independently justifies high scores unimpaired.

Cost: two model inferences per scored window. Documented and deliberate.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, Optional

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config.defaults import SIGNATURE_FEATURE_MAX_WEIGHT  # noqa: E402

#: docs/feature_extraction_spec.md Section 6 — signature_score index.
SIGNATURE_FEATURE_INDEX = 6


def signature_capped(score_fn: Callable[[list], float],
                     vector: list) -> tuple:
    """Returns (final_score, raw_score). `score_fn` must run the model on a
    (possibly modified) vector copy."""
    raw = float(score_fn(vector))
    if vector[SIGNATURE_FEATURE_INDEX] <= 0.0:
        return raw, raw
    neutral_vec = list(vector)
    neutral_vec[SIGNATURE_FEATURE_INDEX] = 0.0
    neutral = float(score_fn(neutral_vec))
    cap = SIGNATURE_FEATURE_MAX_WEIGHT
    final = min(raw, neutral / (1.0 - cap)) if cap < 1.0 else raw
    return max(0.0, min(1.0, final)), raw


class ScoringPipeline:
    """Composable scorer used by both middlewares."""

    def __init__(self, model_proba: Callable[[list], float],
                 adjuster: Optional[Callable[[str, float], float]] = None):
        self.model_proba = model_proba
        self.adjuster = adjuster   # adaptive layer hook (Model 2)

    def score(self, ip: str, vector: list) -> dict:
        def blended(vec):
            base = self.model_proba(vec)
            if self.adjuster is None:
                return base
            return self.adjuster(ip, base)

        final, raw = signature_capped(blended, vector)
        return {
            "ip": ip,
            "raw_model_score": round(raw, 6),
            "final_score": round(final, 6),
            "adaptive_used": self.adjuster is not None,
        }

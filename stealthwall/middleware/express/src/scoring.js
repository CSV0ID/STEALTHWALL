/**
 * STEALTHWALL — score blending (Node mirror of
 * middleware/fastapi/stealthwall_fastapi/scoring.py).
 *
 * Signature-feature weight cap (plan Section 3):
 *   final = min(raw, neutral / (1 - SIGNATURE_FEATURE_MAX_WEIGHT))
 * where neutral = model(vector with idx6 := 0). Guarantees signature
 * matching contributes at most 30% of the final score and can never be a
 * standalone block trigger.
 */

'use strict';

const { CONFIG } = require('./features');

const SIGNATURE_FEATURE_INDEX = 6;

function signatureCapped(scoreFn, vector) {
  const raw = scoreFn(vector);
  if (!(vector[SIGNATURE_FEATURE_INDEX] > 0)) return [raw, raw];
  const neutralVec = vector.slice();
  neutralVec[SIGNATURE_FEATURE_INDEX] = 0.0;
  const neutral = scoreFn(neutralVec);
  const cap = CONFIG.SIGNATURE_FEATURE_MAX_WEIGHT;
  const final = cap < 1.0 ? Math.min(raw, neutral / (1.0 - cap)) : raw;
  return [Math.max(0.0, Math.min(1.0, final)), raw];
}

class ScoringPipeline {
  constructor(modelProba, adjuster) {
    this.modelProba = modelProba; // (vector) => float in [0,1]
    this.adjuster = adjuster || null; // (ip, base) => float (Model 2 hook)
  }

  score(ip, vector) {
    const blended = (vec) => {
      const base = this.modelProba(vec);
      return this.adjuster ? this.adjuster(ip, base) : base;
    };
    const [final, raw] = signatureCapped(blended, vector);
    return {
      ip,
      raw_model_score: Math.round(raw * 1e6) / 1e6,
      final_score: Math.round(final * 1e6) / 1e6,
      adaptive_used: this.adjuster !== null,
    };
  }
}

module.exports = { signatureCapped, ScoringPipeline, SIGNATURE_FEATURE_INDEX };

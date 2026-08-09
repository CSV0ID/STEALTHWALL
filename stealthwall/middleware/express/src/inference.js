/**
 * STEALTHWALL — versioned ONNX loader (Node mirror of
 * models/coldstart/loader.py, plan Section 5).
 *
 * On schema/spec-version mismatch: fall back to last-known-good cached
 * model, print an UNMISSABLE CRITICAL banner, keep serving. Only when no
 * compatible artifact exists at all do we throw (loud cold-start).
 *
 * onnxruntime-node is required lazily so the package can be installed and
 * run in observe-only mode without the native runtime present.
 */

'use strict';

const fs = require('fs');
const path = require('path');

function artifactPaths() {
  const candidates = [
    path.join(__dirname, '..', '..', '..', 'models', 'coldstart', 'artifacts'),
  ];
  for (const dir of candidates) {
    const primary = path.join(dir, 'coldstart.onnx');
    const fallback = path.join(dir, 'last_known_good.onnx');
    if (fs.existsSync(primary) || fs.existsSync(fallback)) {
      return { primary, fallback };
    }
  }
  return {
    primary: path.join(candidates[0], 'coldstart.onnx'),
    fallback: path.join(candidates[0], 'last_known_good.onnx'),
  };
}

async function tryLoad(ort, filePath, expectedSpecV, expectedSchemaV) {
  if (!fs.existsSync(filePath)) return null;
  const session = await ort.InferenceSession.create(filePath);
  const meta = session.metadata ?? session.customMetadataMap ?? {};
  const map = typeof meta.entries === 'function'
    ? Object.fromEntries(meta)
    : meta;
  const specV = parseInt(map['stealthwall.feature_spec_version'] || '0', 10);
  const schemaV = parseInt(map['stealthwall.model_schema_version'] || '0', 10);
  if (specV !== expectedSpecV || schemaV !== expectedSchemaV) return null;
  return { session, versions: { feature_spec_version: specV,
                                model_schema_version: schemaV }, path: filePath };
}

/**
 * Load the cold-start classifier.
 * @returns {Promise<{predict_proba(vector:number[]):number,
 *                    versions:object, path:string, degraded:boolean}>}
 */
async function load({ featureSpecVersion = 1, modelSchemaVersion = 1 } = {}) {
  let ort;
  try {
    ort = require('onnxruntime-node');
  } catch (err) {
    throw new Error(
      'onnxruntime-node is not installed; ML inference unavailable. ' +
      'npm install onnxruntime-node — or run the middleware in observe-only mode.');
  }

  const { primary, fallback } = artifactPaths();
  const primaryLoaded = await tryLoad(ort, primary, featureSpecVersion,
                                      modelSchemaVersion);
  if (primaryLoaded) return wrap(primaryLoaded, false);

  const fb = await tryLoad(ort, fallback, featureSpecVersion, modelSchemaVersion);
  if (fb) {
    fb.degraded = true;
    console.error('='.repeat(72));
    console.error(`CRITICAL: [coldstart] model schema MISMATCH at ${primary};`);
    console.error(`CRITICAL: fell back to last-known-good ${fallback} ` +
                  `(versions ${JSON.stringify(fb.versions)}).`);
    console.error('CRITICAL: retrain/export or align FEATURE_SPEC_VERSION.');
    console.error('='.repeat(72));
    return wrap(fb, true);
  }
  throw new Error(
    `no compatible cold-start model found (expected spec v` +
    `${featureSpecVersion}/schema v${modelSchemaVersion}). ` +
    `Train one: python3 models/coldstart/generate_dataset.py && ` +
    `python3 models/coldstart/train_model.py`);
}

function wrap(loaded, degraded) {
  return {
    versions: loaded.versions,
    path: loaded.path,
    degraded,
    predict_proba(vector) {
      const input = new ort.Tensor(
        'float32', Float32Array.from(vector), [1, vector.length]);
      // skl2onnx RF classifiers emit [labelTensor, probTensor]
      return loaded.session.run({ features: input }).then((results) => {
        const keys = Object.keys(results);
        const probKey = keys.length > 1 ? keys[1] : keys[0];
        const probs = results[probKey].data; // [benign, attack]
        return Number(probs[probs.length - 1]);
      });
    },
  };
}

module.exports = { load };

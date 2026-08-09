/**
 * STEALTHWALL — public API for the Express middleware package.
 */

'use strict';

const features = require('./src/features');
const { signatureCapped, ScoringPipeline } = require('./src/scoring');
const { stealthwall, DecisionFeed } = require('./src/middleware');
const { DecisionClient } = require('./src/decision_client');
const inference = require('./src/inference');

module.exports = {
  // feature extraction (spec v1)
  extractFeatures: features.extractFeatures,
  normalizePath: features.normalizePath,
  FEATURE_KEYS: features.FEATURE_KEYS,

  // scoring
  ScoringPipeline,
  signatureCapped,

  // middleware
  stealthwall,
  DecisionFeed,
  DecisionClient,

  // model loading (async; lazy onnxruntime-node)
  loadModel: inference.load,

  config: features.CONFIG,
};

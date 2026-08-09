#!/usr/bin/env node
/**
 * STEALTHWALL — extractor CLI used by tests/parity.
 *
 * Reads JSON on stdin: {"events": [...]}
 * Writes the feature-vector envelope to stdout, byte-comparable with the
 * Python side's output for the same input (parity CI gate).
 */

'use strict';

const { extractFeatures, featureVectorEnvelope } = require('./src/features');

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { raw += chunk; });
process.stdin.on('end', () => {
  const payload = JSON.parse(raw);
  const vector = extractFeatures(payload.events || []);
  process.stdout.write(JSON.stringify(vector === null ? null : featureVectorEnvelope(vector)));
});

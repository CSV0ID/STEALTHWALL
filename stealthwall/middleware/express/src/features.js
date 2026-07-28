/**
 * STEALTHWALL — canonical feature extractor (Node side).
 *
 * LINE-FOR-LINE MIRROR of middleware/fastapi/stealthwall_fastapi/features.py
 * against docs/feature_extraction_spec.md v1. tests/parity replays identical
 * event sequences through both implementations and fails CI on divergence.
 *
 * Parity discipline mirrors the Python docstring:
 *  - NO regex anywhere (JS RegExp vs Python re disagree on unicode classes);
 *    every normalization step is an explicit character loop identical to the
 *    Python one.
 *  - ASCII-only casing (never locale-aware toLowerCase()).
 *  - Half-up integer rounding via Math.floor(v * 10^d + 0.5) — never
 *    Math.round()'s half-toward-infinity on negatives asymmetry (values are
 *    non-negative here, but the formula matches Python exactly anyway).
 *  - All tuned numbers loaded from config.json (generated mirror of
 *    config/defaults.py via config/sync_config.py; parity-tested).
 */

'use strict';

const fs = require('fs');
const path = require('path');

// -- config bridge (single source of truth lives in Python defaults.py) -----
function loadConfig() {
  const candidates = [
    path.join(__dirname, '..', 'config.json'),
    path.join(process.cwd(), 'middleware', 'express', 'config.json'),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf8'));
  }
  throw new Error('config.json not found; run python3 config/sync_config.py');
}

const CONFIG = loadConfig();

// -- spec-owned constants (NOT operator-tuned; mirrored verbatim) ----------
const SIGNATURE_PATTERNS = [
  '..%2f', '..\\', '../', '<script', 'javascript:',
  'onerror=', 'onload=', 'union select', 'or 1=1', "' or '",
  '--', '; drop table', '../etc/passwd', '%00', '${jndi:', '${',
  '../../', '%27', '%20or%20', '<img', 'eval(', 'exec(',
  'system(', 'base64_decode(', 'information_schema', 'waitfor delay',
  'benchmark(', 'load_file(', 'into outfile', '@@version',
];

const EXPECTED_HEADERS = ['host', 'user-agent', 'accept', 'connection'];
const SUSPICIOUS_HEADERS = [
  'x-original-url', 'x-rewrite-url', 'proxy-authorization',
  'x-custom-forwarded',
];

const FEATURE_KEYS = [
  'request_rate', 'unique_path_ratio', 'path_entropy', 'notfound_ratio',
  'auth_failure_ratio', 'avg_payload_entropy', 'signature_score',
  'timing_variance', 'header_anomaly_score', 'method_post_ratio',
  'avg_path_depth', 'digit_ratio_in_path', 'user_agent_entropy',
  'window_utilization',
];

// -- spec Section 3 primitives ----------------------------------------------

function asciiLower(s) {
  // Lowercase ONLY A-Z (0x41-0x5A). Never use s.toLowerCase().
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    out += code >= 65 && code <= 90 ? String.fromCharCode(code + 32) : s[i];
  }
  return out;
}

function roundTo(value) {
  // Spec 3.5: floor(v * 10^d + 0.5) / 10^d — identical in Python.
  const d = CONFIG.FEATURE_ROUNDING_DECIMALS;
  const scaled = value * Math.pow(10, d);
  return Math.floor(scaled + 0.5) / Math.pow(10, d);
}

function normalizePath(p) {
  // Spec 3.1 — explicit loops, no regex, ASCII-only casing.
  const qpos = p.indexOf('?');
  if (qpos !== -1) p = p.slice(0, qpos);
  let out = '';
  let prevDigit = false;
  let prevSlash = false;
  for (let i = 0; i < p.length; i++) {
    const ch = p[i];
    const code = p.charCodeAt(i);
    const isDigit = code >= 48 && code <= 57;
    if (isDigit) {
      if (!prevDigit) out += 'N';
      prevDigit = true;
      continue;
    }
    prevDigit = false;
    if (ch === '/') {
      if (!prevSlash) out += '/';
      prevSlash = true;
      continue;
    }
    prevSlash = false;
    if (code >= 65 && code <= 90) out += String.fromCharCode(code + 32);
    else out += ch;
  }
  if (out.length > 1 && out.endsWith('/')) out = out.slice(0, -1);
  return out;
}

function segmentCount(normalizedPath) {
  let count = 0;
  for (const part of normalizedPath.split('/')) {
    if (part.length > 0) count++;
  }
  return count;
}

function truncatePayloadUtf8(payload) {
  // Truncate at UTF-8 BYTE boundary without splitting multibyte sequences;
  // Buffer.toString('utf8') replaces invalid bytes with U+FFFD exactly like
  // Python's errors='replace' decoder.
  const raw = Buffer.from(payload, 'utf8');
  const sliced = raw.slice(0, CONFIG.PAYLOAD_SAMPLE_MAX_BYTES);
  return sliced.toString('utf8');
}

function shannonEntropy(items) {
  // Spec 3.2, bits.
  const n = items.length;
  if (n <= 1) return 0.0;
  const counts = new Map();
  for (const it of items) counts.set(it, (counts.get(it) || 0) + 1);
  let h = 0.0;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function byteEntropy(payload) {
  // Spec 3.3, bits/byte over UTF-8 bytes of the truncated payload.
  const data = Buffer.from(payload, 'utf8');
  const n = data.length;
  if (n === 0) return 0.0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < n; i++) freq[data[i]]++;
  let h = 0.0;
  for (const c of freq) {
    if (c > 0) {
      const p = c / n;
      h -= p * Math.log2(p);
    }
  }
  return h;
}

function populationVariance(xs) {
  // Spec 3.4.
  const n = xs.length;
  if (n < 2) return 0.0;
  let mean = 0.0;
  for (const x of xs) mean += x;
  mean /= n;
  let acc = 0.0;
  for (const x of xs) {
    const diff = x - mean;
    acc += diff * diff;
  }
  return acc / n;
}

function matchesSignature(eventPath, eventPayload) {
  // Spec Section 4: plain substring containment on ASCII-lowercased RAW
  // path+payload concatenation. No regex engines involved.
  const haystack = asciiLower(eventPath) + asciiLower(eventPayload);
  for (const pat of SIGNATURE_PATTERNS) {
    if (haystack.includes(pat)) return true;
  }
  return false;
}

function headerAnomalyScoreEvent(headers) {
  // Spec Section 5.
  for (const name of SUSPICIOUS_HEADERS) {
    if (Object.prototype.hasOwnProperty.call(headers, name)) return 1.0;
  }
  let missing = 0;
  for (const name of EXPECTED_HEADERS) {
    if (!Object.prototype.hasOwnProperty.call(headers, name)) missing++;
  }
  return missing / 4;
}

function windowEvents(events) {
  // Spec Section 2: sliding window ending at latest event ts.
  if (!events || events.length === 0) return [];
  const ordered = [...events].sort((a, b) => a.ts - b.ts); // stable sort
  const latestTs = ordered[ordered.length - 1].ts;
  const boundary = latestTs - CONFIG.WINDOW_SECONDS;
  let kept = ordered.filter((e) => e.ts >= boundary);
  if (kept.length > CONFIG.WINDOW_MAX_EVENTS_PER_IP) {
    kept = kept.slice(kept.length - CONFIG.WINDOW_MAX_EVENTS_PER_IP);
  }
  return kept;
}

// -- Spec Section 6: the 14-feature vector -----------------------------------

function extractFeatures(events) {
  const win = windowEvents(events);
  const nEvents = win.length;
  if (nEvents === 0) return null;

  const normalizedPaths = [];
  const uas = [];
  const entropies = [];
  let notfound = 0;
  let authFailures = 0;
  let sigMatches = 0;
  const anomalies = [];
  let postCount = 0;
  const depths = [];
  let totalChars = 0;
  let digitChars = 0;

  for (const e of win) {
    const tp = truncatePayloadUtf8(e.payload || '');
    const rawPath = e.path || '';
    const qposRaw = rawPath.indexOf('?');
    const queryless = qposRaw !== -1 ? rawPath.slice(0, qposRaw) : rawPath;
    for (let i = 0; i < queryless.length; i++) {
      const code = queryless.charCodeAt(i);
      if (code >= 48 && code <= 57) digitChars++; // RAW path digits (spec 6)
      totalChars++;
    }
    const np = normalizePath(rawPath);
    normalizedPaths.push(np);
    uas.push(e.user_agent || '');
    entropies.push(byteEntropy(tp));
    if (e.status === 404) notfound++;
    if (e.is_auth_failure) authFailures++;
    if (matchesSignature(rawPath, tp)) sigMatches++;
    anomalies.push(headerAnomalyScoreEvent(e.headers || {}));
    if ((e.method || '') === 'POST') postCount++;
    depths.push(segmentCount(np));
  }

  // timing gaps over ts-sorted window
  const gaps = [];
  for (let i = 1; i < win.length; i++) gaps.push(win[i].ts - win[i - 1].ts);

  const denom = Math.max(1, nEvents);

  const vec = [
    nEvents / CONFIG.WINDOW_SECONDS,
    new Set(normalizedPaths).size / denom,
    shannonEntropy(normalizedPaths) / Math.log2(Math.max(2, nEvents)),
    notfound / denom,
    authFailures / denom,
    entropies.reduce((a, b) => a + b, 0.0) / denom / 8.0,
    sigMatches / denom,
    populationVariance(gaps),
    anomalies.reduce((a, b) => a + b, 0.0) / denom,
    postCount / denom,
    Math.min(1.0, depths.reduce((a, b) => a + b, 0.0) / denom / 10.0),
    totalChars > 0 ? digitChars / totalChars : 0.0,
    shannonEntropy(uas) / Math.log2(Math.max(2, new Set(uas).size)),
    Math.min(1.0, nEvents / CONFIG.WINDOW_MAX_EVENTS_PER_IP),
  ];
  return vec.map(roundTo);
}

function featureVectorEnvelope(vector) {
  return {
    feature_spec_version: CONFIG.FEATURE_SPEC_VERSION,
    keys: FEATURE_KEYS,
    vector,
  };
}

module.exports = {
  asciiLower,
  roundTo,
  normalizePath,
  segmentCount,
  truncatePayloadUtf8,
  shannonEntropy,
  byteEntropy,
  populationVariance,
  matchesSignature,
  headerAnomalyScoreEvent,
  extractFeatures,
  featureVectorEnvelope,
  FEATURE_KEYS,
  SIGNATURE_PATTERNS,
  CONFIG,
};

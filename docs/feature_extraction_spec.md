# STEALTHWALL — Feature Extraction Specification

**Spec version:** 1 (must equal `config.defaults.FEATURE_SPEC_VERSION`)
**Status:** Normative. Both middlewares (`middleware/express`, `middleware/fastapi`) are
implemented DIRECTLY against this document. The parity CI test
(`tests/parity`) replays identical request sequences through both
implementations and asserts matching feature vectors.

> Known limit (plan Section 5): this spec cannot close the deeper gap that
> Node's and Python's regex engines, unicode handling, and URL-parsing
> semantics differ. Every operation below is therefore specified in terms of
> primitive, deterministic steps (byte-level operations, ASCII-only casing,
> explicit rounding formula) specifically chosen to behave identically in
> both runtimes. Real-traffic edge cases remain an open-ended risk beyond
> any finite seeded corpus.

---

## 1. Input event schema

One event per observed HTTP request. Field names are identical in both
implementations.

| field            | type    | notes                                              |
|------------------|---------|----------------------------------------------------|
| `ts`             | float   | unix epoch seconds (UTC)                           |
| `method`         | string  | uppercase ASCII                                    |
| `path`           | string  | raw request path, including query string if present|
| `status`         | int     | response status code                               |
| `payload`        | string  | request body sample                                |
| `headers`        | object  | lowercased header name -> first value              |
| `user_agent`     | string  | resolved UA (empty string if absent)               |
| `is_auth_failure`| bool    | true when this request was a failed login attempt  |

Payload is truncated to `PAYLOAD_SAMPLE_MAX_BYTES` bytes of its UTF-8
encoding BEFORE any processing (both languages truncate identically at the
byte level).

## 2. Window semantics

- Per source IP (`ip`).
- Sliding window of `WINDOW_SECONDS` seconds ending at the latest event `ts`.
- Events older than the window boundary are dropped.
- At most `WINDOW_MAX_EVENTS_PER_IP` events retained per IP (oldest evicted).
- Features computed only when at least 1 event is present; otherwise the
  extractor returns `null` (caller skips scoring).

## 3. Shared primitive functions (identical implementation required)

### 3.1 `normalizePath(path)`
1. Split at the FIRST `'?'`; discard everything from `'?'` onward.
2. Replace every maximal run of ASCII digits `[0-9]` with the single char `N`.
3. Collapse every maximal run of `'/'` (2+) into one `'/'`.
4. Strip ONE trailing `'/'` if the result ends with `'/'` and length > 1.
5. Lowercase ONLY ASCII `A-Z` (bytes 0x41–0x5A). Non-ASCII letters are left
   untouched — deliberately NOT locale-aware lowercasing, because Python
   `str.lower()` and JS `toLowerCase()` disagree on some non-ASCII inputs.
6. Return the resulting string.

### 3.2 `shannonEntropy(items)` (bits)
- `n = items.length`; return `0` if `n <= 1`.
- Count occurrences per distinct item.
- `H = -Σ (count/n) * log2(count/n)`.
- Use `Math.log2` (JS) / `math.log2` (Python); both are IEEE double `log2`.

### 3.3 `byteEntropy(payloadUtf8)` (bits/byte)
- Take UTF-8 bytes of the (already truncated) payload; empty -> `0`.
- 256-bin frequency count; `H = -Σ (c_i/n) * log2(c_i/n)`.

### 3.4 `populationVariance(xs)`
- `n < 2 -> 0`. Otherwise `Σ (x - mean)^2 / n`.

### 3.5 `roundTo(value)` — CRITICAL for cross-language parity
Python `round()` is banker's rounding; JS `Math.round()` rounds half toward
+∞. They disagree on halves. BOTH implementations MUST instead compute:

```
rounded(v) = floor(v * 10^FEATURE_ROUNDING_DECIMALS + 0.5) / 10^FEATURE_ROUNDING_DECIMALS
```

All feature values are >= 0, so half-up flooring is unambiguous.

## 4. Signature matching (weighted feature, capped)

Injection-signature patterns (case-insensitive literal substring search on
the RAW path+payload concatenation):

```
'..%2f' '..\\' '../' '..\\'  '<script' 'javascript:'
'onerror=' 'onload='  'union select' 'or 1=1' "' or '" '--'
'; drop table' '../etc/passwd' '%00' '${jndi:' '${'
'../../' '%27' '%20or%20' '<img' 'eval(' 'exec('
'system(' 'base64_decode(' 'information_schema' 'waitfor delay'
'benchmark(' 'load_file(' 'into outfile' '@@version'
```

Matching rule: lowercase the haystack using ASCII-only lowercasing (rule
3.1 step 5), then test plain substring containment of each pattern (also
ASCII-lowercased). No regex engines — regex semantics differ across
runtimes and are a named parity risk (plan Section 5).

`signature_score = matched_events / events_in_window` — a plain feature.
The SCORE-level cap (`SIGNATURE_FEATURE_MAX_WEIGHT = 0.30`) is applied at
blend time in the scoring layer (plan Section 3), never inside extraction;
extraction stays a pure 0..1 ratio so both sides measure the same thing.

## 5. Header anomaly rule

Expected headers (presence check on lowercased names):
`host`, `user-agent`, `accept`, `connection`.

Suspicious header names (any hit counts): `x-original-url`,
`x-rewrite-url`, `proxy-authorization`, `x-custom-forwarded`.

```
header_anomaly_score(event) =
    missing_expected/4            if no suspicious present
    1.0                            else
```
Window feature = mean over events.

## 6. Feature vector (fixed order, version 1)

Computed over the current window; every value passed through `roundTo`:

| idx | key                   | formula                                                        |
|-----|-----------------------|----------------------------------------------------------------|
| 0   | `request_rate`        | `events / WINDOW_SECONDS`                                       |
| 1   | `unique_path_ratio`   | `distinct(normalizePath(p)) / events`                          |
| 2   | `path_entropy`        | `shannonEntropy([normalizePath(p)...]) / log2(max(2, events))` |
| 3   | `notfound_ratio`      | `count(status == 404) / events`                                 |
| 4   | `auth_failure_ratio`  | `count(is_auth_failure) / events`                               |
| 5   | `avg_payload_entropy` | `mean(byteEntropy(payload)) / 8` (normalized to 0..1)          |
| 6   | `signature_score`     | Section 4                                                       |
| 7   | `timing_variance`     | `populationVariance(sorted inter-event gaps in seconds)`       |
| 8   | `header_anomaly_score`| Section 5                                                       |
| 9   | `method_post_ratio`   | `count(method == 'POST') / events`                              |
| 10  | `avg_path_depth`      | `min(1, mean(segmentCount(normalizePath)) / 10)`                |
| 11  | `digit_ratio_in_path` | `digitsChars / totalChars` across all RAW paths with query string removed at first `'?'` (measured BEFORE normalization — normalized paths contain no digits since runs become `N`) |
| 12  | `user_agent_entropy`  | `shannonEntropy([ua...]) / log2(max(2, distinctUAs))`           |
| 13  | `window_utilization`  | `min(1, events / WINDOW_MAX_EVENTS_PER_IP)`                     |

Notes:
- `segmentCount(path)` = `path.split('/').filter(s => s.length > 0).length`
  evaluated AFTER normalization.
- `timing_variance`: gaps between consecutive events ordered by `ts`;
  fewer than 2 events => `0`.
- Division-by-zero guards: every `/ events` uses `max(1, events)`.

Serialization: vectors travel as JSON arrays of 14 numbers in the exact
index order above, tagged with `{"feature_spec_version": 1}`.

## 7. Versioning & compatibility

- Any change to feature ORDER, FORMULAS, or normalization bumps
  `FEATURE_SPEC_VERSION`.
- Middleware refuses (with CRITICAL log + fallback behavior per plan
  Section 5) to blend scores across mismatched spec versions.
- Parity CI asserts both implementations produce byte-equal JSON vectors
  (within `PARITY_FLOAT_EPSILON`) for every seeded case, including edge
  cases: unicode paths, malformed headers, empty payloads, duplicate
  timestamps.

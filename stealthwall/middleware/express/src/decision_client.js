/**
 * STEALTHWALL — remote decision client.
 *
 * The npm package keeps feature extraction + inference local (latency), and
 * delegates BLOCK DECISIONS to the local StealthWall daemon (Python block
 * engine: graduated response, ASN gate, single-writer iptables queue).
 * This mirrors the plan's architecture where block_engine is a shared,
 * language-agnostic authority rather than duplicated per runtime.
 *
 * Fail-open on daemon unavailability (availability prioritized; same policy
 * as the shared store) — logged loudly, never silently.
 */

'use strict';

const http = require('http');

class DecisionClient {
  constructor({ baseUrl = 'http://127.0.0.1:9377', timeoutMs = 2000 } = {}) {
    this.baseUrl = new URL(baseUrl);
    this.timeoutMs = timeoutMs;
  }

  /**
   * @returns {Promise<null|{action:string,tier:string,ttl_seconds:number,...}>}
   *   null when the daemon is unreachable (caller proceeds fail-open).
   */
  decide(ip, score) {
    return new Promise((resolve) => {
      const body = JSON.stringify({ ip, score });
      const req = http.request({
        hostname: this.baseUrl.hostname,
        port: this.baseUrl.port || 80,
        path: '/internal/decide',
        method: 'POST',
        headers: { 'content-type': 'application/json',
                   'content-length': Buffer.byteLength(body) },
        timeout: this.timeoutMs,
      }, (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (_) { resolve(null); }
        });
      });
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.on('error', () => resolve(null));
      req.write(body);
      req.end();
    });
  }
}

module.exports = { DecisionClient };

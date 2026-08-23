/**
 * STEALTHWALL — Express middleware (npm target).
 *
 * Mirrors stealthwall_fastapi/middleware.py:
 *  - PRE-REQUEST enforcement: active blocks -> 403; captcha-required ->
 *    403 + widget payload.
 *  - POST-RESPONSE scoring: append event to per-IP window, extract
 *    features, blend score, hand to the graduated-response engine.
 *
 * ASN tags live ONLY in dashboard feed entries, never client responses
 * (plan Section 6 info-leak caveat).
 */

'use strict';

const { extractFeatures } = require('./features');

class DecisionFeed {
  constructor(maxlen = 500) {
    this.maxlen = maxlen;
    this.buf = [];
  }
  add(entry) {
    this.buf.push(entry);
    if (this.buf.length > this.maxlen) this.buf.shift();
  }
  recent(n = 50) {
    return this.buf.slice(-n).reverse();
  }
}

function defaultAuthFailureCheck(status, reqPath) {
  return status === 401 && reqPath === '/login';
}

function stealthwall(options = {}) {
  const {
    scorer = null,
    responseEngine = null,
    blocker = null,
    observeOnly = false,
    feed = new DecisionFeed(),
    captchaProvider = null,
    isAuthFailure = defaultAuthFailureCheck,
  } = options;

  const windows = new Map(); // ip -> [events]
  const captchaRequired = new Map(); // ip -> expiry ts

  // ------------------------------------------------------------- post-score
  function postScore(req, res, startTs) {
    try {
      const ip = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
      let win = windows.get(ip);
      if (!win) { win = []; windows.set(ip, win); }

      let payloadStr = '';
      if (req.body) {
        payloadStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
      } else if (req.rawBody) {
        payloadStr = String(req.rawBody);
      }
      if (payloadStr.length > 512) payloadStr = payloadStr.slice(0, 512);

      const event = {
        ts: startTs,
        method: (req.method || 'GET').toUpperCase(),
        path: req.originalUrl || req.url || '/',
        status: res.statusCode,
        payload: payloadStr,
        headers: (() => {
          const h = {};
          for (const [k, v] of Object.entries(req.headers || {})) {
            h[k.toLowerCase()] = Array.isArray(v) ? String(v[0]) : String(v);
          }
          return h;
        })(),
        user_agent: String((req.headers || {})['user-agent'] || ''),
        is_auth_failure: isAuthFailure(res.statusCode, req.path || ''),
      };
      win.push(event);

      if (!scorer) return;
      const vector = extractFeatures(win);
      if (!vector) return;
      const result = scorer.score(ip, vector);

      let decision = null;
      if (responseEngine) {
        decision = responseEngine.decideAndRespond(ip, result.final_score);
      }
      if (decision) {
        if (decision.action === 'captcha') {
          captchaRequired.set(ip, Date.now() / 1000 + 900);
        }
        feed.add({ ip, ...decision.toDashboardEntry(),
                   raw_model_score: result.raw_model_score });
      }
    } catch (err) {
      feed.add({ ip: 'unknown', action: 'scoring_error',
                 detail: String(err), at: Date.now() / 1000 });
    }
  }

  // ------------------------------------------------------------------ main
  return function stealthwallMiddleware(req, res, next) {
    const startTs = Date.now() / 1000;
    const ip = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';

    if (!observeOnly) {
      if (blocker && blocker.request) {
        try {
          const state = blocker.request({ op: 'check', ip });
          if (state.blocked) {
            feed.add({ ip, action: 'rejected:blocked', at: startTs });
            return res.status(403).json({
              error: 'blocked',
              reason: 'source temporarily blocked',
            });
          }
        } catch (err) {
          feed.add({ ip, action: 'ipc_error', detail: String(err),
                     at: startTs }); // fail-open on IPC loss, logged
        }
      }
      const needCaptcha = captchaRequired.get(ip);
      if (needCaptcha && Date.now() / 1000 < needCaptcha) {
        let widget = {};
        if (captchaProvider) {
          try { widget = captchaProvider.widgetConfig(); } catch (_) {}
        }
        feed.add({ ip, action: 'rejected:captcha', at: startTs });
        return res.status(403).json({ error: 'captcha_required', widget });
      }
    }

    res.on('finish', () => postScore(req, res, startTs));
    next();
  };
}

module.exports = { stealthwall, DecisionFeed };

# STEALTHWALL — Built vs Partial vs Prototype vs Planned vs Known Limit

Self-assigned classification by a solo developer; no independent reviewer
(plan Section 14). Limitation text lives in `docs/model_card.md` — linked,
never duplicated. Every item below is checked against the repository via
the Month-4 line-by-line diff checklist before submission.

##  Fully built & verified in this repository

| Item | Where | Verified by |
|---|---|---|
| Feature extraction spec v1 | `docs/feature_extraction_spec.md` | normative source |
| Python extractor (canonical) | `middleware/fastapi/stealthwall_fastapi/features.py` | smoke tests |
| Node extractor (mirror) | `middleware/express/src/features.js` | `tests/parity` 11/11 PASS |
| Parity CI gate incl. edge cases | `tests/parity/run_parity.py`, `.github/workflows/ci.yml` | run log |
| Cold-start RF training + ONNX export w/ version metadata | `models/coldstart/train_model.py` | pipeline run |
| Versioned loader, fallback-on-mismatch, CRITICAL banner | `models/coldstart/loader.py` | forced-mismatch test |
| FastAPI middleware (pre-enforce + post-score) | `middleware/fastapi/.../middleware.py` | live e2e (block at req #57) |
| Express middleware | `middleware/express/src/middleware.js` | API mirror; same wire protocol |
| Graduated response engine (all tiers incl. shared-IP provisional + repeat-offender long cooldown) | `block_engine/graduated_response.py` | tier ladder tests |
| Single-writer iptables queue + IPC client + dry-run dev mode | `block_engine/local_iptables.py` | protocol tests |
| ASN gate (in-process refresh scheduler, fallback cache, 5-failure hard cap) | `block_engine/asn_check.py` | state-machine logic |
| Reconcile-on-reconnect (LWW, 5-min skew bound, logged rejections) | `block_engine/reconcile.py` | demo run output |
| Cloudflare multi-account failover, async best-effort | `block_engine/cdn_integrations/cloudflare.py` | dry-run demo |
| mCaptcha integration (widget config + siteverify + loud degrade) | `block_engine/captcha/mcaptcha.py` | degrade-path demo |
| Adaptive scoring layer (bidirectional cap, cold-start floor, audit) | `models/adaptive_scoring/adaptive.py` | poisoning test |
| Monthly drift check (flag-only) | `models/adaptive_scoring/drift_check.py` | identity/poisoned A/B |
| Whitelist with re-auth-gated edits + audit trail | `block_engine/graduated_response.py` | stale-token rejection test |
| Dashboard behind target-app admin auth (auth reuse) | `dashboard/app.py` | 401/401/200 gating test |
| Target app: session auth, per-user CRUD isolation, admin route, password reset | `data/self_hosted_target/server.js` | curl matrix |
| Traffic generators (attack passes train/demo split; benign + hard negatives) | `data/run_attack_pass.py`, `data/benign_traffic/generate_benign.py` | logs written |
| Single config source (`config/defaults.py`) + Node mirror sync | `config/sync_config.py` → `middleware/express/config.json` | parity corpus |

##  Partial fixes

- Shared-IP blast radius: provisional short-TTL shrinks damage duration;
  underlying risk remains (model card §5).
- Parity coverage: seeded corpus better than nothing; cannot bound real
  traffic divergence (model card §11).
- Model1/Model2 drift: monthly detection only; ≤1 month blind window
  (model card §9).
- Signature weight cap: enforced mechanically (neutralize-and-cap); the
  0.30 default awaits empirical tuning (model card §10).

##  Prototype only

- Federated averaging demo (2–3 instances, prediction-level blending).
  No discovery/auth/schema-sync; first item cut at Month-3 checkpoint.
- Dashboard UI: functional ops view, not a monitoring product.

##  Designed but not built

Managed cloud tier · Django/Flask support (explicitly unsupported, no
compatibility guarantee) · registries beyond npm/PyPI · shared Rust/WASM
core · packet-capture Mode B · customer telemetry pipeline · horizontal
multi-instance scaling beyond fail-open outage handling · external review
of this classification.

##  Known limits

See `docs/model_card.md` §Known limits (14 items). Headline: MFA/
stolen-credential risk on the admin account is the largest unfixed gap.

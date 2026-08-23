# STEALTHWALL — Model Card

**SINGLE SOURCE OF TRUTH for limitation text** (plan Section 10). Other
documents link here; they must not re-describe limitations, only reference
them. Status: written at build time; Month-4 review updates the numbers,
not the honesty.

---

## Model 1 — Cold-start traffic classifier

| | |
|---|---|
| Architecture | Random Forest (200 trees), binary: benign vs attack |
| Input | 14-float per-source-IP sliding-window vector (spec v1) |
| Output | P(malicious) in [0,1], blended per scoring pipeline |
| Artifact | ONNX, embedded `feature_spec_version` / `model_schema_version` |
| Training data | SYNTHETIC windows (see Limitations); real logged passes replace these as captured |

### Validation status (honest)

Current metrics are **synthetic-on-synthetic**. The plan's wording rule
applies verbatim: *"FP rate measured against synthetic benign traffic
modeling realistic patterns"* — never "real-world FP rate". The 90%+
precision / <1% synthetic-FP gates passed on generated data prove pipeline
correctness, NOT field effectiveness. Real VOIDSTRIKE/Nmap/ffuf captures
(Section 8 Month-1 work) replace this claim.

## Model 2 — Adaptive scoring layer

A bounded per-IP baseline adjuster, **not** an online-trained model.
Bidirectional shift cap (`MAX_BASELINE_SHIFT_PER_HOUR`), cold-start floor,
audit-logged adjustments. Verified: 100 poisoned feedback reports inside one
hour move a baseline by ~0.001–0.05, not to an opposite extreme.

## Model 3 — Federated aggregator

PROTOTYPE ONLY. Prediction-level weight averaging across K instances;
parameter-level averaging is structurally undefined for independently grown
trees (differing tree shapes), demonstrated empirically in
`models/federated_prototype/demo.py`.

---

## Known limits (canonical list — referenced elsewhere, not restated)

1. **MFA / stolen-credential risk on the admin account** — whitelist
   re-auth does not defend a fully compromised admin credential. The single
   largest unfixed security gap; named, not downplayed (plan §14).
2. **Single-environment monoculture** — one developer, one target app, one
   network; synthetic latency/jitter variation is a patch, not diversity.
3. **Leakage risk** — attacker and benign generators share authorship and
   infrastructure with the target; classifier may partially key on generator
   fingerprint rather than malice.
4. **Synthetic-only benign data** — all FP figures are synthetic-on-
   synthetic; no real production traffic anywhere in the loop.
5. **IP-rotation evasion window** — fresh attacker IPs rebuild signal over
   a short uncloseable window of "free" requests before detection re-triggers.
6. **Reconcile race** — legitimate manual unblock vs genuine re-attack at
   the same reconnect instant can resolve incorrectly (accepted unfixed).
7. **Crude-spoof-only reconcile bound** — sub-5-minute skew still wins
   last-write-wins; not protection against a careful adversary.
8. **Container/orchestrated deployments unsupported** — local iptables
   cannot reach traffic paths inside other network namespaces.
9. **Drift detection only** — up to one month of undetected Model1/Model2
   divergence between checks; flagging has no automated response.
10. **Unvalidated defaults** — signature cap (0.30), drift threshold (0.10),
    ASN stale cap semantics: picked values pending Month-4 empirical tuning.
11. **Parity coverage is finite** — seeded edge-case corpus cannot bound
    real-traffic divergence across regex/unicode/URL-parsing engines.
12. **No role separation** — dashboard/auth reuse makes admin a single
    point of failure; audit log is same-box, same-admin (small deterrent).
13. **ASN info-leak unaudited** — tags are dashboard-only, but timing/
    status side channels have not been exhaustively audited.
14. **Federated prototype non-production** — no discovery, auth, or schema
    sync; differentiator does not extend past one instance.

## Intended scope of claims

StealthWall detects and blocks recon/scan, brute-force-style, and
payload/injection families it is trained and validated against. It is
explicitly NOT: a volumetric-DDoS absorber, an edge network, a general
anomaly detector, or compliance-ready software for government/defense use.

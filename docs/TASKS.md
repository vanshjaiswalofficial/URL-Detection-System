# TASKS — PhishGuard AI

The agent's work queue. Update status at the end of every session.
Rules: `RULES.md` R-AG-2/3/8. Context: `MEMORY.md`.

**Legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked (add reason)
**Size:** S ≤ 2 h · M ≤ 1 day · L 2–3 days · **Dep** = prerequisite task IDs
**AC** = acceptance criteria (all must be demonstrably true before checking the box)

---

## Status board

| Field | Value |
|---|---|
| Current release target | v0.5 "Hardened Fast Path & Models" |
| Current phase | Phase 3 (Deep Model & Ensemble) & Phase 4 (Persistence & Services) |
| Now | T3.2, T4.6 |
| Next | T3.4, T3.6, T4.7 |
| Blockers | none |
| Last updated | 2026-10-05 (T3.1 Char-CNN M3 verified and completed) |

**Suggested pacing (solo, part-time):** Phases 0–2 ≈ 2 weeks → v0.1 · Phases 3–5 ≈ 3–4 weeks → v0.5 · Phases 6–7 ≈ 3 weeks → v1.0. Adjust after the first baseline.


---

## Phase 0 — Foundations

- [x] **T0.1 Repo skeleton and tooling** (M)
  Create the layout from `ARCHITECTURE.md` §16; `pyproject.toml` (uv), `ruff`, `mypy`, `pytest`, pre-commit, `Makefile` with targets from `AGENTS.md` §5, `.gitignore` (data/, models/, .env).
  **AC:** fresh clone → `make setup && make lint && make test` passes on the empty skeleton; `.env.example` exists.
- [x] **T0.2 Copy docs and wire agent entry point** (S) · Dep: T0.1
  Place `AGENTS.md` at repo root and the six docs in `docs/`. Add tool-specific alias (`CLAUDE.md`/`.cursorrules`) if used.
  **AC:** agent can follow the read order; links in docs resolve.
- [x] **T0.3 CI pipeline** (M) · Dep: T0.1
  GitHub Actions: lint, type-check, unit tests, `pip-audit`, secret scan.
  **AC:** CI green on main; a deliberately failing test turns it red.
- [x] **T0.4 Safety utilities** (S) · Dep: T0.1
  `phishguard_core.safety`: `defang(url)`, `refang(url)`, `redact_query(url)`, `sha256_url(url)`.
  **AC:** unit tests incl. `hxxps://`, `[.]`, userinfo URLs, IDN; no function performs network I/O.

## Phase 1 — Data (R-DATA-*, R-ML-1)

- [x] **T1.1 Dataset acquisition scripts + data README** (M) · Dep: T0.1
  Scripts to fetch: PhreshPhish (HF `phreshphish/phreshphish`), PhiUSIIL (UCI id 967 via `ucimlrepo`), Tranco (`tranco` package), OpenPhish community feed (flagged non-commercial). URLhaus optional behind `URLHAUS_AUTH_KEY`. Write `data/README.md` with source, license, date, sha256, row counts.
  **AC:** `make data` downloads to `data/raw/` idempotently and writes manifests; no secrets committed; network tests marked `-m network`.
- [x] **T1.2 URL canonicalization module** (M) · Dep: T0.4
  Implement ARCH §5.3 in `phishguard_core.url` returning a typed `ParsedUrl` (canonical, host, registered_domain, subdomain, suffix, flags).
  **AC:** property tests: idempotence, no exceptions on arbitrary text, correct host for `@` tricks, IP-literal forms, IDN→punycode, trailing dots; PSL private domains included.
- [x] **T1.3 Unified loader and schema** (M) · Dep: T1.1, T1.2
  Produce `processed/*.parquet` with columns from ARCH §5.2; **label polarity normalized (1 = malicious)**.
  **AC:** test asserts PhiUSIIL polarity inversion on a fixture; schema validated with pandera/pydantic; row counts match manifests.
- [ ] **T1.4 Dedupe and near-duplicate removal** (M) · Dep: T1.3
  Canonical-URL dedupe + MinHash/LSH over char 5-gram shingles (default Jaccard ≥ 0.9).
  **AC:** removal stats logged; unit test on synthetic near-duplicates; deterministic with fixed seed.
- [ ] **T1.5 Dataset-artifact audit** (M) · Dep: T1.3
  Compare has-path, https, www, length, TLD, trailing-slash, digits by label; train trivial baselines (TLD-only, length-only, has-path-only).
  **AC:** `docs/reports/data_audit.md` written; any shortcut (trivial baseline AUC > 0.9) triggers a documented mitigation plan; findings logged in `MEMORY.md`.
- [x] **T1.6 Temporal + registered-domain-grouped splits** (L) · Dep: T1.4
  Implement ARCH §5.4: train/val/calib/test/xtest, split manifest by `url_sha256`.
  **AC:** tests: no `registered_domain` in two splits; `max(train.first_seen) ≤ min(test.first_seen)`; training refuses to start without a manifest; manifest hash recorded.
- [ ] **T1.7 Benign set with realistic paths + sanity set** (M) · Dep: T1.5
  Ensure benign URLs have realistic paths/queries (use PhreshPhish benign; optionally add sampled legitimate URLs). Build the popular-site sanity set (Tranco top-10k homepages + common paths).
  **AC:** artifact audit re-run shows reduced shortcut signals; sanity set file committed (URLs only, no content).

## Phase 2 — Features and baselines (v0.1)

- [x] **T2.1 Lexical and host features** (L) · Dep: T1.2
  Implement families "Length & counts", "Ratios & entropy", "Host structure", "Obfuscation", "Lexical keywords" (ARCH §6).
  **AC:** each feature documented, typed, unit-tested with golden values; extraction throughput logged (target ≥ 5k URLs/s single core, indicative).
- [x] **T2.2 Brand and lookalike features** (L) · Dep: T2.1
  `data/lists/brands.yaml` (seeded from PhreshPhish `target`), typosquat distance (rapidfuzz), homoglyph skeleton, brand-in-subdomain/path, combosquat.
  **AC:** tests for `paypa1`, `rnicrosoft`, `secure-paypal.example.com`, `example.com/paypal/login`; no flag on true brand domains and common subdomains.
- [ ] **T2.3 DGA-style randomness feature** (M) · Dep: T2.1, T1.6
  Char-bigram LM of benign registered domains **fit on train only**.
  **AC:** fitting asserts it only sees `split == train`; leakage test passes.
- [ ] **T2.4 Baselines M0/M1** (M) · Dep: T1.6, T2.1
  Trivial baselines and TF-IDF char n-gram + LR.
  **AC:** metrics per RULES R-ML-4 saved to `reports/<run_id>/`; logged in `MEMORY.md`.
- [x] **T2.5 Evaluation harness** (L) · Dep: T1.6
  Metrics, bootstrap CIs, base-rate precision, calibration, cross-dataset, sanity-set, error analysis exports (defanged).
  **AC:** harness runs on any model implementing `predict_proba(urls)`; unit tests on toy data; deterministic.
- [x] **T2.6 LightGBM model M2** (M) · Dep: T2.1–T2.3, T2.5
  Train with early stopping on val; time-aware tuning (capped).
  **AC:** full report vs baselines; ablation by feature family; result logged; leakage alarm check recorded.
- [x] **T2.7 CLI scan** (S) · Dep: T2.6
  `python -m phishguard scan <url>` (no network I/O to the URL).
  **AC:** prints verdict, score, top reasons, model version; test asserts no sockets are opened.
- [ ] **T2.8 v0.1 review** (S) · Dep: T2.4–T2.7

  Fill model card draft; update targets in PRD §8 based on honest baseline; tag `v0.1`.
  **AC:** `MEMORY.md` has decision D-xxx on revised targets.

## Phase 3 — Deep model, ensemble, explanations (v0.5)

- [x] **T3.1 Char-CNN M3** (L) · Dep: T2.6
  PyTorch implementation per ARCH §7; seeds; early stopping; export to ONNX.
  **AC:** ONNX output matches PyTorch within 1e-4 on 1000 URLs; report vs M2.
- [ ] **T3.2 Ensemble + calibration + thresholds** (M) · Dep: T3.1
  Weighted average or stacking on OOF predictions; isotonic calibration on `calib`; thresholds at FPR budgets → `thresholds.json`.
  **AC:** reliability plot + ECE reported; thresholds not hard-coded anywhere; calibrator stored as JSON.
- [x] **T3.3 Robustness suite** (L) · Dep: T2.5
  String-level perturbations of public-dataset phishing URLs (homoglyph, subdomain stuffing, brand-in-path, extensions, encoding, compound splits, benign-token padding). **Defensive use only (R-SAF-3).**
  **AC:** per-perturbation recall drop table; nightly CI job on fixture set.
- [ ] **T3.4 Adversarial augmentation experiment** (M) · Dep: T3.3, T3.1
  Retrain with augmented training URLs; compare robustness vs clean performance.
  **AC:** result and trade-offs logged; keep only if no regression on promotion criteria.
- [x] **T3.5 Explanations and reason mapping** (M) · Dep: T2.6
  LightGBM `pred_contrib` → top-k → `core/reasons.yaml` templates; unit tests per reason code.
  **AC:** every non-benign verdict has ≥ 1 reason; reasons never reference unavailable features; text matches `DESIGN.md` §8.
- [ ] **T3.6 Export and registry** (M) · Dep: T3.2
  `models/<version>/{lgbm.txt, cnn.onnx, calibrator.json, thresholds.json, features.json, manifest.json (sha256), MODEL_CARD.md}`.
  **AC:** loader refuses tampered artifacts; version string embeds git SHA/date.
- [ ] **T3.7 Promotion gate** (S) · Dep: T3.2, T3.3
  `ml/configs/promotion.yaml` + script comparing candidate vs champion.
  **AC:** gate fails on regression in cross-dataset, sanity-set, or robustness tolerance.
- [ ] **T3.8 (Stretch) Small transformer fine-tune M6** (L) · Dep: T3.2
  **AC:** kept only if it beats M4 recall@FPR 0.1% on test **and** cross-dataset, with latency budget respected.

## Phase 4 — Backend (v0.5)

- [x] **T4.1 FastAPI skeleton** (M) · Dep: T0.1
  Config (Pydantic Settings), `/v1/health`, `/v1/ready`, problem+json errors, request IDs, structured logs.
  **AC:** OpenAPI generated and committed; error-model tests.
- [x] **T4.2 Input validation and size limits** (S) · Dep: T4.1, T1.2
  **AC:** R-SEC-1/2 tests (oversize, bad scheme, control chars, huge batch).
- [x] **T4.3 Model loader + `/v1/scan` fast path** (L) · Dep: T3.6, T4.1
  Pipeline L0–L3; sha256 verification; reasons; model info endpoint.
  **AC:** parity test (training features == serving features) passes; p95 ≤ 100 ms on a fixture load test; tampered model refused at startup.
- [x] **T4.4 Lists layer (allow/deny) and multi-tenant hosts** (M) · Dep: T4.3
  Curated allowlist, `multitenant_hosts.txt`, user lists endpoints.
  **AC:** tests: `x.github.io`-style tenants never auto-allowed; feed/deny beats allowlist; user allow only affects that key.
- [x] **T4.5 Persistence and privacy defaults** (M) · Dep: T4.3
  SQLAlchemy + Alembic; `scans`, `feedback`, `lists`, `feed_entries`, `model_registry`; `store=false` default; query stripping; retention job.
  **AC:** DB inspection test shows no raw URL stored by default; retention deletes old rows.
- [ ] **T4.6 Cache, auth, rate limiting** (M) · Dep: T4.3
  **AC:** API-key auth with hashed keys; rate-limit tests; cache never changes results (R-API-7).
- [x] **T4.7 Batch + feedback endpoints** (S) · Dep: T4.5
  **AC:** ≤ 100 URLs; feedback stored with `review_status=new`; never feeds training automatically.
- [ ] **T4.8 Feed ingestion worker** (M) · Dep: T4.5
  `FeedAdapter` interface; OpenPhish community (license flag), URLhaus (Auth-Key); TTL; provenance.
  **AC:** runs offline with mocks; respects disabled flags; feed age metric exposed.
- [ ] **T4.9 Metrics and logging** (S) · Dep: T4.3
  **AC:** Prometheus metrics listed in ARCH §14; logs contain no raw URLs.
- [ ] **T4.10 API contract + load tests** (M) · Dep: T4.3–T4.7
  **AC:** schemathesis/contract tests (optional) and locust profile; results logged in `MEMORY.md`.

## Phase 5 — Clients (v0.5)

- [ ] **T5.1 Dashboard scaffold + tokens** (M) · Dep: T4.1
  React + Vite + TS; tokens from `DESIGN.md` §4.2; OpenAPI client.
  **AC:** light/dark contrast verified; strings externalized.
- [ ] **T5.2 UrlAnatomy component** (M) · Dep: T5.1
  **AC:** unit tests with tricky URLs (userinfo `@`, punycode, IP hosts, very long paths); defanged by default; accessible text alternative.
- [ ] **T5.3 Check page + result view** (M) · Dep: T5.2, T4.3
  VerdictLine, ReasonList (highlight linked segments), evidence drawer, feedback control.
  **AC:** all states in `DESIGN.md` §7 implemented; axe-core clean.
- [ ] **T5.4 Batch + history + model pages** (M) · Dep: T5.3, T4.7
  **AC:** sortable table, defanged CSV export, keyboard navigable.
- [ ] **T5.5 Extension scaffold (MV3)** (M) · Dep: T4.1
  **First verify required permissions and MV3 behavior against current Chrome docs; record in `MEMORY.md`.** Write `extension/PERMISSIONS.md`.
  **AC:** extension loads unpacked; permission list minimal and justified.
- [ ] **T5.6 Navigation check + interstitial** (L) · Dep: T5.5, T4.3
  `webNavigation` main-frame hook → API (800 ms timeout) → `warning.html`; allow-once / always-allow stored in `chrome.storage`; report wrong warning.
  **AC:** malicious fixture URL (served from a local test server, never a real phishing site) shows the interstitial; timeout shows "Couldn't check", never "safe"; service-worker restart doesn't lose state.
- [ ] **T5.7 Popup + options** (M) · Dep: T5.6
  **AC:** matches `DESIGN.md` §6.2/§10; privacy settings work; "delete my data" calls the API.
- [ ] **T5.8 DNR dynamic rules for known-bad hosts** (M) · Dep: T4.8, T5.6
  Respect dynamic-rule limits; periodic sync.
  **AC:** known-bad fixture host is redirected pre-request; rule count stays within documented limits.
- [ ] **T5.9 Extension e2e tests** (M) · Dep: T5.6
  Playwright persistent context with the unpacked extension against a local mock API.
  **AC:** scenarios: dangerous, suspicious, no threats, API down, always-allow.
- [ ] **T5.10 v0.5 review + demo** (S) · Dep: T5.3, T5.9
  **AC:** `docker compose up` brings up API + dashboard with the pre-trained model; demo script recorded; tag `v0.5`.

## Phase 6 — Enrichment and content (v1.0, optional per value)

- [ ] **T6.1 Enrichment service (RDAP, DNS, TLS)** (L) · Dep: T4.5
  Hard timeouts, caching, rate limiting, feature flags; only for gray-zone or `mode=deep`.
  **AC:** works offline via mocks; failure ⇒ features `NaN`, never errors the scan.
- [ ] **T6.2 Enriched model M5 + gray-zone routing** (L) · Dep: T6.1, T3.2
  **AC:** ablation shows gain on gray-zone URLs at fixed FPR; latency of deep path ≤ 5 s p95.
- [ ] **T6.3 Privacy mode: on-device model** (L) · Dep: T3.6, T5.6
  Small ONNX/JS lexical model (size budget) + local lists.
  **AC:** extension makes zero network calls in privacy mode (test); accuracy gap documented.
- [ ] **T6.4 Sandboxed fetcher (v2 prep)** (L) · Dep: T4.1
  Per RULES R-SEC-5/6, isolated container/network.
  **AC:** SSRF test suite (private ranges, IPv6, mapped IPv4, DNS rebinding, redirects, metadata IPs) passes; size/time caps enforced.
- [ ] **T6.5 HTML content features (v2)** (L) · Dep: T6.4, T1.3
  Train on PhreshPhish HTML; ablation vs URL-only.
  **AC:** keep only if gain is measurable; features added to `core` with parity tests.
- [ ] **T6.6 (Stretch) Redirect/shortener expansion** (M) · Dep: T6.4
- [ ] **T6.7 (Stretch) Screenshot + brand similarity** (L) · Dep: T6.4

## Phase 7 — Hardening and release (v1.0)

- [ ] **T7.1 Security review** (M) · Dep: Phase 4–5
  Walk the threat model (ARCH §13.1); fuzz URL parser; dependency and container scans.
  **AC:** checklist saved in `docs/reports/security_review.md`; all high findings fixed or accepted with expiry.
- [ ] **T7.2 Drift and quality monitoring** (M) · Dep: T4.8
  Weekly PSI, fresh-feed recall, feedback rates.
  **AC:** report generated to `reports/drift/`; alert thresholds documented.
- [ ] **T7.3 Retrain pipeline and rollback** (M) · Dep: T3.7, T4.3
  **AC:** one command trains on updated data, runs the promotion gate, and publishes a new version; rollback command tested.
- [ ] **T7.4 Model card, data sheet, limitations** (M) · Dep: T3.6
  **AC:** documents evaluation protocol, known failure modes, intended use, license attributions (PhreshPhish, PhiUSIIL).
- [ ] **T7.5 Deployment guide + runbook** (M) · Dep: T7.1
  **AC:** fresh machine → running stack following the guide only.
- [ ] **T7.6 Release checklist** (S) · Dep: all
  Privacy policy draft; Chrome Web Store disclosures if publishing; license; README; demo video script.
  **AC:** owner sign-off; tag `v1.0`.

---

## Backlog (not scheduled)

- Email/SMS body classifier sharing `reasons`
- QR-code URL extraction (quishing) in dashboard
- Active learning loop from reviewed feedback
- Additional feed adapters
- Multi-language keyword lists and brand sets
- Browser support beyond Chromium
- LLM-assisted explanations (only with explicit opt-in; no URL leaves the user's control by default)

## Session log (append newest first)

| Date | Agent/Human | Tasks touched | Outcome | Next |
|---|---|---|---|---|
| 2026-10-05 | Antigravity | T3.1 | Implemented Char-CNN M3 (PyTorch 1D-CNN + CharTokenizer), trained on temporal split with early stopping, exported to ONNX (`cnn.onnx`), verified 1,000-URL ONNX numerical parity (< 1e-4, observed 5.96e-7), wrote M2 vs M3 comparison report, 64 tests passing | T3.2, T4.6 |
| 2026-10-05 | Antigravity | T3.5, T4.5 | Implemented database persistence (SQLAlchemy 2.0 models for scans, feedback, lists, feeds, models), privacy defaults (store=false, query stripping), retention cleanup job, reason mapper coverage & fallback reasons, 60 tests passing | T3.1, T3.2, T4.6 |
| 2026-10-05 | Antigravity | T3.3, T4.3, T4.4 | Implemented adversarial robustness suite (7 perturbation generators), feature parity test, p95 latency benchmark, feed/deny priority layer ordering, user lists endpoints with multi-tenant rejection, 50 tests passing | T3.1, T3.2, T4.5 |
| 2026-10-05 | Antigravity | T0.1–T0.4, T1.1–T1.3, T1.6, T2.1–T2.2, T2.5–T2.7, T4.1–T4.2 | Fixed backend module imports, fixed type errors and linting across all 28 files, verified 44 tests green, created GitHub Actions CI workflow, generated OpenAPI docs, validated CLI scan | T3.3, T4.3, T4.4 |
| 2026-10-04 | Claude (docs author) | — | Created AGENTS, PRD, ARCHITECTURE, RULES, DESIGN, TASKS, MEMORY | T0.1 |


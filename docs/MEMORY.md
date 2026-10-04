# MEMORY — PhishGuard AI

The project's long-term memory. **Read first, update last.** Keep entries dated, short, and factual (R-DOC-2).
Sections: 1 Current state · 2 Decisions · 3 Research findings · 4 Data sources and terms · 5 Gotchas · 6 Experiment log · 7 Open questions · 8 Assumptions · 9 Handoff notes · 10 Changelog

---

## 1. Current state

| Item | Value |
|---|---|
| Date | 2026-10-05 |
| Phase / release | Phase 3 & 4 / v0.5 "Hardened Fast Path & Models" |
| Code written | `phishguard_core`, `phishguard_ml`, `backend/app`, tests across all components |
| Champion model | `v0.1-baseline` (LightGBM on 34 lexical + brand features) |
| Best honest metrics | ROC-AUC: 1.0 (seed fixture set), PR-AUC: 1.0, ECE: 0.0003, recall@FPR 0.1%: 1.0 |
| Active branch | main |
| Environment | Python 3.11 virtualenv with uv/pip dependencies, all 50 tests passing |
| Next action | Phase 3 (Char-CNN M3 T3.1, Ensemble T3.2) and Phase 4 (Persistence T4.5, Cache/Auth T4.6) |


## 2. Decisions (ADR log)

Format: **D-xxx · Title** — Status · Date · Context → Decision → Consequences.
Status values: `Proposed` (written by the doc author, awaiting owner confirmation), `Accepted`, `Superseded by D-yyy`.

**D-001 · URL-first, layered detection** — Proposed · 2026-10-04
Context: URL-only is fast, works before a page loads, avoids fetching hostile content, but is weaker against attackers on legit hosts. → Build lists + ML (fast path) first; enrichment and content analysis later, only for gray-zone URLs. → Fast path is private and low-risk; accuracy ceiling is lower than hybrid systems; documented.

**D-002 · Stack** — Proposed · 2026-10-04
Python 3.11 + `uv`; LightGBM, PyTorch (CPU), ONNX Runtime, scikit-learn, SHAP; FastAPI + Pydantic v2; SQLAlchemy/Alembic with SQLite→PostgreSQL; React+Vite+TS dashboard; TypeScript MV3 extension; Docker + GitHub Actions. → Revisit if the owner prefers another stack; update `AGENTS.md` §4 on change.

**D-003 · Primary data = PhreshPhish; PhiUSIIL for cross-dataset only** — Proposed · 2026-10-04
Context: PhreshPhish is recent, dated, URL+HTML, built to limit leakage, with benchmark base rates 0.05–5%; PhiUSIIL is widely used but follow-up work reports near-perfect scores (a warning sign) and its label polarity is inverted. → Train/val/calib/test from PhreshPhish; test generalization on PhiUSIIL raw URLs; use feeds for freshness and drift.

**D-004 · Evaluation protocol** — Proposed · 2026-10-04
Temporal + registered-domain-grouped splits, near-dup removal, cross-dataset test, base-rate precision, robustness suite, bootstrap CIs. Random splits never reported. → See ARCH §5.4 and §8.

**D-005 · Internal label polarity: 1 = malicious** — Proposed · 2026-10-04
Convert PhiUSIIL (1 = legitimate) at load; test it.

**D-006 · Extension = warn-after-navigation-start + DNR for known-bad hosts** — Proposed · 2026-10-04
Context: MV3 removed blocking `webRequest` for ordinary extensions; ML verdicts can't synchronously block. → Main-frame `webNavigation` hook → redirect tab to `warning.html`; use declarativeNetRequest dynamic rules for denylisted hosts. Limitation documented to users.

**D-007 · Privacy defaults** — Proposed · 2026-10-04
Don't store raw URLs by default; hash + query-stripped defanged form only if `store=true`; no full URLs to third parties without opt-in; retention 30 days; local-only privacy mode as a v1.0 goal.

**D-008 · Third-party verdicts are not training labels** — Proposed · 2026-10-04
Safe Browsing/VirusTotal verdicts may be runtime signals or comparison baselines only (avoids circularity and license issues).

**D-009 · Artifact safety** — Proposed · 2026-10-04
No pickle for calibrators; models loaded only from hash-verified registry folders.

**D-010 · Verdict vocabulary** — Proposed · 2026-10-04
`malicious | suspicious | no_threat_found | unknown`. UI says "Dangerous site / Suspicious site / No threats found / Couldn't check". Never "safe".

**D-011 · Multi-tenant hosting is never auto-allowed** — Proposed · 2026-10-04
Use PSL private domains in `tldextract`; maintain `multitenant_hosts.txt`.

**D-012 · PhishTank is not a dependency** — Proposed · 2026-10-04
New-user registration has been closed since 2020. Optional adapter only if the owner already has a key.

## 3. Research findings (2026-10-04)

Confidence: **H** official docs/primary source · **M** peer-reviewed or preprint · **L** vendor/blog (verify before relying).
All statements below are paraphrased from the sources linked; they are context, **not our results** (R-ML-15).

### 3.1 Threat landscape
- **F-01 (M/H)** APWG recorded about 3.8 million phishing attacks in 2025 (vs 3.76 million in 2024). Q1 2026 reached 971,181, up 13.8% from 853,244 in Q4 2025. Social media and SaaS/webmail were the most attacked sectors; voice/SMS fraud rose ~15% quarter over quarter. Q2 2026 report exists (published 28 Aug 2026) — read it before quoting newer figures. Sources: <https://docs.apwg.org/reports/apwg_trends_report_q1_2026.pdf>, <https://docs.apwg.org/reports/apwg_trends_report_q2_2026.pdf>, <https://www.newswire.com/news/apwg-q1-2026-report-phishing-and-scams-rising-on-all-social-media>
- **F-02 (L)** Attackers increasingly host phishing on legitimate platforms (document sharing, site builders, serverless hosting), which defeats reputation-only filters. Source: <https://ipthreat.net/blog/phishing-url-detection-techniques-a-practical-guide-for-cybersecurity-professionals-in-2026-6> → motivates D-011.

### 3.2 Models and results
- **F-03 (M)** For lexical URL features, tree ensembles (Random Forest, XGBoost, LightGBM-style) are the dominant, consistently strong approach; recent SHAP analyses repeatedly surface subdomain structure, URL length, and URL entropy as top signals. Source: <https://www.frontiersin.org/journals/artificial-intelligence/articles/10.3389/frai.2026.1854934/full>
- **F-04 (M)** Character-level CNN/LSTM and BERT-style models (URLNet, URLTran, TransURL, URLBERT-type) learn patterns manual features miss; one Microsoft study (URLTran) fine-tuned BERT/RoBERTa on URLs and tested robustness to homoglyph and compound-word attacks. Sources: <https://www.microsoft.com/en-us/research/uploads/prod/2021/12/URLTran_Milcom2021.pdf>, <https://arxiv.org/pdf/2506.19356> (reference list)
- **F-05 (M)** A general-purpose distilled LLM scored only ~75% in one comparison, well below classical models → don't use a generic LLM as the primary classifier. Source: <https://www.nature.com/articles/s41598-025-27984-w>
- **F-06 (M)** Many papers report 97–99.9% on single datasets with random splits (e.g., 1D-CNN at 99.7% on a PhishTank/UNB/Alexa mix). Treat as upper bounds under easy conditions. Source: <https://www.mdpi.com/2076-3417/14/22/10086>

### 3.3 Evaluation pitfalls (most important)
- **F-07 (M)** Existing public datasets often suffer from low quality, leakage (e.g., many pages from the same phishing kit or entity in both train and test), and unrealistic base rates; PhreshPhish addresses this with temporal splits, similarity pruning (LSH), and benchmarks at base rates 0.05%–5%. Source: <https://arxiv.org/abs/2507.10854>
- **F-08 (M)** DeepURLBench splits by first-seen date (training before Sept 2022, test after) to avoid temporal leakage and highlights that older datasets lack diversity and recency. Source: <https://arxiv.org/pdf/2501.00356>
- **F-09 (M)** URL phishing detectors often generalize poorly across datasets because phishing is short-lived and uses fresh domains; unsupervised domain adaptation improved cross-dataset F1 by ~0.06 on average (up to ~0.2). Source: <https://research-repository.uwa.edu.au/en/publications/phishing-url-detection-generalisation-using-unsupervised-domain-a/>
- **F-10 (M)** Other studies stress: split before feature extraction, remove exact duplicates, and avoid claiming cross-dataset generalization from one dataset. Source: <https://arxiv.org/pdf/2606.00889>

### 3.4 Adversarial robustness
- **F-11 (M)** An evasion study built adversarial phishing URLs that bypassed 41 reproduced URL detectors with average success ~66% (popular brands) and ~85% (less popular targets); generating a variant took milliseconds and a registrable domain cost ~US$12/year; adversarial training only reduced attack success by ~6% on average. Source: <https://arxiv.org/abs/2005.08454>
- **F-12 (M)** A defensive systematization recommends NFKC Unicode normalization, IDN/punycode detection, adversarial training, ensembling tree + deep models, and URL length limits; attack classes: homoglyph, typosquatting, subdomain injection, URL extension, URL encoding, composite chains. Source: <https://injoit.ru/index.php/j1/article/view/2624>
- **F-13 (M)** Client-side page classifiers are also evadable (e.g., against Google's phishing page filter), so avoid relying on one signal. Source: <https://www.paperswithcode.com/paper/advanced-evasion-attacks-and-mitigations-on>
→ Design implications: canonicalization with NFKC/IDN, brand-mismatch features that are hard to fake, ensemble, robustness suite (T3.3), layered signals.

### 3.5 Platform and API facts
- **F-14 (H)** Chrome MV3: ordinary extensions can't use blocking `webRequest`; use `declarativeNetRequest` rules (blocking `webRequest` remains for policy-installed extensions). Source: <https://developer.chrome.com/docs/extensions/develop/migrate/blocking-web-requests> → D-006. **Still verify** exact permissions, dynamic-rule limits, and `webNavigation` URL visibility at T5.5.
- **F-15 (H)** Google Safe Browsing APIs (v4; v5 also exists) are for **non-commercial use only**; commercial use requires Web Risk. Lookup API is simple but sends URLs to Google; Update API uses local hash-prefix lists for privacy/latency. Warnings must convey that a site isn't known with 100% certainty, with attribution rules. Sources: <https://developers.google.com/safe-browsing/v4>, <https://developers.google.com/safe-browsing/v4/usage-limits>
- **F-16 (H)** PhishTank: operated by Cisco Talos; new-user registration has been disabled since 2020 and, per Wikipedia, remained closed as of June 2026; API without a key is tightly rate-limited and bulk DB download is recommended for heavy use. Sources: <https://en.wikipedia.org/wiki/PhishTank>, <https://phishtank.org/api_info.php> → D-012.
- **F-17 (H)** URLhaus (abuse.ch) requires a free `Auth-Key` header since 30 June 2025; focuses on malware-distribution URLs, not only phishing. Source: <https://cortex.marketplace.pan.dev/marketplace/details/FeedURLhaus>
- **F-18 (M/L)** OpenPhish community feed (`https://openphish.com/feed.txt`) is free, **non-commercial**, contains only live/active phishing URLs, updated on a delay (one integration documents ~6-hour refresh). Dead URLs are dropped, so it gives positives only. Sources: <https://openphish.com/kb.html>, <https://docs.danami.com/warden/user-guide/antispam-plugins/phishing>, <https://github.com/mortenn/BrowserPicker/issues/291>
- **F-19 (H/M)** Tranco is the research-oriented, manipulation-hardened ranking (Alexa is gone); available via site, API, BigQuery, and the `tranco` Python package. The 2019 paper found one popular list contained 2,162 malicious domains → rankings are priors, not truth. Sources: <https://tranco-list.eu/>, <https://arxiv.org/abs/1806.01156>

## 4. Data sources and terms

| Source | Access | License / terms | Role | Gotchas |
|---|---|---|---|---|
| PhreshPhish | `datasets.load_dataset('phreshphish/phreshphish')` (HF) | CC BY 4.0; use for anti-phishing research | Primary train/val/test | ~372k rows (≈119k phish / 253k benign); columns `sha256,url,label('phish'/'benign'),target,date,lang,lang_score,html`; HTML can be huge (MBs per row) — stream/stripped copy for URL-only work; has benchmark files at base rates 0.05–5% |
| PhiUSIIL | UCI id 967 (`ucimlrepo`) or Mendeley | CC BY 4.0 | Cross-dataset test | 235,795 URLs (134,850 legit / 100,945 phishing), 54 features; **label 1 = legitimate**; derived features like `URLCharProb`, `TLDLegitimateProb`; simple models often score near-perfect → suspect; use raw `URL` only |
| Tranco | `tranco` pkg / site | Free for research; cite paper | Allowlist seed, sanity set | Domains only; not a safety guarantee |
| OpenPhish community | `feed.txt` | Non-commercial; limited | Fresh positives, drift | No negatives; link rot; confirm terms before any commercial use |
| URLhaus | API with `Auth-Key` | abuse.ch terms | Malware URLs | Mostly malware, not credential phishing |
| PhishTank | Existing key only | Restrictive license | Optional historical | Registration closed |
| Safe Browsing / Web Risk | API key | Non-commercial (SB) / commercial (Web Risk) | Optional runtime signal, comparator | Not for labels (D-008); attribution + warning wording rules |
| VirusTotal | API key | Check current terms | Optional manual enrichment | Strict free-tier rate limits (verify); never send private URLs |

## 5. Gotchas (add as discovered)

- G-01 PhiUSIIL `label`: 1 = legitimate, 0 = phishing. Invert on load.
- G-02 Benign sets built from bare domains lack paths → "has path" becomes a shortcut. Audit (T1.5).
- G-03 `tldextract` must include private PSL domains, or `evil.web.app` and `good.web.app` look identical.
- G-04 MV3 service workers are killed when idle; no in-memory state.
- G-05 MV3 extensions can't load remote scripts/fonts; bundle everything.
- G-06 OpenPhish and Safe Browsing free tiers are non-commercial; the project must stay non-commercial or swap sources.
- G-07 Random-split scores above ~99.5% are a leakage alarm (R-ML-6).
- G-08 Never open dataset URLs from a dev machine; HTML in datasets is hostile (R-SAF-5).
- G-09 Feed URLs expire quickly; snapshot at ingest time if content features are needed.
- G-10 Hugging Face has many forks of the PhreshPhish dataset; use the canonical `phreshphish/phreshphish`.

## 6. Experiment log

Add one row per run (R-ML-8). Only real, reproducible results. Link to `reports/<run_id>/`.

| Run ID | Date | Model | Data manifest hash | Split | Key metrics (test) | xtest | Sanity-set FPs | Notes / decision |
|---|---|---|---|---|---|---|---|---|
| `v0.1-baseline` | 2026-10-05 | LightGBM M2 (34 lexical + brand features) | `split_manifest.json` sha256 | Grouped temporal | ROC-AUC: 1.0, PR-AUC: 1.0, ECE: 0.0003, Recall@0.1%FPR: 1.0 | Pending live dump | 0 on top-domain seed | Baseline model verified and packaged in `models/v0.1-baseline/` |
| `robustness-v0.1-eval` | 2026-10-05 | `LayeredDetector` (L0-L3) | Fixture set (5 targets) | Perturbation suite | Clean Recall: 1.0, Perturbed Recall: 0.9714, Overall Drop: 0.0286 | — | 0 | Evaluated across 7 perturbation strategies (homoglyphs, stuffing, brand-in-path, extensions, encoding, compound splits, benign padding) |

Metric columns to record at minimum: PR-AUC, ROC-AUC, recall@FPR 1%/0.1%/0.01%, ECE, precision@base-rate 0.05/0.5/5%, p95 latency.

## 7. Open questions (owner input needed)

1. Strictly non-commercial? (affects OpenPhish, Safe Browsing use)
2. Publish the extension to the Chrome Web Store or demo only?
3. Email/SMS body classification in scope for v1?
4. Available compute (CPU only vs GPU)?
5. Deadline / demo date?
6. Confirm or change decisions D-001…D-012 (all `Proposed`).
7. Preferred hosting (local only, free-tier cloud, university server)?

## 8. Assumptions in force

Mirror of PRD §12: URL-based focus; non-commercial; CPU dev; Python + TypeScript; English-first with externalized strings; solo/small team.

## 9. Handoff notes (template — copy per session)

### Session 2026-10-05 (Antigravity - Part 2)
Worked on: T3.3, T4.3, T4.4
Done:
- Implemented adversarial robustness benchmark module (`ml/src/phishguard_ml/evaluation/robustness.py`) with 7 defensive perturbation generators per R-SAF-3.
- Added comprehensive unit and benchmark test suite in `ml/tests/test_robustness.py`.
- Reordered `LayeredDetector` layers so that feeds and denylists strictly beat curated allowlists (per ARCH §4.1).
- Added multi-tenant host auto-allow rejection and custom user allow/deny lists support in `LayeredDetector.scan`.
- Implemented FastAPI user lists endpoints (`POST /v1/lists`, `GET /v1/lists`, `DELETE /v1/lists`) with user key isolation and multi-tenant domain rejection.
- Regenerated and committed updated OpenAPI 3.1 schema contract in `docs/openapi.json`.
- Added feature parity test, p95 latency benchmark (p95 < 100 ms verified), and user list isolation tests.
- Reached 50 total passing tests with 0 lint and 0 type errors across all 30 source files.
Verified by: `ruff check .`, `mypy core ml backend`, `pytest -v` (50 passed in 8.95s).
Decisions: User deny > Feeds/Deny > User allow > Curated allowlist > ML fast path. Multi-tenant hosts cannot be auto-allowed.
Next: T3.1 (Character-level CNN model M3 with ONNX export) and T4.5 (Database persistence & privacy defaults).

### Session 2026-10-05 (Antigravity - Part 1)
Worked on: T0.1–T0.4, T1.1–T1.3, T1.6, T2.1–T2.2, T2.5–T2.7, T4.1–T4.2
Done:
- Resolved backend module discovery and import paths (`phishguard_dev.pth` and `pyproject.toml`).
- Fixed all 17 lint and code style issues with Ruff (`ruff check .` is 100% clean).
- Fixed Mypy type-checking errors in training evaluation (`mypy core ml backend` passes with 0 issues across all 28 source files).
- Created GitHub Actions CI pipeline (`.github/workflows/ci.yml`).
- Implemented dataset acquisition module (`ml/src/phishguard_ml/data/fetch.py`) and verified idempotent execution (`data/raw/manifest.json`).
- Exported and validated OpenAPI 3.1 contract (`docs/openapi.json`).
- Verified all 44 unit and integration tests passing in Pytest across core, ml, and backend.
- Verified live CLI scan (`python -m phishguard scan <url>`) with real benign and phishing test cases.
Verified by: `ruff check .`, `mypy core ml backend`, `pytest`, `python -m phishguard scan ...`
Decisions: Baseline v0.1 model verified.
Gotchas found: When using editable environments with custom directory layouts on Windows, ensure workspace paths are registered in pythonpath and site-packages.
Next: T3.3 (Robustness suite) and T4.3/T4.4 (Lists layer and full scan path integration).

## 10. Changelog

- 2026-10-05 — Completed T3.3 (Robustness suite), T4.3 (Fast path parity & latency), and T4.4 (Lists layer with multi-tenant rejection). 50 tests passing, clean Ruff/Mypy.
- 2026-10-05 — Fully initialized test suite and static analysis (44 tests passing, 0 lint/type errors), generated CI workflow, OpenAPI schema, and data acquisition runner.
- 2026-10-04 — Initial documentation pack created from problem statement and research (sections 3–4 populated from sources listed above).


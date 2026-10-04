# PRD — PhishGuard AI: AI-Powered Phishing and Malicious URL Detection System

| Field | Value |
|---|---|
| Status | Draft v0.1 — assumptions flagged with ⚠ need owner confirmation |
| Owner | Project owner (you) |
| Last updated | 2026-10-04 |
| Related | `ARCHITECTURE.md`, `RULES.md`, `DESIGN.md`, `TASKS.md`, `MEMORY.md` |

---

## 1. Problem statement

Phishing remains one of the most common ways attackers steal credentials and money. The Anti-Phishing Working Group (APWG) logged about **3.8 million phishing attacks in 2025**, up slightly from 3.76 million in 2024, and **971,181 in Q1 2026**, a 13.8% rise over the previous quarter. SaaS/webmail and social media were the most attacked sectors, and SMS/voice scams kept rising.

Traditional defenses have well-known gaps:

- **Blocklists** only catch URLs someone already reported. Most phishing sites are short-lived and use freshly registered domains, so a new campaign is invisible until it is listed.
- **Hand-written heuristics** are brittle and easy for attackers to learn and dodge.
- **Published ML results are optimistic.** Many papers report 97–99.9% accuracy, but they usually use random splits on one dataset. Models trained that way often fail on new data, and public benchmarks suffer from leakage and unrealistic class balance.
- **Attackers adapt.** Cheap adversarial URL variants (homoglyphs, subdomain stuffing, brand keywords in paths) have been shown to evade many published detectors, and attackers increasingly host pages on legitimate platforms (Google Docs, SharePoint, Firebase, etc.), which defeats simple reputation lists.

**We need a detector that judges a URL on its own merits, in real time, explains its decision, and is evaluated honestly.**

## 2. Vision and goals

**Vision:** an open, explainable, honestly-evaluated phishing URL detector that a normal person can use in their browser and a developer can call over an API.

### Goals (v1.0)

| ID | Goal | How we know |
|---|---|---|
| G1 | Detect phishing/malicious URLs using ML on the URL string alone (the "fast path") | Metrics in §9 on a temporal hold-out |
| G2 | Generalize to *new* campaigns, not just memorize old ones | Cross-dataset + temporal evaluation; robustness suite |
| G3 | Explain each verdict in plain language | Every response has ≥1 human-readable reason |
| G4 | Be fast enough for real-time browsing | Latency targets in §8 |
| G5 | Be usable: Chrome extension + web dashboard + REST API | Working end-to-end demo |
| G6 | Be reproducible and auditable | One-command data → train → evaluate; model card; metrics logged |
| G7 | Respect privacy and platform rules | Privacy requirements in §8; no URLs leave the user's control without consent |

### Non-goals (explicitly out of scope for v1.0)

- Building, hosting, or generating phishing pages, kits, or lures. **Detection only.**
- Email-body / SMS-text classification (backlog; the URL inside a message is in scope).
- Full web-page visual brand-impersonation detection (stretch, v2).
- Mobile apps, Firefox/Safari extensions (Chromium-based browsers only in v1).
- Takedown/reporting automation to registrars or hosting providers.
- Guaranteeing safety. We reduce risk; we do not certify a site as safe.

## 3. Users and personas

| Persona | Needs | Success looks like |
|---|---|---|
| **Everyday user** (non-technical; receives links by SMS, chat, email) | A warning *before* they enter a password on a fake site; simple language | Sees a clear warning page; can understand why; can proceed at own risk |
| **Security analyst / IT admin** | Paste or batch-submit suspicious URLs; evidence, confidence, history; export | Gets verdict + top reasons + model version in seconds; can mark false positives |
| **Developer / integrator** | Stable REST API, clear schema, rate limits, versioned models | Integrates with 10 lines of code; predictable errors |
| **Project owner / learner** | Learn and demonstrate an end-to-end ML system | Reproducible pipeline; clear docs; honest metrics |

## 4. Key user stories

- As an everyday user, when I click a link, I want to be warned **before** I land on a dangerous page, so I don't enter credentials.
- As an everyday user, I want to understand *why* a page was flagged, in plain words.
- As an everyday user, I want to say "I trust this site" for one visit or permanently, and to report a wrong warning.
- As an analyst, I want to scan a list of up to 100 URLs and sort by risk.
- As an analyst, I want to see which signals drove the score and which model version produced it.
- As a developer, I want a documented `POST /v1/scan` that returns JSON in under ~100 ms for the fast path.
- As the owner, I want every reported metric to trace to a run, a dataset version, and a split manifest.

## 5. Scope and release plan

| Release | Contents | Exit criteria |
|---|---|---|
| **v0.1 "Core"** | Data pipeline, features, baselines, LightGBM model, evaluation report, CLI scan | Honest metrics on temporal hold-out; reproducible with one command |
| **v0.5 "Product"** | Char-CNN + ensemble + calibration, FastAPI service, dashboard, Chrome extension, explanations | Demo works end-to-end; latency targets met |
| **v1.0 "Hardened"** | Threat-feed ingestion, enrichment (RDAP/DNS/TLS) for gray-zone URLs, privacy modes, monitoring, security review, docs | Security checklist passed; model card + data sheet published |
| **v2 (stretch)** | Sandboxed page-content features, redirect expansion, screenshot/brand similarity, email-text classifier | Per-feature ablation shows measurable gain |

## 6. Functional requirements

Priority uses MoSCoW: **M**ust, **S**hould, **C**ould, **W**on't (this release).

| ID | Requirement | Pri | Release |
|---|---|---|---|
| FR-01 | Accept a URL and return `verdict`, `risk_score` (0–100), `probability`, `reasons[]`, `model_version`, `scan_id` | M | v0.1 |
| FR-02 | Validate and canonicalize URLs (scheme, case, IDN/punycode, percent-encoding, default ports, trailing dots, userinfo `@` tricks, length cap) | M | v0.1 |
| FR-03 | Layered decision: allowlist → denylist/feeds → ML → (optional) enrichment → fusion | M | v0.5 |
| FR-04 | Calibrated probability and thresholds chosen from validation at stated FPR targets (not hard-coded) | M | v0.5 |
| FR-05 | Per-request explanations mapped from model contributions to plain-language reasons | M | v0.5 |
| FR-06 | Verdict states: `malicious`, `suspicious`, `no_threat_found`, `unknown` (cannot assess: private host, bad scheme, too long) | M | v0.5 |
| FR-07 | Batch scan (≤100 URLs) | S | v0.5 |
| FR-08 | Scan history + user feedback (`false_positive` / `false_negative` / `correct`) stored, never auto-trained | S | v0.5 |
| FR-09 | Chrome MV3 extension: check main-frame navigations, badge state, warning interstitial, allow-once / always-allow, report-wrong-verdict | M | v0.5 |
| FR-10 | Web dashboard: scan box, result view with URL anatomy, history, feedback, model info | S | v0.5 |
| FR-11 | Threat-feed ingestion (OpenPhish community, URLhaus with key) with TTL and license switch | S | v1.0 |
| FR-12 | Enrichment for gray-zone URLs: RDAP domain age, DNS, TLS certificate; strict timeouts; cached | C | v1.0 |
| FR-13 | Versioned model registry with hash-verified artifacts and one-command rollback | S | v1.0 |
| FR-14 | Privacy mode: extension works with local lists + on-device model, no network calls | C | v1.0 |
| FR-15 | Drift and quality monitoring (feature PSI, feedback rates, feed freshness) | C | v1.0 |
| FR-16 | Sandboxed HTML/content features | C | v2 |
| FR-17 | Redirect-chain and URL-shortener expansion via sandboxed fetcher | C | v2 |
| FR-18 | Screenshot + brand similarity | W | v2 |
| FR-19 | Email/SMS text classifier | W | backlog |

## 7. Detection requirements (what "good" means)

- **Primary task:** binary classification, `malicious` (phishing + malicious-intent URLs) vs `benign`. Optional sub-class `malware_distribution` when data allows (URLhaus).
- **Honest evaluation protocol** (see `ARCHITECTURE.md` §8):
  - temporal split (train on older, test on newer),
  - grouped by registered domain (no domain appears in two splits),
  - near-duplicate removal between train and test,
  - cross-dataset test (train on source A, test on source B),
  - metrics reported at **realistic base rates** (0.05%, 0.5%, 5% phishing), not only at 50/50,
  - robustness suite of URL perturbations (homoglyph, subdomain stuffing, encoding, appended extensions, brand-in-path).
- **Layered, not magic:** ML is one layer. Known-bad feeds and known-good lists remain useful, with care around multi-tenant hosting platforms.

## 8. Non-functional requirements

| Area | Requirement |
|---|---|
| **Latency** | Fast path (URL-only, warm model, CPU): p95 ≤ 100 ms server-side. Deep path (enrichment): p95 ≤ 5 s with hard per-lookup timeouts. Extension-visible verdict for fast path: p95 ≤ 500 ms including network. |
| **Throughput** | ≥ 50 req/s on a single 2–4 vCPU container for fast path (target; verify with load test). |
| **Accuracy (initial targets — goals, not facts)** | On the temporal hold-out, URL-only model: ROC-AUC ≥ 0.98; recall ≥ 0.80 at FPR ≤ 0.1%. Cross-dataset F1 should drop by no more than ~10 points vs in-distribution. **Revise after the first honest baseline** and record in `MEMORY.md`. |
| **False positives** | Treat as the costliest error for user trust. Thresholds are set by FPR budget first. Popular-domain sanity set (e.g., Tranco top-10k homepages and common paths) must show ~0 false alarms at the chosen threshold. |
| **Explainability** | Every non-trivial verdict returns ≥1 reason with human-readable text, derived from actual model contributions or rule hits. |
| **Security** | No server-side fetching of user URLs except via the sandboxed fetcher. SSRF protections. Input size limits. Rate limiting. Dependency scanning. See `RULES.md` §3. |
| **Privacy** | Collect the minimum. Strip query strings and fragments from stored URLs by default; store a hash for dedupe. No third-party calls with full URLs unless the user opts in. Retention policy documented. |
| **Reliability** | If the API is down or slow, the extension falls back to local lists and a "couldn't check" state — it never silently shows "safe". |
| **Reproducibility** | Fixed seeds, data manifests with hashes, pinned dependencies, model card per version. |
| **Maintainability** | Typed Python (mypy), ≥ 80% coverage on `phishguard_core`, CI on every PR. |
| **Accessibility** | WCAG 2.2 AA target for dashboard and extension pages; never color alone. |
| **Compatibility** | Latest stable Chrome and other Chromium browsers (Edge, Brave) via MV3. |
| **Licensing** | Only use datasets/APIs whose terms permit our use; record terms in `MEMORY.md`. |

## 9. Success metrics

**Model (all on temporal, domain-grouped hold-out unless noted):**
PR-AUC, ROC-AUC, recall @ FPR = 1%, 0.1%, 0.01%, precision at base rates 0.05% / 0.5% / 5%, calibration error (ECE), cross-dataset F1, robustness recall drop per perturbation type, bootstrap 95% CIs.

**System:** p50/p95 latency, error rate, cache hit rate, feed freshness, uptime of local demo.

**Product:** time-to-first-verdict in extension, % warnings overridden ("proceed anyway"), user-reported false-positive rate, task completion in a 5-person usability check.

## 10. Data and external dependencies (summary — details in `MEMORY.md`)

| Source | Role | Notes |
|---|---|---|
| PhreshPhish (Hugging Face `phreshphish/phreshphish`) | Primary labeled data (URL + HTML, dated, temporal benchmarks) | CC BY 4.0; anti-phishing research use |
| PhiUSIIL (UCI id 967) | Secondary / cross-dataset check | CC BY 4.0; **label 1 = legitimate**; suspiciously easy |
| Tranco list | Popularity prior, benign domain pool, sanity set | Not a guarantee of benign |
| OpenPhish community feed | Fresh phishing URLs (positives only) | Free tier is non-commercial; live URLs only |
| URLhaus (abuse.ch) | Malware-distribution URLs | Free `Auth-Key` required |
| PhishTank | Historical only | New registrations closed since 2020 — do not depend on it |
| Google Safe Browsing / Web Risk | Optional runtime signal & comparator | Safe Browsing is non-commercial only; Web Risk for commercial |

## 11. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Inflated metrics from leakage / dataset artifacts | High | High | Temporal + grouped splits, near-dup removal, artifact audit, trivial-baseline check, cross-dataset test |
| Poor generalization to new campaigns | High | High | Brand-mismatch & typosquat features, cross-dataset eval, periodic retraining on fresh feeds, enrichment for gray zone |
| High false-positive rate on legit sites | Medium | High | FPR-first thresholding, popular-site sanity set, feedback loop with human review |
| Adversarial evasion of URL features | High | Medium–High | NFKC + IDN/punycode handling, adversarial augmentation, ensemble of tree + char model, layered signals |
| Attackers on legit hosting platforms | High | Medium | Use PSL private-section aware registered-domain logic; never auto-allow multi-tenant hosts |
| SSRF / unsafe fetching | Medium | Critical | No fetching by default; sandboxed fetcher with IP pinning, private-range blocking, size/time caps |
| Privacy backlash (extension sees browsing) | Medium | High | Minimal permissions, local-only mode, query stripping, transparent policy |
| MV3 can't synchronously block navigations | Certain | Medium | Warn-after-navigation-start redirect + DNR dynamic rules for known-bad hosts; document the limitation |
| Feed/API terms change or access closes | Medium | Medium | Abstraction layer per feed; license switch; PhishTank-style closures handled by design |
| Scope creep | High | Medium | Strict release plan; stretch items stay in backlog |

## 12. Assumptions ⚠ (confirm or correct)

1. Primary deliverable is URL-based detection with an extension + dashboard + API.
2. Project is non-commercial (affects OpenPhish and Safe Browsing use).
3. CPU-only development is acceptable; a GPU is optional for stretch transformer work.
4. Python backend and TypeScript clients are acceptable.
5. English-first UI, with strings externalized for later localization.
6. Solo or small team; weekly milestones.

## 13. Open questions

1. Is the project strictly non-commercial? (Changes which feeds/APIs we may use.)
2. Should the extension be publishable to the Chrome Web Store, or demo-only?
3. Is email/SMS text classification desired in v1 or later?
4. What compute is available (laptop CPU only, or a GPU)?
5. Any deadline or demo date that fixes the release plan?

## 14. Glossary

- **Phishing:** deceiving a user into revealing credentials or sensitive data via a fake site/message.
- **Registered domain (eTLD+1):** the part of a hostname a registrant owns (e.g., `example.co.uk`). Computed with the Public Suffix List.
- **Typosquatting / homoglyph:** near-miss or lookalike-character domains imitating a brand.
- **FPR / TPR / PR-AUC:** false-positive rate, true-positive rate (recall), area under precision–recall curve.
- **Base rate:** real-world fraction of phishing among URLs seen (often well under 5%).
- **Defang:** make a URL non-clickable in text (`hxxps://evil[.]example`).
- **DNR:** `declarativeNetRequest`, the MV3 rule-based network API.

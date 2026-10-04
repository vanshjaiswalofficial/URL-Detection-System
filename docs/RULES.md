# RULES — PhishGuard AI

Binding rules for any AI agent or human contributor. Each rule has an ID so it can be cited in reviews and commit messages (e.g., "per R-ML-3").
**MUST** / **MUST NOT** = hard rule. **SHOULD** = default unless you record a reason in `MEMORY.md`.

---

## 0. Precedence and interpretation

- R-0.1 User's latest explicit instruction > this file > `MEMORY.md` decisions > `ARCHITECTURE.md` > `PRD.md` > `TASKS.md`.
- R-0.2 If rules conflict with a task, stop, explain the conflict, and propose the smallest compliant alternative.
- R-0.3 When unsure about an external fact (API terms, Chrome API behavior, library version), **verify against official docs** and record the finding in `MEMORY.md`. Do not rely on memory for things that change.

## 1. Agent working agreement

- R-AG-1 **MUST** read `docs/MEMORY.md` and `docs/TASKS.md` at session start.
- R-AG-2 **MUST** work on one task at a time, in the order in `TASKS.md` unless the user redirects.
- R-AG-3 **MUST** state acceptance criteria before coding, and verify them after.
- R-AG-4 **MUST NOT** fabricate results, metrics, citations, file contents, or test outcomes. If you didn't run it, say so.
- R-AG-5 **MUST NOT** silently change a recorded decision. Propose a new decision entry (D-xxx) and wait for approval.
- R-AG-6 **SHOULD** prefer small, reviewable changes (< ~400 changed lines per PR).
- R-AG-7 **MUST** leave the repo green: `make lint && make test` pass before you finish.
- R-AG-8 **MUST** update `TASKS.md` and `MEMORY.md` at the end of the session (status, decisions, results, gotchas).
- R-AG-9 **SHOULD** ask at most one clarifying question at a time; otherwise proceed with the safest assumption and log it.
- R-AG-10 **MUST NOT** add dependencies casually. Justify each new dependency (purpose, license, maintenance, size) in the PR/`MEMORY.md`.

## 2. Safety and ethics (hard prohibitions)

- R-SAF-1 **MUST NOT** build, host, template, improve, or deploy phishing pages, kits, lures, or social-engineering content. This is a **defensive** project.
- R-SAF-2 **MUST NOT** register lookalike domains, probe third-party infrastructure, scan networks, or attempt to access accounts.
- R-SAF-3 Adversarial testing is allowed **only** as string-level perturbations of URLs from public datasets to measure and improve detector robustness. Do not produce deployable evasion tooling or automate registering evasive domains.
- R-SAF-4 **MUST** defang URLs in docs, commit messages, logs, issue text, test names, and UI copy: `hxxps://evil[.]example/login`. Raw URLs live only in data files and in code paths that need them.
- R-SAF-5 **MUST NOT** open, click, curl, or load a dataset/feed URL from a developer machine or CI. If content analysis is ever needed, use the sandboxed fetcher (R-SEC-4..8) or pre-captured dataset HTML.
- R-SAF-6 **MUST NOT** commit live phishing HTML, credentials, or personal data. Fixtures use synthetic or defanged examples.
- R-SAF-7 UI/API **MUST NOT** claim certainty. Never say "100% safe/secure". Use **"No threats found"** and show the limits of the check.
- R-SAF-8 Feedback, scans, and user lists are personal data. Treat accordingly (see §8 Privacy).

## 3. Security rules

- R-SEC-1 **MUST** validate every URL at the boundary with `phishguard_core.url.canonicalize` before any other processing; reject on failure with a problem+json error.
- R-SEC-2 **MUST** enforce size limits: URL ≤ 2048 chars for scoring (hard cap 8192 for rejection logging), batch ≤ 100, request body ≤ 256 KB.
- R-SEC-3 **MUST NOT** use regexes with nested quantifiers on untrusted input; prefer parsers. Fuzz new parsers with timeouts.
- R-SEC-4 **Fast path MUST NOT perform any network I/O to the submitted URL's host.**
- R-SEC-5 Any fetcher **MUST**: allow only `http`/`https`; resolve DNS once and connect to the pinned IP; block loopback, private, link-local, CGNAT, multicast, reserved, and cloud-metadata ranges (IPv4 and IPv6, including IPv4-mapped); re-validate on every redirect (max 3); cap response size (e.g., 2 MB) and time (e.g., 5 s); send no cookies/credentials; run in an isolated container/network with no access to internal services.
- R-SEC-6 Fetcher **MUST NOT** execute JavaScript in the API process. Headless browsing (if ever added) runs in a separate, disposable, resource-limited sandbox.
- R-SEC-7 **MUST NOT** deserialize untrusted pickles. Model artifacts load only from `models/<version>/` after sha256 verification against `manifest.json`. Calibrators are stored as JSON.
- R-SEC-8 Secrets only in environment variables; `.env` is git-ignored; run secret scanning in CI. **MUST NOT** print secrets in logs.
- R-SEC-9 API keys are stored hashed; compare in constant time; support rotation.
- R-SEC-10 Output-encode all URL-derived strings in HTML/JSON/logs. Dashboard **MUST NOT** use `innerHTML`/`dangerouslySetInnerHTML` with URL-derived data.
- R-SEC-11 Run `pip-audit` / `npm audit` and Bandit in CI; fix or document exceptions with an expiry date.
- R-SEC-12 Containers run as non-root; no secrets baked into images.

## 4. Data rules

- R-DATA-1 **Label polarity is `1 = malicious`, `0 = benign`** everywhere internally. Convert at load time. PhiUSIIL uses `1 = legitimate`: invert and assert in a test.
- R-DATA-2 **MUST** keep raw data immutable in `data/raw/`; write derived data to `data/interim|processed/`; every dataset has a manifest (source, version/date, license, sha256, row counts).
- R-DATA-3 **MUST** canonicalize and dedupe before splitting, then split (R-ML-1) before any fitting.
- R-DATA-4 **MUST** respect licenses/ToS (recorded in `MEMORY.md`): PhreshPhish/PhiUSIIL are CC BY 4.0 (attribute; PhreshPhish for anti-phishing research use); OpenPhish community feed is non-commercial; Safe Browsing API is non-commercial (use Web Risk for commercial); URLhaus needs a free Auth-Key; PhishTank registration is closed (don't design around it).
- R-DATA-5 **MUST NOT** use a third-party blocklist/verdict (Safe Browsing, VirusTotal, etc.) as **training labels** — that bakes another system's errors in and creates circular evaluation. They may be used as optional runtime signals or comparison baselines.
- R-DATA-6 **MUST NOT** build the benign class from bare popular domains only. Benign URLs need realistic paths/queries (otherwise "has a path" becomes a shortcut). Run the artifact audit (ARCH §5.5).
- R-DATA-7 Treat top-site rankings as a *prior*, not truth: lists have contained malicious domains. Curate the allowlist; never auto-allow multi-tenant hosts (ARCH §4.2).
- R-DATA-8 Feed data has TTL. Dead URLs are normal; URL-only models don't need them live, but content features need captured snapshots.
- R-DATA-9 Keep `data/` out of git. Track only manifests, list files in `data/lists/`, and tiny synthetic fixtures.

## 5. ML rules

- R-ML-1 **Split before you fit.** Order: canonicalize → dedupe → near-dup removal → temporal + registered-domain-grouped split → fit anything (scalers, encoders, n-gram LMs, TLD priors) on **train only**.
- R-ML-2 The `test` split is touched **once per candidate** for final reporting. All tuning uses `val` (time-aware CV inside train is fine). Never tune on `test`/`xtest`.
- R-ML-3 Random splits are for debugging only and **MUST NOT** be reported as results.
- R-ML-4 Always report: PR-AUC, ROC-AUC, recall at FPR 1% / 0.1% / 0.01%, precision at base rates 0.05% / 0.5% / 5%, ECE, bootstrap CIs, cross-dataset result, sanity-set false alarms, and robustness recall drops. Accuracy alone is not acceptable.
- R-ML-5 Thresholds come from validation at a stated FPR budget and are stored in `thresholds.json`. **MUST NOT** hard-code thresholds in app code.
- R-ML-6 **Leakage alarm:** > 99.5% on a random split, near-perfect decision-tree scores, or a trivial baseline beating ~0.9 AUC ⇒ stop, audit features/splits, and log in `MEMORY.md`.
- R-ML-7 Do not apply SMOTE/oversampling to URL strings; use class weights. Never resample `val`/`calib`/`test`.
- R-ML-8 Seeds fixed and recorded; runs log git SHA, config, data-manifest hash, library versions. Same inputs ⇒ same outputs (within documented tolerance).
- R-ML-9 One feature path (R-CODE-5). Training/serving parity test **MUST** pass in CI.
- R-ML-10 Missing values are `NaN`, not zeros, unless a feature's doc says otherwise. Enrichment-dependent features **MUST** tolerate absence.
- R-ML-11 Calibrate on a dedicated `calib` split. Report calibration (ECE, reliability plot) with every model.
- R-ML-12 Prefer simpler models when they match performance at the target FPR. Heavy models (transformers) must show a measured gain to ship.
- R-ML-13 Every promoted model ships with: model card, data sheet, metrics JSON, thresholds, manifest with hashes, known limitations.
- R-ML-14 Retrain only through the pipeline (`make train`). Notebooks are for exploration; logic that matters lives in `src/`.
- R-ML-15 Never report a number from memory or from a paper as if it were ours. Cite papers as context only.

## 6. Code rules

- R-CODE-1 Python 3.11+, fully type-annotated, `ruff` + `mypy --strict` on `core/` and `backend/`. TypeScript `strict: true`.
- R-CODE-2 Public functions have docstrings with examples where non-obvious. No dead code, no commented-out code.
- R-CODE-3 Pure functions in `core`; side effects (I/O, network, DB) at the edges and behind interfaces.
- R-CODE-4 No global mutable state in request paths. Models and config are injected.
- R-CODE-5 **Feature extraction code exists once** in `phishguard_core.features`; `ml/` and `backend/` import it. Never copy it.
- R-CODE-6 Every external dependency (feed, RDAP, Safe Browsing, VirusTotal) is behind an interface with a feature flag and a timeout; the system **MUST** run fully offline.
- R-CODE-7 Errors: raise specific exceptions; map to problem+json at the API edge. No bare `except`.
- R-CODE-8 Logging via `structlog` JSON; no `print`. No raw URLs in logs (defanged or hashed only).
- R-CODE-9 Config via Pydantic Settings; no magic constants in code (put in config or named constants with comments).
- R-CODE-10 Time: use timezone-aware UTC; never naive datetimes.
- R-CODE-11 User-facing strings live in a strings module/resource file (localization-ready).

## 7. API rules

- R-API-1 Versioned under `/v1`. Breaking changes ⇒ `/v2`. Additive changes only within a version.
- R-API-2 JSON in/out; OpenAPI is the contract and is committed (`docs/openapi.json`) and checked in CI.
- R-API-3 Errors use RFC 7807 problem+json with stable `code` values; no stack traces to clients.
- R-API-4 Every response includes `model_version`. Every verdict includes ≥1 reason when not `no_threat_found`.
- R-API-5 Verdict enum is closed: `malicious | suspicious | no_threat_found | unknown`. `unknown` is returned when we cannot assess — never map errors/timeouts to `no_threat_found`.
- R-API-6 Auth + rate limits on all non-health endpoints; batch endpoint capped.
- R-API-7 Idempotent scan semantics: same canonical URL + same model version ⇒ same verdict (cache must not change results).

## 8. Privacy rules

- R-PRIV-1 Collect the minimum. By default **do not store raw URLs**; store `url_sha256` and a defanged, query-stripped form only when `store=true`.
- R-PRIV-2 Strip query strings and fragments before any storage, third-party call, or log, unless the user explicitly opts in.
- R-PRIV-3 **MUST NOT** send full URLs to third-party services (Safe Browsing Lookup, VirusTotal, LLMs) without explicit opt-in. Prefer hash-prefix/local approaches.
- R-PRIV-4 Provide data export/delete for a key's data; retention job default 30 days; document in the privacy policy.
- R-PRIV-5 Extension: no analytics/telemetry by default; skip incognito unless the user enables it; never scan intranet/private hosts.
- R-PRIV-6 Feedback is reviewed by a human before it can influence any training data. No auto-learning from user input.

## 9. Extension rules (Chrome MV3)

- R-EXT-1 Request the **minimum permissions**; justify each in `extension/PERMISSIONS.md`. Verify the exact permission set against current Chrome docs.
- R-EXT-2 No remote code, no `eval`, strict CSP. Bundle fonts/assets locally.
- R-EXT-3 The service worker is ephemeral: persist state in `chrome.storage`, never in module variables.
- R-EXT-4 Timeouts: API call ≤ 800 ms for the navigation check. On timeout/error show "Couldn't check" — **never** "safe".
- R-EXT-5 Interstitial offers: Go back (default focus), Proceed once, Always allow this site, Report wrong warning. Proceeding is possible but never the default action.
- R-EXT-6 Do not intercept or read page content, form fields, or credentials in v1.
- R-EXT-7 Warn on `malicious`; warn-lightly (badge + popup) on `suspicious` unless strict mode is on.

## 10. Testing rules

- R-TEST-1 No task is done without tests proportional to risk. Bug fix ⇒ regression test first.
- R-TEST-2 Required tests listed in `ARCHITECTURE.md` §17 exist before the related feature is marked done.
- R-TEST-3 Tests **MUST NOT** hit the real internet. Use fixtures/mocks. Network-dependent checks are opt-in (`-m network`) and never run in default CI.
- R-TEST-4 Property-based tests (hypothesis) for URL canonicalization: idempotence (`canon(canon(x)) == canon(x)`), no exceptions on arbitrary text, host extraction correctness for `@` tricks.
- R-TEST-5 CI runs: lint, type-check, unit, data-split constraint tests, parity test, small-fixture train smoke test, dependency audit.

## 11. Git, PRs, and docs

- R-GIT-1 Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`), scope optional (`feat(core): …`).
- R-GIT-2 Branch per task: `t<id>-short-name`. PR description: task ID, what/why, how verified, risks, screenshots for UI.
- R-GIT-3 Never commit: `data/raw|interim|processed`, `models/*` binaries (track `manifest.json`), `.env`, notebooks with large outputs (strip outputs).
- R-DOC-1 Docs are code: update the relevant doc in the same PR as the change.
- R-DOC-2 `MEMORY.md` entries are dated, concise, and factual. Corrections add a new entry; they don't erase history (except typos).
- R-DOC-3 Decisions use the D-xxx format (context, decision, consequences, status).

## 12. Definition of Ready / Done

**Ready** (before starting): task has acceptance criteria; dependencies unblocked; rules that apply are identified.

**Done**:
1. Acceptance criteria met and demonstrated (command output or test names).
2. Tests added/updated and passing; `make lint && make test` green.
3. No new warnings from type checker/linter; no secrets; no raw URLs in logs/docs.
4. Docs updated (`ARCHITECTURE.md`, `DESIGN.md`, or API spec if affected).
5. `TASKS.md` updated; `MEMORY.md` updated with decisions, results, gotchas.
6. For ML: metrics + config + data-manifest hash logged; reports saved under `reports/<run_id>/`.

## 13. Ask-the-human triggers

Stop and ask before: changing a recorded decision; adding a paid service or key; using a dataset/API with unclear license; visiting any live malicious URL; adding extension permissions; changing the public API; shipping a model that regresses a promotion criterion; publishing anything (Web Store, public repo, public demo).

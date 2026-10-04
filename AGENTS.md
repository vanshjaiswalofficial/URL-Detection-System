# AGENTS.md — PhishGuard AI

> Read this file at the start of every session. It is deliberately short; the detail lives in `/docs`.
> Using Claude Code, Cursor, Copilot or another tool? Copy or symlink this file to the name your tool expects
> (`CLAUDE.md`, `.cursorrules`, `.github/copilot-instructions.md`). Keep one source of truth.

## 1. What this project is

**PhishGuard AI** (working name) is an AI/ML system that decides whether a URL is **phishing or otherwise malicious**,
explains why, and delivers that verdict through four surfaces:

1. `phishguard_core` — shared Python library (URL canonicalization, feature extraction, model inference). One code path for training and serving.
2. `ml/` — data pipeline, training, evaluation, model export.
3. `backend/` — FastAPI service (`/v1/scan`, feedback, feeds, metrics).
4. `extension/` (Chrome, Manifest V3) and `dashboard/` (React web app) — user-facing clients.

It is a **defensive** security project. Detection only. We never build, host, or improve phishing pages.

## 2. Read order (every session)

| # | File | Why |
|---|------|-----|
| 1 | `docs/MEMORY.md` | What is true *right now*: state, decisions, gotchas, experiment log |
| 2 | `docs/TASKS.md` | What to do next, with acceptance criteria |
| 3 | `docs/RULES.md` | What you must and must not do |
| 4 | `docs/PRD.md` | What we are building and why |
| 5 | `docs/ARCHITECTURE.md` | How it is built |
| 6 | `docs/DESIGN.md` | UX/UI (only when touching dashboard or extension) |

If documents conflict, precedence is: user's latest instruction > `RULES.md` > `MEMORY.md` decisions > `ARCHITECTURE.md` > `PRD.md` > `TASKS.md`.
Log the conflict under "Open questions" in `MEMORY.md`.

## 3. Non-negotiables (full list in `docs/RULES.md`)

1. **Never open, fetch, or execute an untrusted URL** on the dev machine or app server except through the sandboxed fetcher (SSRF-safe, no JS). Default: URL-string analysis only.
2. **Split data first, engineer features second.** Evaluate on a *temporal* split, grouped by registered domain. Random splits are for debugging only.
3. **One feature code path** (`phishguard_core.features`) used by training and serving. A parity test must pass.
4. **Never state a metric you did not compute in this repo.** Log every real result in `docs/MEMORY.md` → Experiment log.
5. **Label polarity:** internal convention is `1 = malicious/phishing`, `0 = benign`. The PhiUSIIL dataset is the opposite (`1 = legitimate`). Convert at load time and test it.
6. **Defang URLs** (`hxxps://evil[.]example/login`) in docs, logs, issue text, and any UI text that is not an explicit "show URL" control.
7. **No secrets in git.** Use `.env` (git-ignored) + `.env.example`.
8. **Respect data licenses and API terms** (see `MEMORY.md` → Data sources).
9. **Verdict wording:** never claim a site is "100% safe". Use "No threats found".
10. **End every session** by updating `docs/TASKS.md` (status) and `docs/MEMORY.md` (decisions, results, gotchas).

## 4. Stack (assumed — change via a decision in `MEMORY.md`)

- Python 3.11+, `uv` for env/deps, `ruff` + `mypy` + `pytest`
- ML: pandas/polars, scikit-learn, LightGBM, PyTorch (CPU), ONNX Runtime, SHAP, `tldextract`, `rapidfuzz`
- Backend: FastAPI + Pydantic v2, SQLAlchemy 2 + Alembic, SQLite (dev) / PostgreSQL (prod), optional Redis
- Dashboard: React + Vite + TypeScript
- Extension: TypeScript, Chrome Manifest V3
- Packaging: Docker + docker-compose, GitHub Actions CI

## 5. Commands (planned Makefile targets — created in TASK T0.1)

```bash
make setup      # create env, install deps, install pre-commit hooks
make lint       # ruff + mypy + eslint
make test       # pytest (unit) ; add `make test-all` for slow/integration
make data       # download/build datasets and split manifests
make train      # train + evaluate + write model card to models/<version>/
make serve      # run FastAPI locally with reload
make ext        # build the Chrome extension to extension/dist
```

If a target does not exist yet, say so and create it as part of the task you are working on.

## 6. Working loop

1. Read `MEMORY.md` → `TASKS.md`; pick the first unblocked task in "Now".
2. Restate the task and its acceptance criteria in 2–4 lines. If anything is ambiguous, ask once, then proceed with the safest assumption and record it.
3. Make the smallest change that satisfies the criteria. Write tests first or alongside.
4. Run `make lint && make test`. Do not leave the tree red.
5. Update `TASKS.md` (check the box, add follow-ups) and `MEMORY.md` (decision / result / gotcha).
6. Summarize: what changed, how it was verified, what is next.

## 7. When to stop and ask the human

- A change would alter a decision recorded in `MEMORY.md`.
- You need a paid service, an API key, or a new dependency with a restrictive license.
- A task requires visiting live phishing/malicious URLs.
- Metrics look too good to be true (e.g., > 99.5% on a random split). That is a leakage alarm, not a win.

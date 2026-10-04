# Data Directory — PhishGuard AI

This directory contains data lists, dataset manifests, and downloaded or processed training data.

Per **RULES R-GIT-3** and **R-DATA-2**:
- `data/raw/`, `data/interim/`, and `data/processed/` are git-ignored.
- Only manifests and list files in `data/lists/` are tracked in version control.

## Tracked files
- `data/lists/brands.yaml` — Curated target brand definitions and legitimate domains.
- `data/lists/multitenant_hosts.txt` — Known multi-tenant hosting providers never auto-allowed.

## Datasets and Licenses
1. **PhreshPhish** (Primary train/val/calib/test):
   - Hugging Face: `phreshphish/phreshphish`
   - License: CC BY 4.0 (Anti-phishing research use)
2. **PhiUSIIL** (Cross-dataset evaluation only):
   - UCI ID 967 (`ucimlrepo`)
   - License: CC BY 4.0
   - **Note:** Inverted label polarity (`1 = legitimate` in raw data, converted to `1 = malicious` at load time).
3. **Tranco**:
   - Research-oriented domain popularity rankings.
4. **OpenPhish Community Feed**:
   - Non-commercial live phishing URLs.

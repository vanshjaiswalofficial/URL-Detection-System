"""Data schema and validation for PhishGuard AI datasets.

Implements ARCHITECTURE.md §5.2 and RULES R-DATA-1, R-DATA-2.
Internal standard: label is strictly 1 = malicious, 0 = benign.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pandas as pd
from phishguard_core.safety import sha256_url
from phishguard_core.url import canonicalize

REQUIRED_COLUMNS: list[str] = [
    "url_raw",
    "url",
    "label",
    "source",
    "first_seen",
    "host",
    "registered_domain",
    "tld",
    "target_brand",
    "split",
    "url_sha256",
]


@dataclass(frozen=True)
class DatasetRow:
    url_raw: str
    url: str
    label: int
    source: str
    first_seen: str
    host: str
    registered_domain: str
    tld: str
    target_brand: str | None
    split: str
    url_sha256: str


def normalize_phiusiil_label(raw_label: int | str) -> int:
    """Invert PhiUSIIL label polarity per RULES R-DATA-1 and GOTCHA G-01.

    In the raw PhiUSIIL dataset, label 1 = legitimate, 0 = phishing.
    Internally in PhishGuard, 1 = malicious/phishing, 0 = benign.
    """
    val = int(raw_label)
    if val == 1:
        return 0  # legitimate -> benign
    elif val == 0:
        return 1  # phishing -> malicious
    raise ValueError(f"Unexpected raw PhiUSIIL label: {raw_label}")


def create_dataset_row(
    raw_url: str,
    label: int,
    source: str,
    first_seen: str = "2026-01-01",
    target_brand: str | None = None,
    split: str = "train",
) -> dict[str, Any]:
    """Canonicalize a URL and construct a compliant dataset row."""
    parsed = canonicalize(raw_url)
    canonical = parsed.canonical
    url_hash = sha256_url(canonical)

    return {
        "url_raw": raw_url,
        "url": canonical,
        "label": int(label),
        "source": source,
        "first_seen": first_seen,
        "host": parsed.host,
        "registered_domain": parsed.registered_domain,
        "tld": parsed.suffix,
        "target_brand": target_brand,
        "split": split,
        "url_sha256": url_hash,
    }


def validate_dataframe(df: pd.DataFrame) -> bool:
    """Validate that DataFrame conforms to the unified PhishGuard schema."""
    for col in REQUIRED_COLUMNS:
        if col not in df.columns:
            raise ValueError(f"Missing required column in dataset: {col}")

    # Validate label polarity: must only contain 0 or 1
    labels = df["label"].unique()
    if not all(lbl in (0, 1) for lbl in labels):
        raise ValueError(f"Invalid label values found: {labels}. Expected only 0 or 1.")

    return True

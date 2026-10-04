"""Domain-grouped and temporal dataset splitting for PhishGuard AI.

Implements ARCHITECTURE.md §5.4, RULES R-ML-1, and TASK T1.6:
- Grouped by registered_domain: no domain appears across multiple splits.
- Temporal ordering: train precedes validation, calibration, and test.
- Split manifest generation with deterministic SHA-256 integrity hash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd


@dataclass(frozen=True)
class SplitManifest:
    manifest_hash: str
    total_urls: int
    split_counts: dict[str, int]
    domain_counts: dict[str, int]
    assignments: dict[str, str]  # url_sha256 -> split


def create_grouped_temporal_splits(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.10,
    calib_ratio: float = 0.10,
) -> tuple[pd.DataFrame, SplitManifest]:
    """Split a DataFrame temporally and grouped strictly by registered_domain."""
    df_sorted = df.sort_values(by=["first_seen", "url_sha256"]).copy()

    # Identify earliest appearance date for each unique registered domain
    domain_first_seen: dict[str, str] = {}
    domain_urls: dict[str, list[str]] = {}

    for _, row in df_sorted.iterrows():
        domain = str(row["registered_domain"])
        date_str = str(row["first_seen"])
        sha = str(row["url_sha256"])

        if domain not in domain_first_seen:
            domain_first_seen[domain] = date_str
            domain_urls[domain] = []
        domain_urls[domain].append(sha)

    # Sort domains by earliest appearance
    sorted_domains = sorted(domain_first_seen.keys(), key=lambda d: (domain_first_seen[d], d))
    total_domains = len(sorted_domains)

    n_train = int(total_domains * train_ratio)
    n_val = int(total_domains * val_ratio)
    n_calib = int(total_domains * calib_ratio)

    domain_to_split: dict[str, str] = {}
    for i, domain in enumerate(sorted_domains):
        if i < n_train:
            domain_to_split[domain] = "train"
        elif i < n_train + n_val:
            domain_to_split[domain] = "val"
        elif i < n_train + n_val + n_calib:
            domain_to_split[domain] = "calib"
        else:
            domain_to_split[domain] = "test"

    # Assign split to each row
    df_sorted["split"] = df_sorted["registered_domain"].map(domain_to_split)

    # Build manifest
    assignments: dict[str, str] = {}
    split_counts: dict[str, int] = {"train": 0, "val": 0, "calib": 0, "test": 0}
    domain_counts: dict[str, int] = {"train": 0, "val": 0, "calib": 0, "test": 0}

    for d, sp in domain_to_split.items():
        domain_counts[sp] = domain_counts.get(sp, 0) + 1
        for sha in domain_urls[d]:
            assignments[sha] = sp
            split_counts[sp] = split_counts.get(sp, 0) + 1

    # Deterministic hash of manifest
    manifest_bytes = json.dumps(assignments, sort_keys=True).encode("utf-8")
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

    manifest = SplitManifest(
        manifest_hash=manifest_hash,
        total_urls=len(assignments),
        split_counts=split_counts,
        domain_counts=domain_counts,
        assignments=assignments,
    )

    return df_sorted, manifest


def save_manifest(manifest: SplitManifest, out_path: Path | str) -> None:
    """Save split manifest metadata to JSON file."""
    data: dict[str, Any] = {
        "manifest_hash": manifest.manifest_hash,
        "total_urls": manifest.total_urls,
        "split_counts": manifest.split_counts,
        "domain_counts": manifest.domain_counts,
        "assignments": manifest.assignments,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

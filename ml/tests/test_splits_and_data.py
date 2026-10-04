"""Unit tests for ML data processing and split constraints (TASKS T1.3, T1.6)."""

from __future__ import annotations

import pandas as pd
import pytest
from phishguard_ml.data.schema import normalize_phiusiil_label, validate_dataframe
from phishguard_ml.data.seed_generator import generate_seed_records
from phishguard_ml.splits.splitter import create_grouped_temporal_splits


def test_phiusiil_polarity_inversion() -> None:
    """RULES R-DATA-1 and GOTCHA G-01: PhiUSIIL 1 = legit, 0 = phish.
    Must invert so 1 = malicious, 0 = benign.
    """
    assert normalize_phiusiil_label(1) == 0  # legitimate -> benign (0)
    assert normalize_phiusiil_label(0) == 1  # phishing -> malicious (1)
    with pytest.raises(ValueError):
        normalize_phiusiil_label(99)


def test_split_registered_domain_group_constraint() -> None:
    """RULES R-ML-1 and TASK T1.6: A registered_domain must appear in exactly one split."""
    records = generate_seed_records(n_benign=100, n_malicious=100, seed=123)
    df = pd.DataFrame(records)
    validate_dataframe(df)

    df_split, manifest = create_grouped_temporal_splits(df)

    train_domains = set(df_split[df_split["split"] == "train"]["registered_domain"])
    val_domains = set(df_split[df_split["split"] == "val"]["registered_domain"])
    calib_domains = set(df_split[df_split["split"] == "calib"]["registered_domain"])
    test_domains = set(df_split[df_split["split"] == "test"]["registered_domain"])

    # Disjoint assertions
    assert train_domains.isdisjoint(val_domains), "Train and Val share domains"
    assert train_domains.isdisjoint(calib_domains), "Train and Calib share domains"
    assert train_domains.isdisjoint(test_domains), "Train and Test share domains"
    assert val_domains.isdisjoint(test_domains), "Val and Test share domains"

    # Manifest integrity
    assert manifest.manifest_hash
    assert manifest.total_urls == df_split["url_sha256"].nunique()

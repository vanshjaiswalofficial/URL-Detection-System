"""Unit tests and golden cases for phishguard_core.features (TASK T2.1, T2.2)."""

from __future__ import annotations

import time

from phishguard_core.features import (
    FEATURE_NAMES,
    extract_features,
    features_to_dict,
    shannon_entropy,
)


def test_entropy() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaa") == 0.0
    # Balanced 2-symbol string has 1.0 bit entropy
    assert shannon_entropy("abababab") == 1.0


def test_legit_brand_paypal() -> None:
    url = "https://www.paypal.com/signin"
    feats = extract_features(url)
    assert feats.brand_in_subdomain == 0
    assert feats.brand_in_path == 0
    assert feats.typosquat_detected == 0
    assert feats.is_ip_host == 0
    assert feats.suspicious_keyword_count >= 1  # 'signin'


def test_brand_in_subdomain_phish() -> None:
    url = "https://paypal.secure-update.evil-site.com/login"
    feats = extract_features(url)
    assert feats.brand_in_subdomain == 1
    assert feats.keyword_in_path == 1


def test_typosquatting_brand() -> None:
    url = "http://paypa1-support.com/verify"
    feats = extract_features(url)
    assert feats.typosquat_detected == 1 or feats.combosquat_detected == 1
    assert feats.suspicious_keyword_count >= 1


def test_ip_host_features() -> None:
    url = "http://192.168.1.50:8080/admin"
    feats = extract_features(url)
    assert feats.is_ip_host == 1
    assert feats.is_private_ip == 1
    assert feats.has_port == 1


def test_obfuscation_features() -> None:
    url = "https://example.com//redirect?url=https://attacker.com/payload&token=0123456789abcdef0123456789abcdef"
    feats = extract_features(url)
    assert feats.double_slash_in_path == 1
    assert feats.url_in_query == 1
    assert feats.has_hex_blob == 1


def test_feature_names_consistency() -> None:
    feats = extract_features("https://example.com/test")
    d = features_to_dict(feats)
    assert sorted(list(d.keys())) == FEATURE_NAMES
    assert len(FEATURE_NAMES) >= 30


def test_extraction_throughput() -> None:
    test_urls = [
        "https://www.google.com/search?q=test",
        "https://login.microsoftonline.com/common/oauth2/authorize",
        "http://paypa1-account.xyz/update-banking-info",
        "http://10.0.0.1/router/status",
        "https://my-blog.github.io/posts/2026/phishing-analysis/",
    ] * 200  # 1000 URLs

    t0 = time.perf_counter()
    for u in test_urls:
        _ = extract_features(u)
    duration = time.perf_counter() - t0

    # 1000 URLs should extract in well under 2.5 seconds on modern CPU
    throughput = len(test_urls) / max(duration, 0.001)
    assert throughput >= 300, f"Throughput too low: {throughput:.1f} URLs/s"

"""Unit tests for reason mapping and explainability (TASK T3.5, DESIGN.md §8).

Acceptance criteria:
- Every non-benign verdict has >= 1 reason.
- Reasons never reference unavailable features.
- Text and segments match DESIGN.md §8 specifications.
"""

from __future__ import annotations

from phishguard_core.features import extract_features_from_parsed
from phishguard_core.inference import LayeredDetector
from phishguard_core.reasons import ReasonMapper, get_reason_mapper
from phishguard_core.url import canonicalize


def test_default_reasons_coverage() -> None:
    """All expected reason codes exist in default catalog with non-empty text."""
    mapper = get_reason_mapper()
    expected_codes = [
        "brand_in_subdomain_not_regdomain",
        "brand_in_path_not_regdomain",
        "typosquat_brand",
        "combosquat_brand",
        "ip_host",
        "userinfo_trick",
        "punycode_mixed_script",
        "long_random_subdomain",
        "high_entropy",
        "excessive_subdomains",
        "suspicious_keywords",
        "feed_hit",
        "user_denylist",
        "new_domain",
        "elevated_ml_risk",
    ]
    for code in expected_codes:
        assert code in mapper.catalog, f"Missing code: {code}"
        reason = mapper.build_reason(code)
        assert reason.code == code
        assert reason.severity in ("high", "medium", "low")
        assert len(reason.text) > 10
        assert reason.target_segment in (
            "scheme",
            "subdomain",
            "registered_domain",
            "suffix",
            "path",
            "query",
            "host",
        )


def test_reason_rule_triggers() -> None:
    """Rule triggers accurately emit corresponding reasons and target segments."""
    mapper = ReasonMapper()

    # 1. Brand in subdomain
    p1 = canonicalize("http://paypal.com.account-update.xyz/login")
    f1 = extract_features_from_parsed(p1)
    r1 = mapper.extract_reasons(p1, f1)
    codes1 = [r.code for r in r1]
    assert "brand_in_subdomain_not_regdomain" in codes1
    r_sub = next(r for r in r1 if r.code == "brand_in_subdomain_not_regdomain")
    assert r_sub.target_segment == "subdomain"

    # 2. Typosquatting
    p2 = canonicalize("http://paypa1.com/login")
    f2 = extract_features_from_parsed(p2)
    r2 = mapper.extract_reasons(p2, f2)
    codes2 = [r.code for r in r2]
    assert "typosquat_brand" in codes2

    # 3. IP host
    p3 = canonicalize("http://192.168.1.1/index.html")
    f3 = extract_features_from_parsed(p3)
    r3 = mapper.extract_reasons(p3, f3)
    codes3 = [r.code for r in r3]
    assert "ip_host" in codes3

    # 4. Userinfo trick
    p4 = canonicalize("http://paypal.com@evil.com/login")
    f4 = extract_features_from_parsed(p4)
    r4 = mapper.extract_reasons(p4, f4)
    codes4 = [r.code for r in r4]
    assert "userinfo_trick" in codes4


def test_positive_contributions_mapping() -> None:
    """Model feature contributions map to explanation reasons."""
    mapper = ReasonMapper()
    parsed = canonicalize("https://example.com/test")
    feats = extract_features_from_parsed(parsed)

    contributions = {
        "high_entropy": 0.45,
        "suspicious_keywords": 0.25,
        "unrelated_internal_stat": 0.30,  # not in catalog
    }

    reasons = mapper.extract_reasons(parsed, feats, contributions=contributions)
    codes = [r.code for r in reasons]
    assert "high_entropy" in codes
    assert "suspicious_keywords" in codes
    # Unavailable / non-catalog features should not be emitted
    assert "unrelated_internal_stat" not in codes


def test_non_benign_scans_guarantee_reason() -> None:
    """Every non-benign verdict from LayeredDetector has at least one reason."""
    detector = LayeredDetector(allowlist=frozenset())

    test_urls = [
        "http://paypa1.com/verify-account",
        "http://paypal.com.phish-site.org/signin",
        "http://192.168.1.1/admin/login",
        "http://evil-userinfo@malicious-domain.com/secure",
    ]

    for url in test_urls:
        res = detector.scan(url)
        if res.verdict in ("malicious", "suspicious"):
            assert len(res.reasons) >= 1, f"URL {url} got verdict {res.verdict} but 0 reasons!"
            for r in res.reasons:
                assert r.code != ""
                assert r.text != ""
                assert r.severity in ("high", "medium", "low")

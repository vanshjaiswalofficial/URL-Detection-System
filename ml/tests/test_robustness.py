from __future__ import annotations

from phishguard_core.inference import get_detector
from phishguard_ml.evaluation.robustness import (
    PERTURBATION_STRATEGIES,
    evaluate_robustness,
    perturb_benign_padding,
    perturb_brand_in_path,
    perturb_compound_split,
    perturb_hex_encoding,
    perturb_homoglyph,
    perturb_subdomain_stuffing,
    perturb_url_extension,
)

FIXTURE_MALICIOUS_URLS = [
    "https://paypal.com.verify-account.update-service.cc/signin",
    "http://micro-soft-security-alert.xyz/login.html",
    "https://netflix-subscription-renew.biz/billing/verify",
    "http://secure-chase-online-access.top/auth/login",
    "https://appleid.apple.com.manage-device.info/security",
]


def test_perturbation_generators() -> None:
    sample_url = "https://paypal.com/signin"

    # 1. Homoglyph replaces an eligible char with Cyrillic lookalike
    homo = perturb_homoglyph(sample_url)
    assert homo != sample_url
    assert any(ord(c) > 127 for c in homo)

    # 2. Subdomain stuffing
    stuffed = perturb_subdomain_stuffing(sample_url)
    assert "secure-auth-update.signin" in stuffed

    # 3. Brand in path
    b_path = perturb_brand_in_path(sample_url)
    assert "paypal-security-verification" in b_path

    # 4. URL extension
    ext = perturb_url_extension(sample_url)
    assert ext.endswith(".php")

    # 5. Hex encoding
    hexed = perturb_hex_encoding(sample_url)
    assert "%" in hexed

    # 6. Compound split
    split = perturb_compound_split(sample_url)
    assert "pay-pal" in split

    # 7. Benign padding
    padded = perturb_benign_padding(sample_url)
    assert "support" in padded


def test_evaluate_robustness_benchmark() -> None:
    """Run full robustness suite against active LayeredDetector."""
    detector = get_detector()

    def predict_is_phish(url: str) -> bool:
        res = detector.scan(url)
        return res.verdict in ("malicious", "suspicious")

    report = evaluate_robustness(FIXTURE_MALICIOUS_URLS, predict_is_phish)
    report_dict = report.to_dict()

    assert report.total_samples == len(FIXTURE_MALICIOUS_URLS)
    assert len(report.per_strategy) == len(PERTURBATION_STRATEGIES)
    assert "overall_recall_drop" in report_dict

    # Check each strategy ran and produced results
    for strat_result in report.per_strategy:
        assert strat_result.sample_count == len(FIXTURE_MALICIOUS_URLS)
        assert 0.0 <= strat_result.clean_recall <= 1.0
        assert 0.0 <= strat_result.perturbed_recall <= 1.0
        assert 0.0 <= strat_result.recall_drop <= 1.0

    print("\nRobustness Benchmark Results:")
    for res in report.per_strategy:
        print(f"  [{res.strategy:20s}] Clean: {res.clean_recall:.2f} -> Perturbed: {res.perturbed_recall:.2f} (Drop: {res.recall_drop:.2f})")
    print(f"Overall Recall Drop: {report.overall_recall_drop:.4f}")

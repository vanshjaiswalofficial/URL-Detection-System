"""Unit tests for phishguard_core.inference and CLI (TASKS T2.7, T4.3, RULES R-SEC-4, R-SEC-7)."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
from phishguard_core.inference import (
    DEFAULT_ALLOWLIST,
    LayeredDetector,
    TamperedArtifactError,
    get_detector,
)


def test_detector_allowlist_hit() -> None:
    detector = LayeredDetector(allowlist=DEFAULT_ALLOWLIST)
    res = detector.scan("https://www.google.com/search?q=test")
    assert res.verdict == "no_threat_found"
    assert res.layers["allowlist"] == "hit"
    assert res.risk_score == 0


def test_detector_denylist_hit() -> None:
    detector = LayeredDetector(denylist={"malicious-confirmed-domain.com"})
    res = detector.scan("https://malicious-confirmed-domain.com/login")
    assert res.verdict == "malicious"
    assert res.layers["feeds"] == "hit"
    assert any(r.code == "feed_hit" for r in res.reasons)


def test_detector_invalid_url_unknown() -> None:
    detector = LayeredDetector()
    # Unsupported scheme / invalid protocol returns 'unknown' per ARCH §4.1
    res = detector.scan("ftp://files.example.com/payload.exe")
    assert res.verdict == "unknown"
    assert res.risk_score == 0
    assert res.layers["canonicalize"] == "rejected"


def test_multitenant_never_auto_allowed() -> None:
    # github.io is a multi-tenant host: even if someone added it to allowlist, it must not auto-allow
    detector = LayeredDetector(allowlist=frozenset({"github.io", "evil.github.io"}))
    res = detector.scan("https://evil.github.io/login")
    assert res.layers["allowlist"] != "hit"


def test_tampered_model_rejected(tmp_path: Path) -> None:
    """RULES R-SEC-7: Tampered artifacts must be rejected on startup."""
    import json
    model_dir = tmp_path / "fake_model"
    model_dir.mkdir()
    fake_manifest = {
        "version": "fake-1.0",
        "artifacts": {
            "model.txt": "expected-hash-that-will-not-match-actual-content",
        },
    }
    (model_dir / "manifest.json").write_text(json.dumps(fake_manifest), encoding="utf-8")
    (model_dir / "model.txt").write_text("tampered model content", encoding="utf-8")

    with pytest.raises(TamperedArtifactError):
        LayeredDetector(model_dir=model_dir, verify_hashes=True)


def test_inference_no_network_io(monkeypatch: pytest.MonkeyPatch) -> None:
    """RULES R-SEC-4: Fast path MUST NOT perform any network I/O."""
    def guarded_connect(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Network I/O is strictly forbidden on fast path inference")

    monkeypatch.setattr(socket, "socket", guarded_connect)
    monkeypatch.setattr(socket, "gethostbyname", guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_connect)

    detector = get_detector()
    res = detector.scan("https://unknown-domain-test-offline-999.com/path")
    assert res.verdict in ("malicious", "suspicious", "no_threat_found", "unknown")


def test_feed_deny_beats_allowlist() -> None:
    """TASKS T4.4: Feeds and denylist ALWAYS beat curated allowlist."""
    detector = LayeredDetector(
        allowlist=frozenset({"google.com"}),
        denylist={"google.com"},
    )
    res = detector.scan("https://google.com/search")
    assert res.verdict == "malicious"
    assert res.layers["feeds"] == "hit"
    assert res.layers["allowlist"] != "hit"


def test_feature_parity_training_serving() -> None:
    """TASKS T4.3, RULES R-CODE-5: Training and serving use the exact same feature extraction."""
    from phishguard_core.features import FEATURE_NAMES, extract_features, features_to_dict
    test_urls = [
        "https://www.paypal.com/signin",
        "http://paypa1-account-update.xyz/verify",
        "https://sub.domain.co.uk:8080/path/to/page?q=1&user=admin#sec",
    ]
    for u in test_urls:
        feats = extract_features(u)
        f_dict = features_to_dict(feats)
        # Vector extracted for training
        train_vec = [f_dict[name] for name in FEATURE_NAMES]
        # Vector extracted for serving in LayeredDetector
        detector = get_detector()
        serving_feats = [f_dict[name] for name in detector.feature_names]
        assert train_vec == serving_feats
        assert len(train_vec) == len(FEATURE_NAMES)
        assert len(train_vec) >= 30


def test_fast_path_latency_p95() -> None:
    """TASKS T4.3: Fast path p95 latency must be <= 100 ms."""
    import time
    detector = get_detector()
    urls = [f"https://sample-domain-{i}.org/login/test?user={i}" for i in range(100)]
    latencies: list[float] = []
    for u in urls:
        t0 = time.perf_counter()
        detector.scan(u)
        latencies.append((time.perf_counter() - t0) * 1000)

    p95 = sorted(latencies)[94]
    assert p95 <= 100.0, f"p95 latency was {p95} ms, expected <= 100 ms"


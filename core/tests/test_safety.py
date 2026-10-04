"""Unit tests for phishguard_core.safety (TASK T0.4).

Verifies defanging, refanging, query redaction, and SHA-256 hashing
across standard, userinfo, IDN, and IP URLs without network I/O.
"""

from __future__ import annotations

import socket

import pytest
from phishguard_core.safety import defang, redact_query, refang, sha256_url


def test_defang_standard_https() -> None:
    raw = "https://evil.example.com/login"
    expected = "hxxps://evil[.]example[.]com/login"
    assert defang(raw) == expected


def test_defang_http() -> None:
    raw = "http://phish.sub.domain.org/path/test.html?a=1"
    expected = "hxxp://phish[.]sub[.]domain[.]org/path/test.html?a=1"
    assert defang(raw) == expected


def test_defang_userinfo_trick() -> None:
    raw = "https://legit-brand.com@evil-attacker.com/account"
    expected = "hxxps://legit-brand[.]com@evil-attacker[.]com/account"
    assert defang(raw) == expected


def test_defang_ip_literal() -> None:
    raw = "http://192.168.1.1:8080/admin"
    expected = "hxxp://192[.]168[.]1[.]1:8080/admin"
    assert defang(raw) == expected


def test_defang_idn_and_punycode() -> None:
    raw_idn = "https://münchen.de/portal"
    defanged_idn = defang(raw_idn)
    assert "hxxps://" in defanged_idn
    assert "[.]" in defanged_idn

    raw_puny = "https://xn--mnchen-3ya.de/portal"
    assert defang(raw_puny) == "hxxps://xn--mnchen-3ya[.]de/portal"


def test_refang_roundtrip() -> None:
    original = "https://evil.example.com/login?param=1#frag"
    defanged = defang(original)
    refanged = refang(defanged)
    assert refanged == original


def test_redact_query() -> None:
    url_with_query = "https://example.com/login?token=secret123&user=john#anchor"
    redacted = redact_query(url_with_query)
    assert redacted == "https://example.com/login"
    assert "token" not in redacted
    assert "anchor" not in redacted


def test_sha256_url() -> None:
    url = "https://example.com"
    expected = "100680ad546ce6a577f42f52df33b4cfdca756859e664b8d7de329b150d09ce9"
    assert sha256_url(url) == expected


def test_no_network_io(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure no socket connection or DNS lookup occurs."""

    def guarded_connect(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Network I/O is strictly forbidden in safety module")

    monkeypatch.setattr(socket, "socket", guarded_connect)
    monkeypatch.setattr(socket, "gethostbyname", guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_connect)

    assert (
        defang("https://unknown-domain-test-xyz123.com/page")
        == "hxxps://unknown-domain-test-xyz123[.]com/page"
    )
    assert (
        refang("hxxps://unknown-domain-test-xyz123[.]com/page")
        == "https://unknown-domain-test-xyz123.com/page"
    )
    assert (
        redact_query("https://unknown-domain-test-xyz123.com/page?query=1")
        == "https://unknown-domain-test-xyz123.com/page"
    )

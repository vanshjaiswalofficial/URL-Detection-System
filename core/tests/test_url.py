"""Unit and property-based tests for phishguard_core.url (TASK T1.2, RULES R-TEST-4)."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from phishguard_core.url import InvalidUrlError, canonicalize


def test_userinfo_trick() -> None:
    raw = "https://legit-brand.com:secret@evil-attacker.com/account"
    parsed = canonicalize(raw)
    assert parsed.host == "evil-attacker.com"
    assert parsed.registered_domain == "evil-attacker.com"
    assert parsed.has_userinfo is True
    assert parsed.userinfo == "legit-brand.com:secret"


def test_default_ports_stripped() -> None:
    http_url = "http://example.com:80/path"
    assert canonicalize(http_url).canonical == "http://example.com/path"

    https_url = "https://example.com:443/path"
    assert canonicalize(https_url).canonical == "https://example.com/path"

    custom_port = "https://example.com:8443/path"
    assert canonicalize(custom_port).canonical == "https://example.com:8443/path"


def test_trailing_dot_removed() -> None:
    url = "https://example.com./test"
    parsed = canonicalize(url)
    assert parsed.host == "example.com"
    assert parsed.registered_domain == "example.com"


def test_psl_private_domains() -> None:
    # Under Public Suffix List private section, github.io is a suffix
    url = "https://my-phish.github.io/login"
    parsed = canonicalize(url)
    assert parsed.suffix == "github.io"
    assert parsed.registered_domain == "my-phish.github.io"
    assert parsed.subdomain == ""


def test_ip_literal_formats() -> None:
    # Standard IPv4
    p1 = canonicalize("http://192.168.1.1/admin")
    assert p1.is_ip is True
    assert p1.ip_address == "192.168.1.1"
    assert p1.is_private_ip is True

    # Decimal 32-bit IP (2130706433 -> 127.0.0.1)
    p2 = canonicalize("http://2130706433/test")
    assert p2.is_ip is True
    assert p2.ip_address == "127.0.0.1"
    assert p2.is_private_ip is True

    # Hex IP (0x7f000001 -> 127.0.0.1)
    p3 = canonicalize("http://0x7f000001/test")
    assert p3.is_ip is True
    assert p3.ip_address == "127.0.0.1"


def test_idn_and_punycode_conversion() -> None:
    idn_url = "https://münchen.de/news"
    parsed = canonicalize(idn_url)
    assert parsed.is_idn is True
    assert "xn--mnchen-3ya.de" in parsed.punycode_host

    puny_url = "https://xn--mnchen-3ya.de/news"
    parsed_puny = canonicalize(puny_url)
    assert parsed_puny.has_punycode is True
    assert parsed_puny.host == "münchen.de"


def test_path_normalization() -> None:
    url = "https://example.com/a/b/../c/./d"
    parsed = canonicalize(url)
    assert parsed.path == "/a/c/d"


def test_double_encoding_detection() -> None:
    normal = "https://example.com/search?q=hello%20world"
    assert canonicalize(normal).has_double_encoding is False

    double = "https://example.com/search?q=hello%2520world"
    assert canonicalize(double).has_double_encoding is True


def test_scheme_inference() -> None:
    parsed = canonicalize("example.com/login")
    assert parsed.scheme_inferred is True
    assert parsed.scheme == "http"
    assert parsed.host == "example.com"


def test_invalid_urls() -> None:
    with pytest.raises(InvalidUrlError):
        canonicalize("")

    with pytest.raises(InvalidUrlError):
        canonicalize("ftp://ftp.example.com/file")

    with pytest.raises(InvalidUrlError):
        canonicalize("a" * 8193)


# --- Property-Based Tests (Hypothesis) ---


@given(st.from_regex(r"https?://[a-z0-9-]{1,30}\.[a-z]{2,6}(/[a-z0-9_-]{0,20})*", fullmatch=True))
@settings(max_examples=100)
def test_canonicalization_idempotence(url: str) -> None:
    """Property test: canonicalize(canonicalize(u).canonical) == canonicalize(u).canonical."""
    parsed1 = canonicalize(url)
    parsed2 = canonicalize(parsed1.canonical)
    assert parsed1.canonical == parsed2.canonical


@given(st.text(max_size=300))
@settings(max_examples=100)
def test_no_unexpected_crashes_on_arbitrary_strings(text: str) -> None:
    """Property test: canonicalize on arbitrary text either returns ParsedUrl or raises InvalidUrlError."""
    try:
        res = canonicalize(text)
        assert isinstance(res.canonical, str)
    except InvalidUrlError:
        pass

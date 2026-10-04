"""URL parsing, validation, and canonicalization engine for PhishGuard AI.

Implements ARCHITECTURE.md §5.3, RULES R-SEC-1, R-SEC-2, R-SEC-3, and R-TEST-4.
Strictly offline: uses bundled Public Suffix List (PSL) with private domains included.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import tldextract

# Maximum allowed URL lengths per RULES R-SEC-2
MAX_URL_LEN = 2048
HARD_MAX_URL_LEN = 8192

# Safe unreserved characters in URI path (RFC 3986 §2.3)
UNRESERVED_PAT = re.compile(r"%([0-9a-fA-F]{2})")

# Extract extractor instance offline
_EXTRACTOR = tldextract.TLDExtract(
    include_psl_private_domains=True,
    suffix_list_urls=(),  # strictly offline, uses bundled list
)


class InvalidUrlError(ValueError):
    """Raised when a URL violates length limits or basic protocol requirements."""

    pass


@dataclass(frozen=True)
class ParsedUrl:
    """Structured representation of a parsed and canonicalized URL."""

    raw: str
    canonical: str
    scheme: str
    netloc: str
    host: str
    port: int | None
    registered_domain: str
    subdomain: str
    suffix: str
    path: str
    query: str
    fragment: str

    # Security and anomaly flags
    scheme_inferred: bool = False
    has_userinfo: bool = False
    userinfo: str = ""
    is_ip: bool = False
    ip_address: str | None = None
    is_private_ip: bool = False
    is_idn: bool = False
    punycode_host: str = ""
    is_mixed_script: bool = False
    has_punycode: bool = False
    has_double_encoding: bool = False
    fragment_has_url: bool = False
    is_valid: bool = True
    error_message: str | None = None


def _detect_mixed_script(label: str) -> bool:
    """Detect if a single label mixes distinct alphabetic scripts (e.g. Latin + Cyrillic)."""
    scripts: set[str] = set()
    for ch in label:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            # Extract script from first word of character name
            first_word = name.split()[0] if name else ""
            if first_word in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "DEVANAGARI"):
                scripts.add(first_word)
    return len(scripts) > 1


def _normalize_ip(host: str) -> tuple[bool, str | None, bool]:
    """Check if host is an IP literal (IPv4 or IPv6) in dotted, decimal, or hex form.

    Returns (is_ip, normalized_ip_str, is_private).
    """
    clean_host = host.strip("[]")

    # Try direct parsing (dotted-quad or IPv6)
    try:
        ip = ipaddress.ip_address(clean_host)
        is_private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        return True, str(ip), is_private
    except ValueError:
        pass

    # Try 32-bit integer / octal / hex literal IPv4 (e.g., 2130706433 or 0x7f000001)
    if re.match(r"^(0x[0-9a-fA-F]+|[0-9]+)$", clean_host):
        try:
            num = int(clean_host, 0)
            if 0 <= num <= 0xFFFFFFFF:
                ip = ipaddress.IPv4Address(num)
                is_private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                return True, str(ip), is_private
        except (ValueError, OverflowError):
            pass

    return False, None, False


def _percent_decode_unreserved(text: str) -> tuple[str, bool]:
    """Decode unreserved percent-encoded bytes (RFC 3986) and detect double encoding."""
    has_double_encoding = False
    if "%25" in text.lower():
        has_double_encoding = True

    def replace_unreserved(m: re.Match[str]) -> str:
        hex_val = m.group(1)
        byte_val = int(hex_val, 16)
        # RFC 3986 unreserved: ALPHA, DIGIT, '-', '.', '_', '~'
        char = chr(byte_val)
        if (
            (65 <= byte_val <= 90)  # A-Z
            or (97 <= byte_val <= 122)  # a-z
            or (48 <= byte_val <= 57)  # 0-9
            or char in "-._~"
        ):
            return char
        return m.group(0)

    decoded = UNRESERVED_PAT.sub(replace_unreserved, text)
    return decoded, has_double_encoding


def canonicalize(url: str) -> ParsedUrl:
    """Validate, parse, and canonicalize a URL string.

    Performs RFC-compliant normalization, Unicode NFKC, IDN punycode conversion,
    userinfo extraction, path normalization, and PSL-aware domain decomposition.
    """
    if not isinstance(url, str):
        url = str(url)

    # 1. Strip whitespace and control characters
    stripped = "".join(ch for ch in url.strip() if ord(ch) >= 32 and ord(ch) != 127)

    if not stripped:
        raise InvalidUrlError("Empty URL")

    if len(stripped) > HARD_MAX_URL_LEN:
        raise InvalidUrlError(f"URL exceeds maximum allowed length of {HARD_MAX_URL_LEN} chars")

    scheme_inferred = False
    # 2. Add scheme if missing and input looks like a web host or path
    url_to_parse = stripped
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_to_parse):
        url_to_parse = "http://" + url_to_parse
        scheme_inferred = True

    # 3. Parse with urlsplit
    try:
        parts = urlsplit(url_to_parse)
    except Exception as exc:
        raise InvalidUrlError(f"Malformed URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        # For non-http schemes, mark or reject per L0
        raise InvalidUrlError(f"Unsupported scheme: {scheme}")

    netloc = parts.netloc
    if not netloc:
        raise InvalidUrlError("URL missing hostname / netloc")

    # 4. Userinfo detection (Real host is after the last '@' in netloc)
    has_userinfo = False
    userinfo = ""
    host_port = netloc
    if "@" in netloc:
        has_userinfo = True
        userinfo, host_port = netloc.rsplit("@", 1)

    # Split host and port
    port: int | None = None
    if ":" in host_port and not host_port.endswith("]"):
        # Check if port is specified
        h, _sep, p_str = host_port.rpartition(":")
        if p_str.isdigit():
            port = int(p_str)
            host = h
        else:
            host = host_port
    else:
        host = host_port

    # 5. Host normalization: strip brackets for IPv6, strip trailing dots, lowercase
    host = host.strip(".").lower()

    # Unicode NFKC normalization
    host = unicodedata.normalize("NFKC", host)

    # IDN & Punycode handling
    is_idn = False
    has_punycode = False
    punycode_host = host
    is_mixed_script = False

    try:
        # Check if host contains non-ASCII characters
        if any(ord(c) > 127 for c in host):
            is_idn = True
            punycode_host = host.encode("idna").decode("ascii")
        elif "xn--" in host:
            has_punycode = True
            punycode_host = host
            try:
                host = punycode_host.encode("ascii").decode("idna")
                is_idn = True
            except Exception:
                pass
    except Exception:
        # Fallback if IDNA encoding fails
        punycode_host = host

    # Check mixed script on labels
    for label in host.split("."):
        if _detect_mixed_script(label):
            is_mixed_script = True
            break

    # 6. Check IP literal
    is_ip, normalized_ip, is_private_ip = _normalize_ip(host)
    if is_ip and normalized_ip:
        host = normalized_ip
        punycode_host = normalized_ip

    # 7. Drop default ports
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    canonical_netloc = host if port is None else f"{host}:{port}"
    if has_userinfo:
        # Userinfo retained in netloc with '@'
        canonical_netloc = f"{userinfo}@{canonical_netloc}"

    # 8. Path normalization: resolve dot segments & decode unreserved
    path = parts.path
    if not path:
        path = "/"
    path = posixpath.normpath(path)
    # Ensure preserved trailing slash if present originally
    if parts.path.endswith("/") and not path.endswith("/"):
        path += "/"

    path, path_has_double_enc = _percent_decode_unreserved(path)

    # 9. Query & Fragment
    query, query_has_double_enc = _percent_decode_unreserved(parts.query)
    has_double_encoding = path_has_double_enc or query_has_double_enc

    fragment = parts.fragment
    fragment_has_url = bool(re.search(r"https?://", fragment, re.IGNORECASE))

    # Reconstruct canonical URL (fragment dropped for canonical scoring URL per ARCH §5.3)
    canonical = urlunsplit((scheme, canonical_netloc, path, query, ""))

    # 10. PSL registered domain and subdomain extraction (using private PSL)
    subdomain = ""
    registered_domain = host
    suffix = ""

    if not is_ip:
        ext = _EXTRACTOR(punycode_host)
        suffix = ext.suffix
        registered_domain = ext.top_domain_under_public_suffix or host
        subdomain = ext.subdomain

    return ParsedUrl(
        raw=url,
        canonical=canonical,
        scheme=scheme,
        netloc=canonical_netloc,
        host=host,
        port=port,
        registered_domain=registered_domain,
        subdomain=subdomain,
        suffix=suffix,
        path=path,
        query=query,
        fragment=fragment,
        scheme_inferred=scheme_inferred,
        has_userinfo=has_userinfo,
        userinfo=userinfo,
        is_ip=is_ip,
        ip_address=normalized_ip,
        is_private_ip=is_private_ip,
        is_idn=is_idn,
        punycode_host=punycode_host,
        is_mixed_script=is_mixed_script,
        has_punycode=has_punycode,
        has_double_encoding=has_double_encoding,
        fragment_has_url=fragment_has_url,
        is_valid=True,
    )

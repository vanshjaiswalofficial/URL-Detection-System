"""Feature extraction engine for PhishGuard AI.

Implements ARCHITECTURE.md §6 and TASKS T2.1, T2.2, T2.3.
Per RULES R-CODE-5: This is the SINGLE canonical feature extraction code path
used for both offline training and online serving.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import asdict, dataclass

from phishguard_core.brands import SUSPICIOUS_KEYWORDS, get_brand_matcher
from phishguard_core.url import ParsedUrl, canonicalize

# Common URL shortener services
SHORTENER_DOMAINS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "cutt.ly",
        "rebrand.ly",
        "tiny.cc",
    }
)

# Known multi-tenant hosts (ARCHITECTURE §4.2, D-011)
MULTITENANT_HOSTS: frozenset[str] = frozenset(
    {
        "github.io",
        "web.app",
        "firebaseapp.com",
        "pages.dev",
        "vercel.app",
        "netlify.app",
        "blogspot.com",
        "sharepoint.com",
        "notion.site",
        "wordpress.com",
        "wixsite.com",
        "weebly.com",
        "glitch.me",
        "render.com",
        "railway.app",
        "fly.dev",
        "supabase.co",
        "azurewebsites.net",
        "s3.amazonaws.com",
        "storage.googleapis.com",
        "blob.core.windows.net",
    }
)


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string (in bits)."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


@dataclass(frozen=True)
class UrlFeatures:
    """Numerical and boolean features extracted from a URL."""

    # Length & counts
    url_len: int
    host_len: int
    path_len: int
    query_len: int
    n_dots: int
    n_hyphens: int
    n_underscores: int
    n_digits: int
    n_special: int
    n_params: int
    path_depth: int
    n_subdomains: int

    # Ratios & entropy
    digit_ratio: float
    letter_ratio: float
    uppercase_ratio: float
    special_ratio: float
    entropy_url: float
    entropy_host: float
    entropy_path: float
    longest_token_len: int
    avg_token_len: float
    vowel_ratio: float

    # Host structure
    is_ip_host: int
    is_private_ip: int
    has_port: int
    has_userinfo: int
    is_idn: int
    is_mixed_script: int
    has_punycode: int
    has_double_encoding: int
    is_multitenant_host: int
    is_shortener: int
    label_count: int
    subdomain_len: int

    # Brand & lookalike
    brand_in_subdomain: int
    brand_in_path: int
    typosquat_detected: int
    combosquat_detected: int
    min_brand_edit_distance: int

    # Lexical keywords
    suspicious_keyword_count: int
    keyword_in_path: int
    keyword_in_subdomain: int

    # Obfuscation
    pct_encoded_ratio: float
    has_base64_like_token: int
    has_hex_blob: int
    double_slash_in_path: int
    at_symbol_in_query: int
    url_in_query: int
    long_random_subdomain: int


def extract_features_from_parsed(parsed: ParsedUrl) -> UrlFeatures:
    """Extract tabular features from an already canonicalized ParsedUrl."""
    url = parsed.canonical
    url_len = max(len(url), 1)
    host = parsed.host
    host_len = len(host)
    path = parsed.path
    path_len = len(path)
    query = parsed.query
    query_len = len(query)

    # 1. Counts
    n_dots = url.count(".")
    n_hyphens = url.count("-")
    n_underscores = url.count("_")
    n_digits = sum(ch.isdigit() for ch in url)
    n_letters = sum(ch.isalpha() for ch in url)
    n_uppercase = sum(ch.isupper() for ch in parsed.raw)
    n_special = url_len - (n_digits + n_letters)

    n_params = len(query.split("&")) if query else 0
    path_depth = len([seg for seg in path.split("/") if seg])
    subdomain_parts = [p for p in parsed.subdomain.split(".") if p]
    n_subdomains = len(subdomain_parts)

    # 2. Ratios
    digit_ratio = round(n_digits / url_len, 4)
    letter_ratio = round(n_letters / url_len, 4)
    uppercase_ratio = round(n_uppercase / max(len(parsed.raw), 1), 4)
    special_ratio = round(n_special / url_len, 4)

    # Vowels
    vowels = set("aeiouAEIOU")
    vowel_count = sum(ch in vowels for ch in url)
    vowel_ratio = round(vowel_count / max(n_letters, 1), 4)

    # Tokens across path and query
    tokens = [t for t in re.split(r"[/.\-_?=&]", f"{path}?{query}") if t]
    longest_token_len = max((len(t) for t in tokens), default=0)
    avg_token_len = round(sum(len(t) for t in tokens) / len(tokens), 2) if tokens else 0.0

    # 3. Host structure
    is_multitenant = int(
        parsed.suffix in MULTITENANT_HOSTS or parsed.registered_domain in MULTITENANT_HOSTS
    )
    is_shortener = int(parsed.registered_domain in SHORTENER_DOMAINS)
    labels = host.split(".")
    label_count = len(labels)
    subdomain_len = len(parsed.subdomain)

    # 4. Brand analysis
    brand_matcher = get_brand_matcher()
    brand_res = brand_matcher.analyze(
        registered_domain=parsed.registered_domain,
        subdomain=parsed.subdomain,
        path=path,
        query=query,
    )

    # 5. Keywords
    kw_count = 0
    kw_in_path = 0
    kw_in_sub = 0
    url_lower = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            kw_count += 1
            if kw in path.lower():
                kw_in_path = 1
            if kw in parsed.subdomain.lower():
                kw_in_sub = 1

    # 6. Obfuscation
    pct_encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    pct_encoded_ratio = round((pct_encoded_count * 3) / url_len, 4)

    # Base64-like token (>= 16 chars base64 charset)
    has_base64 = int(bool(re.search(r"[A-Za-z0-9+/]{20,}={0,2}", url)))
    # Hex blob (>= 16 chars hex)
    has_hex = int(bool(re.search(r"[0-9a-fA-F]{16,}", url)))
    double_slash = int("//" in path)
    at_query = int("@" in query)
    url_in_query = int(bool(re.search(r"https?://", query, re.IGNORECASE)))
    long_random_sub = int(len(parsed.subdomain) >= 18 and shannon_entropy(parsed.subdomain) >= 3.5)

    return UrlFeatures(
        url_len=url_len,
        host_len=host_len,
        path_len=path_len,
        query_len=query_len,
        n_dots=n_dots,
        n_hyphens=n_hyphens,
        n_underscores=n_underscores,
        n_digits=n_digits,
        n_special=n_special,
        n_params=n_params,
        path_depth=path_depth,
        n_subdomains=n_subdomains,
        digit_ratio=digit_ratio,
        letter_ratio=letter_ratio,
        uppercase_ratio=uppercase_ratio,
        special_ratio=special_ratio,
        entropy_url=shannon_entropy(url),
        entropy_host=shannon_entropy(host),
        entropy_path=shannon_entropy(path),
        longest_token_len=longest_token_len,
        avg_token_len=avg_token_len,
        vowel_ratio=vowel_ratio,
        is_ip_host=int(parsed.is_ip),
        is_private_ip=int(parsed.is_private_ip),
        has_port=int(parsed.port is not None),
        has_userinfo=int(parsed.has_userinfo),
        is_idn=int(parsed.is_idn),
        is_mixed_script=int(parsed.is_mixed_script),
        has_punycode=int(parsed.has_punycode),
        has_double_encoding=int(parsed.has_double_encoding),
        is_multitenant_host=is_multitenant,
        is_shortener=is_shortener,
        label_count=label_count,
        subdomain_len=subdomain_len,
        brand_in_subdomain=int(brand_res.brand_in_subdomain_not_regdomain),
        brand_in_path=int(brand_res.brand_in_path_not_regdomain),
        typosquat_detected=int(brand_res.typosquat_detected),
        combosquat_detected=int(brand_res.combosquat_detected),
        min_brand_edit_distance=min(brand_res.min_edit_distance, 20),
        suspicious_keyword_count=kw_count,
        keyword_in_path=kw_in_path,
        keyword_in_subdomain=kw_in_sub,
        pct_encoded_ratio=pct_encoded_ratio,
        has_base64_like_token=has_base64,
        has_hex_blob=has_hex,
        double_slash_in_path=double_slash,
        at_symbol_in_query=at_query,
        url_in_query=url_in_query,
        long_random_subdomain=long_random_sub,
    )


def extract_features(url: str) -> UrlFeatures:
    """Convenience helper to canonicalize and extract features in one step."""
    parsed = canonicalize(url)
    return extract_features_from_parsed(parsed)


def features_to_dict(features: UrlFeatures) -> dict[str, float | int]:
    """Convert UrlFeatures dataclass to a dictionary suitable for DataFrame/LightGBM."""
    return asdict(features)


# Sorted list of feature names for model feature alignment
FEATURE_NAMES: list[str] = sorted(list(asdict(extract_features("http://example.com")).keys()))

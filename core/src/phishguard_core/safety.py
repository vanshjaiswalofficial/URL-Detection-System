"""Safety utilities for PhishGuard AI.

Implements defanging, refanging, query redaction, and hashing for URLs
without performing any network I/O (per RULES R-SAF-4, R-PRIV-1, R-PRIV-2).
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit


def defang(url: str) -> str:
    """Defang a URL or host to prevent accidental clicking / execution.

    Transforms:
      - 'https://' -> 'hxxps://'
      - 'http://'  -> 'hxxp://'
      - Hostname dots '.' -> '[.]'

    Example:
      >>> defang("https://evil.example.com/login?u=1")
      'hxxps://evil[.]example[.]com/login?u=1'
    """
    if not url:
        return ""

    # Parse scheme and rest
    match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)(://)(.*)$", url, re.DOTALL)
    if match:
        scheme, sep, rest = match.groups()
        lower_scheme = scheme.lower()
        if lower_scheme == "http":
            scheme = "hxxp"
        elif lower_scheme == "https":
            scheme = "hxxps"

        # Split rest into authority/host and path/query/fragment
        # Authority ends at first '/', '?', or '#'
        auth_match = re.match(r"^([^/?#]*)(.*)$", rest, re.DOTALL)
        if auth_match:
            authority, tail = auth_match.groups()
            defanged_auth = authority.replace(".", "[.]")
            return f"{scheme}{sep}{defanged_auth}{tail}"
        return f"{scheme}{sep}{rest.replace('.', '[.]')}"

    # If no scheme, defang the string directly
    # If it contains a path, only defang the host part
    auth_match = re.match(r"^([^/?#]*)(.*)$", url, re.DOTALL)
    if auth_match:
        authority, tail = auth_match.groups()
        return authority.replace(".", "[.]") + tail
    return url.replace(".", "[.]")


def refang(url: str) -> str:
    """Restore a defanged URL back to its standard clickable / machine form.

    Transforms:
      - 'hxxps://' -> 'https://'
      - 'hxxp://'  -> 'http://'
      - '[.]' or '(.)' -> '.'
      - '[:]' -> ':'
      - '[/]' -> '/'

    Example:
      >>> refang("hxxps://evil[.]example[.]com/login")
      'https://evil.example.com/login'
    """
    if not url:
        return ""

    res = url
    res = re.sub(r"^hxxps://", "https://", res, flags=re.IGNORECASE)
    res = re.sub(r"^hxxp://", "http://", res, flags=re.IGNORECASE)
    res = res.replace("[.]", ".").replace("(.)", ".")
    res = res.replace("[:]", ":").replace("(:)", ":")
    res = res.replace("[/]", "/").replace("(/)", "/")
    return res


def redact_query(url: str) -> str:
    """Remove query parameters and fragments from a URL for privacy.

    Per RULES R-PRIV-1 and R-PRIV-2, stripped URLs protect user confidentiality.

    Example:
      >>> redact_query("https://example.com/login?token=secret#section")
      'https://example.com/login'
    """
    if not url:
        return ""

    try:
        parts = urlsplit(url)
        # Drop query and fragment
        redacted = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        return redacted
    except Exception:
        # Fallback regex if urlsplit fails on malformed input
        return re.sub(r"[?#].*$", "", url)


def sha256_url(url: str) -> str:
    """Calculate the lowercase SHA-256 hexadecimal hash of a URL string.

    Example:
      >>> sha256_url("https://example.com")
      '100680ad546ce6a577f42f52df33b4cfdca756859e664b8d7fa3e015ecd367d8'
    """
    return hashlib.sha256(url.encode("utf-8")).hexdigest()

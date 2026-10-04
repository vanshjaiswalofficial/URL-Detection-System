"""Explainability and human-readable reason mapping for PhishGuard AI.

Implements ARCHITECTURE.md §9 and DESIGN.md §8 (TASK T3.5):
Maps model feature contributions and rule hits to plain-language reasons
linked to URL anatomy segments.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from phishguard_core.features import UrlFeatures
from phishguard_core.url import ParsedUrl


@dataclass(frozen=True)
class Reason:
    """A human-readable reason explaining why a URL received a risk score."""
    code: str
    severity: str  # "high", "medium", "low"
    text: str
    target_segment: str | None = None  # "scheme", "subdomain", "registered_domain", "suffix", "path", "query", "host"
    evidence: dict[str, Any] | None = None


# Default reason definitions if reasons.yaml is missing
DEFAULT_REASONS: dict[str, dict[str, str]] = {
    "brand_in_subdomain_not_regdomain": {
        "severity": "high",
        "text": "The name of a well-known brand appears in the address, but the site isn't run by that brand.",
        "target_segment": "subdomain",
    },
    "brand_in_path_not_regdomain": {
        "severity": "high",
        "text": "The address uses a brand name in its path on an unrelated website.",
        "target_segment": "path",
    },
    "typosquat_brand": {
        "severity": "high",
        "text": "The domain looks like a misspelling of a popular site.",
        "target_segment": "registered_domain",
    },
    "combosquat_brand": {
        "severity": "high",
        "text": "The address combines a popular brand name with suspicious keywords like login or verify.",
        "target_segment": "registered_domain",
    },
    "ip_host": {
        "severity": "high",
        "text": "The address uses numbers instead of a name, which real services rarely do.",
        "target_segment": "host",
    },
    "userinfo_trick": {
        "severity": "high",
        "text": "Part of the address before an '@' is hiding the real destination.",
        "target_segment": "host",
    },
    "punycode_mixed_script": {
        "severity": "medium",
        "text": "The address mixes letters from different alphabets that look alike.",
        "target_segment": "host",
    },
    "long_random_subdomain": {
        "severity": "medium",
        "text": "The address has a long string of random-looking characters.",
        "target_segment": "subdomain",
    },
    "high_entropy": {
        "severity": "medium",
        "text": "The web address contains an unusually high amount of random or obfuscated text.",
        "target_segment": "registered_domain",
    },
    "excessive_subdomains": {
        "severity": "medium",
        "text": "The address contains multiple levels of subdomains attempting to deceive readers.",
        "target_segment": "subdomain",
    },
    "suspicious_keywords": {
        "severity": "medium",
        "text": "The address asks you to sign in, verify, or update account credentials.",
        "target_segment": "path",
    },
    "feed_hit": {
        "severity": "high",
        "text": "This address was reported as a scam by a threat-intelligence source.",
        "target_segment": "registered_domain",
    },
    "user_denylist": {
        "severity": "high",
        "text": "This address matches a domain in your personal blocklist.",
        "target_segment": "registered_domain",
    },
}


class ReasonMapper:
    """Maps URL features and inference contributions to structured explanation reasons."""

    def __init__(self, catalog_path: Path | str | None = None) -> None:
        self.catalog = dict(DEFAULT_REASONS)
        if catalog_path:
            p = Path(catalog_path)
            if p.exists():
                try:
                    with open(p, encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    if data and "reasons" in data:
                        for k, v in data["reasons"].items():
                            self.catalog[k] = v
                except Exception:
                    pass

    def build_reason(self, code: str, evidence: dict[str, Any] | None = None) -> Reason:
        info = self.catalog.get(code, {})
        severity = info.get("severity", "medium")
        text = info.get("text", f"Suspicious indicator detected: {code}.")
        target_segment = info.get("target_segment", "host")
        return Reason(
            code=code,
            severity=severity,
            text=text,
            target_segment=target_segment,
            evidence=evidence,
        )

    def extract_reasons(
        self,
        parsed: ParsedUrl,
        features: UrlFeatures,
        contributions: dict[str, float] | None = None,
        max_reasons: int = 5,
    ) -> list[Reason]:
        """Extract prioritized reasons for a scan verdict."""
        reasons: list[Reason] = []
        seen_codes: set[str] = set()

        def add_code(code: str, evidence: dict[str, Any] | None = None) -> None:
            if code not in seen_codes:
                seen_codes.add(code)
                reasons.append(self.build_reason(code, evidence))

        # 1. Structural / Brand rule triggers (Highest precision)
        if features.brand_in_subdomain:
            add_code("brand_in_subdomain_not_regdomain", {"subdomain": parsed.subdomain})

        if features.brand_in_path:
            add_code("brand_in_path_not_regdomain", {"path": parsed.path})

        if features.typosquat_detected:
            add_code("typosquat_brand", {"registered_domain": parsed.registered_domain})

        if features.combosquat_detected:
            add_code("combosquat_brand", {"registered_domain": parsed.registered_domain})

        if features.is_ip_host:
            add_code("ip_host", {"ip": parsed.host})

        if features.has_userinfo:
            add_code("userinfo_trick", {"userinfo": parsed.userinfo})

        if features.is_mixed_script or features.has_punycode:
            add_code("punycode_mixed_script", {"host": parsed.punycode_host})

        if features.long_random_subdomain:
            add_code("long_random_subdomain", {"subdomain": parsed.subdomain})

        if features.n_subdomains >= 3:
            add_code("excessive_subdomains", {"n_subdomains": features.n_subdomains})

        if features.suspicious_keyword_count >= 1 and (features.keyword_in_path or features.keyword_in_subdomain):
            add_code("suspicious_keywords")

        if features.entropy_url >= 4.2:
            add_code("high_entropy", {"entropy": features.entropy_url})

        # 2. Check model contributions if available (e.g. from LightGBM pred_contrib)
        if contributions:
            # Sort positive contributors (features that pushed risk up)
            pos_contribs = sorted(
                [(k, v) for k, v in contributions.items() if v > 0.05 and k not in seen_codes],
                key=lambda x: x[1],
                reverse=True,
            )
            for feat_name, val in pos_contribs:
                if len(reasons) >= max_reasons:
                    break
                if feat_name in self.catalog and feat_name not in seen_codes:
                    add_code(feat_name, {"contribution": round(val, 3)})

        return reasons[:max_reasons]


# Default module-level mapper
_DEFAULT_MAPPER: ReasonMapper | None = None


def get_reason_mapper() -> ReasonMapper:
    global _DEFAULT_MAPPER
    if _DEFAULT_MAPPER is None:
        p = Path(__file__).parent / "reasons.yaml"
        _DEFAULT_MAPPER = ReasonMapper(p if p.exists() else None)
    return _DEFAULT_MAPPER

"""Brand and lookalike feature extraction for PhishGuard AI.

Implements ARCHITECTURE.md §6 and TASK T2.2:
- Detection of brand impersonation in subdomain, path, or query
- Typosquatting distance via rapidfuzz
- Homoglyph skeleton normalization
- Combosquatting patterns (brand + suspicious keyword)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from rapidfuzz.distance import Levenshtein

# Standard homoglyph / leetspeak character substitutions
HOMOGLYPH_MAP: dict[str, str] = {
    "0": "o",
    "1": "l",
    "!": "i",
    "|": "l",
    "@": "a",
    "$": "s",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
    "vv": "w",
    "rn": "m",
    "cl": "d",
}

# Suspicious security / account keywords often combined with brand names
SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "wallet",
    "bank",
    "banking",
    "invoice",
    "payment",
    "password",
    "support",
    "service",
    "portal",
    "auth",
    "authenticate",
    "billing",
)

# Default brands catalog in case external YAML file is absent
DEFAULT_BRANDS: list[dict[str, Any]] = [
    {"name": "paypal", "canonical_domain": "paypal.com", "aliases": ["paypal"]},
    {
        "name": "microsoft",
        "canonical_domain": "microsoft.com",
        "aliases": ["microsoft", "office365", "outlook", "live", "azure"],
    },
    {"name": "apple", "canonical_domain": "apple.com", "aliases": ["apple", "icloud"]},
    {"name": "google", "canonical_domain": "google.com", "aliases": ["google", "gmail", "youtube"]},
    {"name": "amazon", "canonical_domain": "amazon.com", "aliases": ["amazon", "primevideo"]},
    {"name": "netflix", "canonical_domain": "netflix.com", "aliases": ["netflix"]},
    {"name": "chase", "canonical_domain": "chase.com", "aliases": ["chase"]},
    {"name": "wellsfargo", "canonical_domain": "wellsfargo.com", "aliases": ["wellsfargo"]},
    {
        "name": "bankofamerica",
        "canonical_domain": "bankofamerica.com",
        "aliases": ["bankofamerica", "bofa"],
    },
    {
        "name": "facebook",
        "canonical_domain": "facebook.com",
        "aliases": ["facebook", "meta", "instagram", "whatsapp"],
    },
    {"name": "binance", "canonical_domain": "binance.com", "aliases": ["binance"]},
    {"name": "coinbase", "canonical_domain": "coinbase.com", "aliases": ["coinbase"]},
    {"name": "steam", "canonical_domain": "steampowered.com", "aliases": ["steam", "steampowered"]},
    {"name": "dhl", "canonical_domain": "dhl.com", "aliases": ["dhl"]},
]


@dataclass(frozen=True)
class BrandTarget:
    name: str
    canonical_domain: str
    aliases: list[str]


@dataclass(frozen=True)
class BrandAnalysisResult:
    brand_in_subdomain_not_regdomain: bool = False
    brand_in_path_not_regdomain: bool = False
    typosquat_detected: bool = False
    combosquat_detected: bool = False
    closest_brand: str | None = None
    min_edit_distance: int = 999
    matched_brand_name: str | None = None


def compute_skeleton(text: str) -> str:
    """Normalize text by replacing common homoglyphs and leetspeak numbers."""
    s = text.lower()
    for search, replace in HOMOGLYPH_MAP.items():
        s = s.replace(search, replace)
    return s


class BrandMatcher:
    """Matches URLs against curated target brand names."""

    def __init__(self, brands_file: Path | str | None = None) -> None:
        self.brands: list[BrandTarget] = []
        loaded = False

        if brands_file:
            path = Path(brands_file)
            if path.exists():
                try:
                    with open(path, encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    if data and "brands" in data:
                        for entry in data["brands"]:
                            self.brands.append(
                                BrandTarget(
                                    name=entry["name"].lower(),
                                    canonical_domain=entry["canonical_domain"].lower(),
                                    aliases=[
                                        a.lower() for a in entry.get("aliases", [entry["name"]])
                                    ],
                                )
                            )
                        loaded = True
                except Exception:
                    loaded = False

        if not loaded:
            for entry in DEFAULT_BRANDS:
                self.brands.append(
                    BrandTarget(
                        name=entry["name"],
                        canonical_domain=entry["canonical_domain"],
                        aliases=entry["aliases"],
                    )
                )

    def analyze(
        self,
        registered_domain: str,
        subdomain: str,
        path: str,
        query: str,
    ) -> BrandAnalysisResult:
        """Analyze URL components for brand impersonation or typosquatting."""
        reg_domain_clean = registered_domain.lower()
        subdomain_clean = subdomain.lower()
        path_clean = path.lower()
        query_clean = query.lower()

        # Extract SLD (second-level domain) label of registered domain (e.g., 'example' from 'example.com')
        reg_labels = reg_domain_clean.split(".")
        sld = reg_labels[0] if reg_labels else reg_domain_clean
        sld_skeleton = compute_skeleton(sld)

        brand_in_subdomain = False
        brand_in_path = False
        typosquat_detected = False
        combosquat_detected = False
        closest_brand: str | None = None
        min_dist = 999
        matched_brand: str | None = None

        # Tokens in SLD (e.g. ['paypa1', 'support'] from 'paypa1-support')
        sld_tokens = [t for t in re.split(r"[-_]", sld) if t]
        sld_skeleton_tokens = [compute_skeleton(t) for t in sld_tokens]

        for b in self.brands:
            is_legit_domain = reg_domain_clean == b.canonical_domain or reg_domain_clean.endswith(
                "." + b.canonical_domain
            )

            for alias in b.aliases:
                alias_len = len(alias)
                if alias_len < 3:
                    continue

                # 1. Typosquatting / homoglyph distance to SLD or SLD tokens
                # Compare full SLD
                dists = [
                    Levenshtein.distance(sld, alias),
                    Levenshtein.distance(sld_skeleton, alias),
                ]
                # Also compare each token inside SLD (e.g., 'paypa1' inside 'paypa1-support')
                for tok, tok_skel in zip(sld_tokens, sld_skeleton_tokens, strict=False):
                    dists.append(Levenshtein.distance(tok, alias))
                    dists.append(Levenshtein.distance(tok_skel, alias))

                best_dist = min(dists)

                if best_dist < min_dist:
                    min_dist = best_dist
                    closest_brand = b.name

                # If edit distance is 1 or 2 (for longer brand names) and it is NOT legitimate brand domain
                if not is_legit_domain:
                    # Exact homoglyph match (distance 0 after skeleton, but was not equal before)
                    has_homoglyph_match = any(
                        (tok != alias and tok_skel == alias)
                        for tok, tok_skel in zip(sld_tokens, sld_skeleton_tokens, strict=False)
                    ) or (sld != alias and sld_skeleton == alias)

                    if (
                        has_homoglyph_match
                        or (best_dist == 1 and alias_len >= 4)
                        or (best_dist == 2 and alias_len >= 7)
                    ):
                        typosquat_detected = True
                        matched_brand = b.name

                # 2. Check Combosquatting: brand (or skeleton) + suspicious keyword inside SLD
                if not is_legit_domain and (alias in sld or alias in sld_skeleton):
                    for kw in SUSPICIOUS_KEYWORDS:
                        if kw in sld_skeleton and (
                            f"{alias}-{kw}" in sld_skeleton
                            or f"{alias}{kw}" in sld_skeleton
                            or f"{kw}-{alias}" in sld_skeleton
                        ):
                            combosquat_detected = True
                            matched_brand = b.name
                            break

                # 3. Check Brand in Subdomain when registered domain is not the brand's domain
                if not is_legit_domain and subdomain_clean:
                    # Look for exact alias token in subdomain (separated by . or -)
                    tokens = re.split(r"[.\-_]", subdomain_clean)
                    if alias in tokens:
                        brand_in_subdomain = True
                        matched_brand = b.name

                # 4. Check Brand in Path or Query
                if not is_legit_domain and (path_clean or query_clean):
                    path_tokens = re.split(r"[/.\-_?=&#]", f"{path_clean}?{query_clean}")
                    if alias in path_tokens:
                        brand_in_path = True
                        if not matched_brand:
                            matched_brand = b.name

        return BrandAnalysisResult(
            brand_in_subdomain_not_regdomain=brand_in_subdomain,
            brand_in_path_not_regdomain=brand_in_path,
            typosquat_detected=typosquat_detected,
            combosquat_detected=combosquat_detected,
            closest_brand=closest_brand,
            min_edit_distance=min_dist,
            matched_brand_name=matched_brand,
        )


# Global singleton matcher with default / discovery search
_MATCHER: BrandMatcher | None = None


def get_brand_matcher() -> BrandMatcher:
    global _MATCHER
    if _MATCHER is None:
        candidate_paths = [
            Path("data/lists/brands.yaml"),
            Path(__file__).parent.parent.parent.parent / "data" / "lists" / "brands.yaml",
        ]
        chosen: Path | None = None
        for p in candidate_paths:
            if p.exists():
                chosen = p
                break
        _MATCHER = BrandMatcher(chosen)
    return _MATCHER

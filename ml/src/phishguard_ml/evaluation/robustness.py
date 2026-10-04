"""Defensive adversarial robustness evaluation suite (TASK T3.3).

Per RULES R-SAF-3 and ARCHITECTURE.md §8:
- String-level perturbations of phishing URLs for defensive benchmarking only.
- Evaluates model degradation against common evasion tactics:
  1. Homoglyphs (Cyrillic/Greek lookalikes)
  2. Subdomain stuffing (injecting brand/token subdomains)
  3. Brand-in-path (shifting brand keywords to path segments)
  4. URL extensions (adding .php, .html, login endpoints)
  5. Hex / Percent encoding (escaping characters to evade lexical filters)
  6. Compound word splitting (inserting hyphens into keyword tokens)
  7. Benign token padding (appending known benign keywords)
- Computes per-perturbation recall drop metrics.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from phishguard_core.url import canonicalize

# Character homoglyphs mapping ASCII to lookalike characters via explicit unicode escapes
HOMOGLYPH_MAP: dict[str, str] = {
    "a": "\u0430",  # Cyrillic small letter a
    "c": "\u0441",  # Cyrillic small letter es
    "e": "\u0435",  # Cyrillic small letter ie
    "i": "\u0456",  # Cyrillic small letter byelorussian-ukrainian i
    "j": "\u0458",  # Cyrillic small letter je
    "o": "\u043e",  # Cyrillic small letter o
    "p": "\u0440",  # Cyrillic small letter er
    "s": "\u0455",  # Cyrillic small letter dze
    "x": "\u0445",  # Cyrillic small letter ha
    "y": "\u0443",  # Cyrillic small letter u
}


BENIGN_TOKENS: list[str] = ["support", "secure", "login", "portal", "cloud", "auth", "verify", "account"]


def perturb_homoglyph(url: str) -> str:
    """Substitute eligible ASCII characters with visual homoglyphs in domain labels."""
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    new_host_chars: list[str] = []
    replaced = False

    for ch in host:
        if not replaced and ch.lower() in HOMOGLYPH_MAP:
            new_host_chars.append(HOMOGLYPH_MAP[ch.lower()])
            replaced = True
        else:
            new_host_chars.append(ch)

    new_host = "".join(new_host_chars)
    if parsed.netloc:
        return url.replace(parsed.netloc, new_host, 1)
    return new_host


def perturb_subdomain_stuffing(url: str) -> str:
    """Inject deceptive brand/security subdomains before the apex domain."""
    parsed = urlparse(url)
    host = parsed.netloc
    if not host:
        return url
    stuffed_host = f"secure-auth-update.signin.{host}"
    return url.replace(host, stuffed_host, 1)


def perturb_brand_in_path(url: str) -> str:
    """Shift or append deceptive brand tokens into path/query segments."""
    if "?" in url:
        return f"{url}&target=paypal_verification_portal"
    return f"{url.rstrip('/')}/paypal-security-verification/signin.php"


def perturb_url_extension(url: str) -> str:
    """Append deceptive file extensions or endpoint patterns."""
    if "?" in url:
        base, query = url.split("?", 1)
        return f"{base}.html?{query}"
    return f"{url}.php"


def perturb_hex_encoding(url: str) -> str:
    """Percent-encode path characters to test obfuscation handling."""
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == "/":
        return f"{url}/%6c%6f%67%69%6e"  # /login encoded
    # Percent-encode letters in path (e.g. /signin -> /%73%69%67%6e%69%6e)
    encoded_chars = [f"%{ord(c):02x}" if c.isalnum() else c for c in path]
    encoded_path = "".join(encoded_chars)
    return url.replace(path, encoded_path, 1)



def perturb_compound_split(url: str) -> str:
    """Split concatenated brand or keyword tokens using hyphens."""
    substitutions = [
        ("paypal", "pay-pal"),
        ("microsoft", "micro-soft"),
        ("netflix", "net-flix"),
        ("facebook", "face-book"),
        ("appleid", "apple-id"),
        ("signin", "sign-in"),
        ("login", "log-in"),
    ]
    perturbed = url
    for orig, rep in substitutions:
        if orig in perturbed.lower():
            perturbed = re.sub(re.escape(orig), rep, perturbed, flags=re.IGNORECASE)
            break
    if perturbed == url:
        perturbed = f"{url}?client=auth-service-login"
    return perturbed


def perturb_benign_padding(url: str) -> str:
    """Pad URL with trusted benign terms to dilute malicious signal density."""
    padding = "-".join(BENIGN_TOKENS[:3])
    if "?" in url:
        return f"{url}&ref={padding}"
    return f"{url.rstrip('/')}/{padding}"


PERTURBATION_STRATEGIES: dict[str, Callable[[str], str]] = {
    "homoglyph": perturb_homoglyph,
    "subdomain_stuffing": perturb_subdomain_stuffing,
    "brand_in_path": perturb_brand_in_path,
    "url_extension": perturb_url_extension,
    "hex_encoding": perturb_hex_encoding,
    "compound_split": perturb_compound_split,
    "benign_padding": perturb_benign_padding,
}


@dataclass(frozen=True)
class PerturbationResult:
    strategy: str
    sample_count: int
    clean_detected: int
    perturbed_detected: int
    clean_recall: float
    perturbed_recall: float
    recall_drop: float


@dataclass(frozen=True)
class RobustnessReport:
    total_samples: int
    overall_clean_recall: float
    overall_perturbed_recall: float
    overall_recall_drop: float
    per_strategy: list[PerturbationResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "overall_clean_recall": round(self.overall_clean_recall, 4),
            "overall_perturbed_recall": round(self.overall_perturbed_recall, 4),
            "overall_recall_drop": round(self.overall_recall_drop, 4),
            "per_strategy": [
                {
                    "strategy": r.strategy,
                    "sample_count": r.sample_count,
                    "clean_recall": round(r.clean_recall, 4),
                    "perturbed_recall": round(r.perturbed_recall, 4),
                    "recall_drop": round(r.recall_drop, 4),
                }
                for r in self.per_strategy
            ],
        }


def evaluate_robustness(
    malicious_urls: list[str],
    detector_predict: Callable[[str], bool],
    strategies: dict[str, Callable[[str], str]] | None = None,
) -> RobustnessReport:
    """Run full robustness benchmark suite against a detector function.

    detector_predict: accepts a URL string and returns True if detected as malicious/suspicious.
    """

    active_strategies = strategies or PERTURBATION_STRATEGIES
    results: list[PerturbationResult] = []

    clean_total = len(malicious_urls)
    clean_detected_total = sum(1 for u in malicious_urls if detector_predict(u))
    clean_recall_overall = (clean_detected_total / clean_total) if clean_total > 0 else 0.0

    total_perturbed = 0
    total_perturbed_detected = 0

    for name, perturb_fn in active_strategies.items():
        perturbed_urls: list[str] = []
        for u in malicious_urls:
            try:
                p_url = perturb_fn(u)
                # Verify that perturbed URL can still be canonicalized
                canonicalize(p_url)
                perturbed_urls.append(p_url)
            except Exception:
                # If perturbation invalidates URL, keep original
                perturbed_urls.append(u)

        det_clean = sum(1 for u in malicious_urls if detector_predict(u))
        det_pert = sum(1 for u in perturbed_urls if detector_predict(u))
        c_recall = (det_clean / len(malicious_urls)) if malicious_urls else 0.0
        p_recall = (det_pert / len(perturbed_urls)) if perturbed_urls else 0.0
        drop = max(0.0, c_recall - p_recall)

        results.append(
            PerturbationResult(
                strategy=name,
                sample_count=len(perturbed_urls),
                clean_detected=det_clean,
                perturbed_detected=det_pert,
                clean_recall=c_recall,
                perturbed_recall=p_recall,
                recall_drop=drop,
            )
        )

        total_perturbed += len(perturbed_urls)
        total_perturbed_detected += det_pert

    overall_pert_recall = (total_perturbed_detected / total_perturbed) if total_perturbed > 0 else 0.0
    overall_drop = max(0.0, clean_recall_overall - overall_pert_recall)

    return RobustnessReport(
        total_samples=clean_total,
        overall_clean_recall=clean_recall_overall,
        overall_perturbed_recall=overall_pert_recall,
        overall_recall_drop=overall_drop,
        per_strategy=results,
    )

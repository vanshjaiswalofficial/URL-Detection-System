"""Layered detection and model inference engine for PhishGuard AI.

Implements ARCHITECTURE.md §4, §10.1, §10.2 and RULES R-SEC-4, R-SEC-7, R-API-4, R-API-5:
- L0: Validate & canonicalize
- L1: Allowlist check (excluding multi-tenant hosts)
- L2: Denylist / threat feeds
- L3: LightGBM fast ML inference + feature contribution explanations
- Cryptographic SHA-256 verification of loaded model artifacts
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import lightgbm as lgb
import numpy as np

from phishguard_core.features import (
    FEATURE_NAMES,
    MULTITENANT_HOSTS,
    extract_features_from_parsed,
    features_to_dict,
)
from phishguard_core.reasons import Reason, get_reason_mapper
from phishguard_core.safety import sha256_url
from phishguard_core.url import InvalidUrlError, canonicalize

# Curated apex allowlist domains (Tranco top benign seed)
DEFAULT_ALLOWLIST: frozenset[str] = frozenset({
    "google.com", "microsoft.com", "apple.com", "amazon.com", "wikipedia.org",
    "github.com", "cloudflare.com", "mozilla.org", "stackoverflow.com", "linkedin.com",
    "nytimes.com", "cnn.com", "bbc.com", "medium.com", "nih.gov", "cdc.gov", "who.int"
})


class TamperedArtifactError(RuntimeError):
    """Raised when artifact SHA-256 does not match registry manifest.json."""
    pass


@dataclass(frozen=True)
class ScanResult:
    scan_id: str
    url_raw: str
    url_canonical: str
    url_canonical_hash: str
    registered_domain: str
    verdict: str  # 'malicious' | 'suspicious' | 'no_threat_found' | 'unknown'
    risk_score: int  # 0 to 100
    probability: float  # 0.0 to 1.0
    confidence: str  # 'low' | 'medium' | 'high'
    reasons: list[Reason]
    layers: dict[str, str]
    model_version: str
    latency_ms: int
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["reasons"] = [asdict(r) for r in self.reasons]
        return d


class LayeredDetector:
    """Production detection pipeline coordinating layers L0 to L3."""

    def __init__(
        self,
        model_dir: Path | str | None = None,
        verify_hashes: bool = True,
        allowlist: frozenset[str] | None = None,
        denylist: set[str] | None = None,
    ) -> None:
        self.allowlist = allowlist or DEFAULT_ALLOWLIST
        self.denylist = denylist or set()
        self.reason_mapper = get_reason_mapper()

        self.booster: lgb.Booster | None = None
        self.feature_names: list[str] = FEATURE_NAMES
        self.t_suspicious: float = 0.35
        self.t_malicious: float = 0.70
        self.model_version: str = "v0.1-rule-fallback"

        if model_dir:
            self._load_model_artifacts(Path(model_dir), verify_hashes=verify_hashes)

    def _load_model_artifacts(self, model_path: Path, verify_hashes: bool = True) -> None:
        if not model_path.exists():
            return

        manifest_file = model_path / "manifest.json"
        if manifest_file.exists():
            with open(manifest_file, encoding="utf-8") as f:
                manifest_data = json.load(f)
            self.model_version = manifest_data.get("version", model_path.name)

            # Cryptographic SHA-256 verification per RULES R-SEC-7
            if verify_hashes and "artifacts" in manifest_data:
                for filename, expected_hash in manifest_data["artifacts"].items():
                    fpath = model_path / filename
                    if fpath.exists():
                        computed = hashlib.sha256(fpath.read_bytes()).hexdigest()
                        if computed != expected_hash:
                            raise TamperedArtifactError(
                                f"Integrity check failed for {filename}: expected {expected_hash}, got {computed}"
                            )

        # Load thresholds
        thresh_file = model_path / "thresholds.json"
        if thresh_file.exists():
            with open(thresh_file, encoding="utf-8") as f:
                thresh_data = json.load(f)
            self.t_suspicious = float(thresh_data.get("t_suspicious", 0.35))
            self.t_malicious = float(thresh_data.get("t_malicious", 0.70))

        # Load feature names
        feats_file = model_path / "features.json"
        if feats_file.exists():
            with open(feats_file, encoding="utf-8") as f:
                self.feature_names = json.load(f)

        # Load LightGBM booster
        model_file = model_path / "model.txt"
        if model_file.exists():
            self.booster = lgb.Booster(model_file=str(model_file))

    def scan(
        self,
        url: str,
        user_allow: set[str] | None = None,
        user_deny: set[str] | None = None,
    ) -> ScanResult:
        """Scan a URL through layered detection without network I/O."""
        t0 = time.perf_counter()
        scan_id = str(uuid.uuid4())
        layers: dict[str, str] = {
            "canonicalize": "miss",
            "user_list": "none",
            "allowlist": "miss",
            "feeds": "miss",
            "ml": "skipped",
        }

        # --- L0: Validate & Canonicalize ---
        try:
            parsed = canonicalize(url)
            layers["canonicalize"] = "ok"
        except InvalidUrlError as exc:
            duration_ms = max(int((time.perf_counter() - t0) * 1000), 1)
            return ScanResult(
                scan_id=scan_id,
                url_raw=url,
                url_canonical="",
                url_canonical_hash=sha256_url(url),
                registered_domain="",
                verdict="unknown",
                risk_score=0,
                probability=0.0,
                confidence="low",
                reasons=[
                    Reason(
                        code="invalid_url",
                        severity="medium",
                        text=f"Cannot assess: {exc}",
                        target_segment="host",
                    )
                ],
                layers={"canonicalize": "rejected"},
                model_version=self.model_version,
                latency_ms=duration_ms,
            )

        canonical = parsed.canonical
        canon_hash = sha256_url(canonical)
        reg_domain = parsed.registered_domain
        is_multitenant = reg_domain in MULTITENANT_HOSTS or parsed.suffix in MULTITENANT_HOSTS

        # --- User Denylist Check (ARCH §4.1) ---
        if user_deny and (
            canonical in user_deny or reg_domain in user_deny or parsed.host in user_deny
        ):
            layers["user_list"] = "deny_hit"
            reason = Reason(
                code="user_denylist",
                severity="high",
                text="The site was flagged on your custom blocklist.",
                target_segment="host",
            )
            duration_ms = max(int((time.perf_counter() - t0) * 1000), 1)
            return ScanResult(
                scan_id=scan_id,
                url_raw=url,
                url_canonical=canonical,
                url_canonical_hash=canon_hash,
                registered_domain=reg_domain,
                verdict="malicious",
                risk_score=99,
                probability=0.99,
                confidence="high",
                reasons=[reason],
                layers=layers,
                model_version=self.model_version,
                latency_ms=duration_ms,
            )

        # --- L1: Global Denylist / Threat Feeds Check (RULES R-API-5, ARCH §4.1) ---
        # Feed/Deny ALWAYS beats curated allowlist.
        is_denied = (
            canonical in self.denylist
            or reg_domain in self.denylist
            or parsed.host in self.denylist
        )
        if is_denied:
            layers["feeds"] = "hit"
            feed_reason = self.reason_mapper.build_reason("feed_hit", {"match": reg_domain})
            duration_ms = max(int((time.perf_counter() - t0) * 1000), 1)
            return ScanResult(
                scan_id=scan_id,
                url_raw=url,
                url_canonical=canonical,
                url_canonical_hash=canon_hash,
                registered_domain=reg_domain,
                verdict="malicious",
                risk_score=99,
                probability=0.99,
                confidence="high",
                reasons=[feed_reason],
                layers=layers,
                model_version=self.model_version,
                latency_ms=duration_ms,
            )

        # --- User Allowlist Check (user-pinned allow) ---
        if user_allow and not is_multitenant and (
            canonical in user_allow or reg_domain in user_allow or parsed.host in user_allow
        ):
            layers["user_list"] = "allow_hit"
            duration_ms = max(int((time.perf_counter() - t0) * 1000), 1)
            return ScanResult(
                scan_id=scan_id,
                url_raw=url,
                url_canonical=canonical,
                url_canonical_hash=canon_hash,
                registered_domain=reg_domain,
                verdict="no_threat_found",
                risk_score=0,
                probability=0.01,
                confidence="high",
                reasons=[],
                layers=layers,
                model_version=self.model_version,
                latency_ms=duration_ms,
            )

        # --- L2: Curated Apex Allowlist Check ---
        # Multi-tenant hosts are NEVER auto-allowed (ARCHITECTURE §4.2, D-011)
        if not is_multitenant and reg_domain in self.allowlist and not parsed.has_userinfo:
            layers["allowlist"] = "hit"
            duration_ms = max(int((time.perf_counter() - t0) * 1000), 1)
            return ScanResult(
                scan_id=scan_id,
                url_raw=url,
                url_canonical=canonical,
                url_canonical_hash=canon_hash,
                registered_domain=reg_domain,
                verdict="no_threat_found",
                risk_score=0,
                probability=0.01,
                confidence="high",
                reasons=[],
                layers=layers,
                model_version=self.model_version,
                latency_ms=duration_ms,
            )


        # --- L3: Fast ML Feature Extraction & Inference ---
        feats = extract_features_from_parsed(parsed)
        f_dict = features_to_dict(feats)
        layers["ml"] = "scored"

        prob = 0.50
        contributions: dict[str, float] = {}

        if self.booster:
            x_vec = np.array([[f_dict[name] for name in self.feature_names]], dtype=float)
            raw_pred = self.booster.predict(x_vec)
            prob = float(raw_pred[0])

            # Extract per-request feature contributions via pred_contrib=True
            try:
                contrib_raw = self.booster.predict(x_vec, pred_contrib=True)[0]
                # Last entry is the bias term
                for i, name in enumerate(self.feature_names):
                    contributions[name] = float(contrib_raw[i])
            except Exception:
                pass
        else:
            # Heuristic fallback if model not loaded
            score_acc = 0.0
            if feats.is_ip_host:
                score_acc += 0.45
            if feats.brand_in_subdomain:
                score_acc += 0.40
            if feats.typosquat_detected or feats.combosquat_detected:
                score_acc += 0.40
            if feats.suspicious_keyword_count > 0:
                score_acc += 0.15
            prob = min(max(score_acc, 0.05), 0.95)

        # Map contributions to human-readable reasons
        reasons = self.reason_mapper.extract_reasons(
            parsed=parsed,
            features=feats,
            contributions=contributions,
        )

        # Verdict assignment based on calibrated operating thresholds (RULES R-ML-5)
        if prob >= self.t_malicious:
            verdict = "malicious"
        elif prob >= self.t_suspicious:
            verdict = "suspicious"
        else:
            verdict = "no_threat_found"

        risk_score = round(prob * 100)
        confidence = "high" if (prob >= 0.85 or prob <= 0.15) else "medium"

        # Ensure every non-benign verdict has >= 1 reason (TASK T3.5, DESIGN.md §8)
        if verdict in ("malicious", "suspicious") and not reasons:
            reasons = [
                self.reason_mapper.build_reason(
                    "elevated_ml_risk",
                    evidence={"risk_score": risk_score, "probability": round(prob, 4)},
                )
            ]

        duration_ms = max(int((time.perf_counter() - t0) * 1000), 1)

        return ScanResult(
            scan_id=scan_id,
            url_raw=url,
            url_canonical=canonical,
            url_canonical_hash=canon_hash,
            registered_domain=reg_domain,
            verdict=verdict,
            risk_score=risk_score,
            probability=round(prob, 4),
            confidence=confidence,
            reasons=reasons,
            layers=layers,
            model_version=self.model_version,
            latency_ms=duration_ms,
        )


_DETECTOR: LayeredDetector | None = None


def get_detector() -> LayeredDetector:
    """Return a shared LayeredDetector initialized with active model artifacts."""
    global _DETECTOR
    if _DETECTOR is None:
        candidate_paths = [
            Path("models/v0.1-baseline"),
            Path(__file__).parent.parent.parent.parent / "models" / "v0.1-baseline",
        ]
        chosen: Path | None = None
        for p in candidate_paths:
            if (p / "model.txt").exists():
                chosen = p
                break
        _DETECTOR = LayeredDetector(chosen)
    return _DETECTOR

"""Repository data access layer with privacy enforcement for PhishGuard AI.

Implements ARCHITECTURE.md §10.3 and RULES R-PRIV-1, R-PRIV-2:
- Never stores raw URL unless store=True
- When store=True, strips query parameters and fragment
- Stores defanged URL and SHA-256 hash
- Hashes user keys for privacy isolation
"""

from __future__ import annotations

import hashlib
from typing import Any

from phishguard_core.inference import ScanResult
from phishguard_core.safety import defang, redact_query
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.db.models import FeedbackRecord, ListRecord, ScanRecord


def hash_key(key: str) -> str:
    """Return SHA-256 hex digest of a user or client key."""
    return hashlib.sha256(key.strip().encode("utf-8")).hexdigest()


def record_scan(
    db: Session,
    scan_result: ScanResult,
    store: bool = False,
    client: str = "api",
) -> ScanRecord:
    """Persist a scan result enforcing privacy defaults.

    - url_stored is NULL by default unless store=True.
    - If store=True, query string and fragment are stripped.
    - url_defanged is always saved for safe display.
    """
    canonical_or_raw = scan_result.url_canonical or scan_result.url_raw

    url_to_store: str | None = None
    if store and canonical_or_raw:
        # Strip query parameters and fragment per RULES R-PRIV-1
        url_to_store = redact_query(canonical_or_raw)

    reasons_data: list[dict[str, Any]] = [
        {
            "code": r.code,
            "severity": r.severity,
            "text": r.text,
            "target_segment": r.target_segment,
            "evidence": r.evidence,
        }
        for r in scan_result.reasons
    ]

    record = ScanRecord(
        id=scan_result.scan_id,
        url_sha256=scan_result.url_canonical_hash,
        url_stored=url_to_store,
        url_defanged=defang(canonical_or_raw),
        registered_domain=scan_result.registered_domain,
        verdict=scan_result.verdict,
        risk_score=scan_result.risk_score,
        probability=scan_result.probability,
        model_version=scan_result.model_version,
        layers_json=scan_result.layers,
        reasons_json=reasons_data,
        client=client,
        latency_ms=scan_result.latency_ms,
    )

    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def record_feedback(
    db: Session,
    scan_id: str,
    label: str,
    note: str | None = None,
) -> FeedbackRecord:
    """Persist user feedback for human review with status 'new'."""
    record = FeedbackRecord(
        scan_id=scan_id,
        label=label,
        note=note,
        review_status="new",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def add_user_list_entry(
    db: Session,
    user_key: str,
    kind: str,
    pattern: str,
    scope: str = "domain",
    note: str | None = None,
) -> ListRecord:
    """Add an entry to user's allow or deny list."""
    key_hash = hash_key(user_key)
    clean_pattern = pattern.strip().lower()

    # Avoid duplicate entry
    stmt = select(ListRecord).where(
        ListRecord.owner_key_hash == key_hash,
        ListRecord.kind == kind,
        ListRecord.pattern == clean_pattern,
    )
    existing = db.execute(stmt).scalar_one_or_none()
    if existing:
        return existing

    record = ListRecord(
        owner_key_hash=key_hash,
        kind=kind,
        pattern=clean_pattern,
        scope=scope,
        note=note,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_user_lists(db: Session, user_key: str) -> dict[str, list[str]]:
    """Retrieve allow and deny list patterns for a given user key."""
    key_hash = hash_key(user_key)
    stmt = select(ListRecord).where(ListRecord.owner_key_hash == key_hash)
    records = db.execute(stmt).scalars().all()

    allow_list: list[str] = []
    deny_list: list[str] = []
    for r in records:
        if r.kind == "allow":
            allow_list.append(r.pattern)
        elif r.kind == "deny":
            deny_list.append(r.pattern)

    return {
        "allow": sorted(allow_list),
        "deny": sorted(deny_list),
    }


def delete_user_list_entry(
    db: Session,
    user_key: str,
    kind: str,
    pattern: str,
) -> bool:
    """Delete an entry from user's custom list."""
    key_hash = hash_key(user_key)
    clean_pattern = pattern.strip().lower()

    stmt = select(ListRecord).where(
        ListRecord.owner_key_hash == key_hash,
        ListRecord.kind == kind,
        ListRecord.pattern == clean_pattern,
    )
    record = db.execute(stmt).scalar_one_or_none()
    if record:
        db.delete(record)
        db.commit()
        return True
    return False

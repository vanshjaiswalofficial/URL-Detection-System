"""Data retention and privacy cleanup job for PhishGuard AI.

Implements ARCHITECTURE.md §10.3 and RULES R-PRIV-1:
- Deletes scan records older than retention_days (default 30 days)
- Can be scheduled as a background worker task or executed via cron/maintenance
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete
from sqlalchemy.orm import Session

from backend.app.db.models import ScanRecord


def cleanup_expired_scans(db: Session, retention_days: int = 30) -> int:
    """Delete scan records older than the specified retention window.

    Returns the number of deleted records.
    """
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    stmt = delete(ScanRecord).where(ScanRecord.created_at < cutoff)
    result = db.execute(stmt)
    db.commit()
    cursor_res = cast("CursorResult[Any]", result)
    return int(cursor_res.rowcount or 0)

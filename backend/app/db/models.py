"""SQLAlchemy database models for PhishGuard AI.

Implements ARCHITECTURE.md §10.3 and RULES R-PRIV-1, R-PRIV-2:
- scans: Scan history with privacy defaults (raw URL null unless store=true; query stripped)
- feedback: Human review feedback on scans
- feed_entries: Fresh positive feeds cache
- lists: User custom allow/deny lists
- model_registry: Tracked model versions, metrics, and thresholds
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def utc_now() -> datetime:
    return datetime.now(UTC)


class ScanRecord(Base):
    """Stores scan results with privacy-by-default guarantees (ARCH §10.3, R-PRIV-1)."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    url_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # url_stored is NULL by default unless user explicitly passed store=True.
    # When stored, query string and fragment MUST be stripped.
    url_stored: Mapped[str | None] = mapped_column(Text, nullable=True)
    url_defanged: Mapped[str] = mapped_column(Text, nullable=False)
    registered_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    probability: Mapped[float] = mapped_column(Float, nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    layers_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reasons_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    client: Mapped[str] = mapped_column(String(64), default="api")
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (
        Index("ix_scans_created_at_desc", created_at.desc()),
    )


class FeedbackRecord(Base):
    """User feedback for active learning review (ARCH §10.3, RULES R-ML-14)."""

    __tablename__ = "feedback"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    label: Mapped[str] = mapped_column(
        String(32),
        CheckConstraint("label IN ('false_positive', 'false_negative', 'correct')"),
        nullable=False,
    )
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    review_status: Mapped[str] = mapped_column(String(32), default="new", index=True)


class FeedEntryRecord(Base):
    """Normalized external threat feed entry (OpenPhish, URLhaus)."""

    __tablename__ = "feed_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    url_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    label: Mapped[str] = mapped_column(String(32), default="malicious")


class ListRecord(Base):
    """User custom allow/deny list entries."""

    __tablename__ = "lists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_key_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(
        String(16),
        CheckConstraint("kind IN ('allow', 'deny')"),
        nullable=False,
    )
    pattern: Mapped[str] = mapped_column(String(2048), nullable=False)
    scope: Mapped[str] = mapped_column(String(32), default="domain")
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ModelRegistryRecord(Base):
    """Audit log of registered models, metrics, and calibration thresholds."""

    __tablename__ = "model_registry"

    version: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    git_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    data_manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    metrics_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    thresholds_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="active")

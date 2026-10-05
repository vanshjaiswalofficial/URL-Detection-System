"""Unit tests for persistence, privacy defaults, and retention (TASK T4.5).

Implements acceptance criteria:
- DB inspection test shows no raw URL stored by default (store=false)
- When store=true, query parameters and fragments are stripped
- Scans, feedback, and user lists are persisted in SQLite/PostgreSQL
- Retention job deletes rows older than retention_days
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from phishguard_core.inference import ScanResult
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.models import Base, FeedbackRecord, ListRecord, ScanRecord
from backend.app.db.repository import (
    add_user_list_entry,
    get_user_lists,
    hash_key,
    record_feedback,
    record_scan,
)
from backend.app.db.retention import cleanup_expired_scans
from backend.app.db.session import get_db
from backend.app.main import app

TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    future=True,
)
Base.metadata.create_all(bind=TEST_ENGINE)
TestingSessionLocal = sessionmaker(bind=TEST_ENGINE, autoflush=False, autocommit=False)


def get_test_db() -> Session:
    """Create test session for isolated testing."""
    return TestingSessionLocal()


def test_privacy_defaults_no_raw_url_stored() -> None:
    """When store=False (default), url_stored in DB is None (ARCH §10.3, R-PRIV-1)."""
    db = get_test_db()
    result = ScanResult(
        scan_id="scan-1234",
        url_raw="https://example.com/login?token=secret123&user=alice#section1",
        url_canonical="https://example.com/login?token=secret123&user=alice",
        url_canonical_hash="abc123hash",
        registered_domain="example.com",
        verdict="no_threat_found",
        risk_score=5,
        probability=0.05,
        confidence="high",
        reasons=[],
        layers={"allowlist": "hit"},
        model_version="test-model",
        latency_ms=10,
    )

    # 1. Default store=False
    record = record_scan(db, result, store=False)
    assert record.url_stored is None
    assert "secret123" not in str(record.url_stored)

    # Query DB directly to verify persistence
    stmt = select(ScanRecord).where(ScanRecord.id == "scan-1234")
    db_record = db.execute(stmt).scalar_one()
    assert db_record.url_stored is None
    assert db_record.url_sha256 == "abc123hash"
    assert "hxxps" in db_record.url_defanged  # Defanged representation


def test_store_true_strips_query_and_fragment() -> None:
    """When store=True, query and fragment are stripped before storing (R-PRIV-1)."""
    db = get_test_db()
    result = ScanResult(
        scan_id="scan-5678",
        url_raw="https://bank.com/signin?session_id=xyz987&oauth_token=sensitive#top",
        url_canonical="https://bank.com/signin?session_id=xyz987&oauth_token=sensitive",
        url_canonical_hash="bankhash789",
        registered_domain="bank.com",
        verdict="suspicious",
        risk_score=60,
        probability=0.60,
        confidence="medium",
        reasons=[],
        layers={"ml": "scored"},
        model_version="test-model",
        latency_ms=25,
    )

    record = record_scan(db, result, store=True)
    assert record.url_stored is not None
    # Must NOT contain query parameters or fragments
    assert record.url_stored == "https://bank.com/signin"
    assert "session_id" not in record.url_stored
    assert "oauth_token" not in record.url_stored


def test_feedback_persistence() -> None:
    """Feedback is persisted with status 'new' for human review."""
    db = get_test_db()
    fb = record_feedback(
        db,
        scan_id="scan-1234",
        label="false_positive",
        note="Legitimate internal portal",
    )
    assert fb.review_status == "new"
    assert fb.label == "false_positive"

    stmt = select(FeedbackRecord).where(FeedbackRecord.scan_id == "scan-1234")
    persisted = db.execute(stmt).scalar_one()
    assert persisted.note == "Legitimate internal portal"


def test_user_list_db_persistence_and_isolation() -> None:
    """Custom user lists persist and isolate per hashed user key."""
    db = get_test_db()
    user_a = "user_alpha_secret_key"
    user_b = "user_beta_secret_key"

    add_user_list_entry(db, user_a, kind="allow", pattern="internal-tool.company.com")
    add_user_list_entry(db, user_a, kind="deny", pattern="evil-phish.xyz")
    add_user_list_entry(db, user_b, kind="deny", pattern="malicious-site.net")

    lists_a = get_user_lists(db, user_a)
    assert "internal-tool.company.com" in lists_a["allow"]
    assert "evil-phish.xyz" in lists_a["deny"]
    assert "malicious-site.net" not in lists_a["deny"]

    # Verify key is stored hashed in DB
    stmt = select(ListRecord).where(ListRecord.pattern == "internal-tool.company.com")
    entry = db.execute(stmt).scalar_one()
    assert entry.owner_key_hash == hash_key(user_a)
    assert entry.owner_key_hash != user_a


def test_retention_job_deletes_old_scans() -> None:
    """cleanup_expired_scans deletes scans older than retention_days (ARCH §10.3)."""
    db = get_test_db()

    now = datetime.now(UTC)
    old_date = now - timedelta(days=45)
    recent_date = now - timedelta(days=5)

    # Insert an old scan
    old_scan = ScanRecord(
        id="old-scan",
        created_at=old_date,
        url_sha256="oldhash",
        url_stored=None,
        url_defanged="hxxp://old[.]com",
        registered_domain="old.com",
        verdict="no_threat_found",
        risk_score=0,
        probability=0.01,
        model_version="v0.1",
        layers_json={},
        reasons_json=[],
    )
    # Insert a recent scan
    recent_scan = ScanRecord(
        id="recent-scan",
        created_at=recent_date,
        url_sha256="recenthash",
        url_stored=None,
        url_defanged="hxxp://recent[.]com",
        registered_domain="recent.com",
        verdict="no_threat_found",
        risk_score=0,
        probability=0.01,
        model_version="v0.1",
        layers_json={},
        reasons_json=[],
    )

    db.add(old_scan)
    db.add(recent_scan)
    db.commit()

    # Run retention cleanup for 30 days
    deleted = cleanup_expired_scans(db, retention_days=30)
    assert deleted == 1

    # Verify old_scan is gone and recent_scan remains
    assert db.execute(select(ScanRecord).where(ScanRecord.id == "old-scan")).scalar_one_or_none() is None
    assert db.execute(select(ScanRecord).where(ScanRecord.id == "recent-scan")).scalar_one_or_none() is not None


def test_api_scan_persistence_integration() -> None:
    """Integration test verifying scan persistence via FastAPI endpoints."""
    # Override get_db with in-memory test db
    def override_get_db() -> Generator[Session, None, None]:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)

    # 1. Scan with store=False
    resp = client.post("/v1/scan", json={"url": "https://example.com/test?param=1", "store": False})
    assert resp.status_code == 200
    data = resp.json()
    scan_id = data["scan_id"]

    # 2. Retrieve via GET /v1/scan/{scan_id}
    get_resp = client.get(f"/v1/scan/{scan_id}")
    assert get_resp.status_code == 200
    scan_detail = get_resp.json()
    assert scan_detail["scan_id"] == scan_id
    assert scan_detail["url_stored"] is None  # Never stored
    assert scan_detail["registered_domain"] == "example.com"

    # 3. Scan with store=True
    resp_stored = client.post("/v1/scan", json={"url": "https://example.com/test?param=secret", "store": True})
    assert resp_stored.status_code == 200
    scan_id_stored = resp_stored.json()["scan_id"]

    get_stored_resp = client.get(f"/v1/scan/{scan_id_stored}")
    assert get_stored_resp.status_code == 200
    stored_detail = get_stored_resp.json()
    assert stored_detail["url_stored"] == "https://example.com/test"
    assert "param=secret" not in stored_detail["url_stored"]

    # 4. Trigger retention cleanup endpoint
    cleanup_resp = client.post("/v1/admin/retention/cleanup", json={"retention_days": 30})
    assert cleanup_resp.status_code == 200
    assert cleanup_resp.json()["status"] == "cleaned"

    # Clean up override
    app.dependency_overrides.clear()

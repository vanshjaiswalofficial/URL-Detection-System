"""FastAPI service for PhishGuard AI.

Implements ARCHITECTURE.md §10.1, §10.3, RULES R-API-1..7, R-SEC-1, R-SEC-2, R-PRIV-1, R-PRIV-2:
- Versioned under /v1
- POST /v1/scan and POST /v1/scan/batch (capped <= 100)
- GET /v1/scan/{scan_id} (retrieval with privacy defaults)
- POST /v1/feedback (persisted for human review)
- GET /v1/lists, POST /v1/lists, DELETE /v1/lists (user key isolated database lists)
- POST /v1/admin/retention/cleanup (deletes scans older than N days)
- GET /v1/model/info, GET /v1/health, GET /v1/ready
- RFC 7807 problem+json error formatting
- Defanged logging only (no raw URLs logged per RULES R-CODE-8)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Annotated, Any

import structlog
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from phishguard_core.features import MULTITENANT_HOSTS
from phishguard_core.inference import ScanResult, get_detector
from phishguard_core.safety import defang
from phishguard_core.url import canonicalize
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.db.models import ScanRecord
from backend.app.db.repository import (
    add_user_list_entry,
    delete_user_list_entry,
    get_user_lists,
    record_feedback,
    record_scan,
)
from backend.app.db.retention import cleanup_expired_scans
from backend.app.db.session import get_db, init_db

# Type alias for injected database session (clean with B008)
DbSession = Annotated[Session, Depends(get_db)]

# Configure structured logging
logger = structlog.get_logger()


class ScanRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="URL to scan (up to 2048 chars per R-SEC-2)")
    mode: str = Field(default="fast", description="Detection mode: fast or deep")
    client: str = Field(default="api", description="Client identifier (e.g. extension/0.1.0)")
    store: bool = Field(default=False, description="Whether user explicitly consented to store URL (R-PRIV-1)")
    user_key: str | None = Field(default=None, description="Optional user key for custom allow/deny lists")


class BatchScanRequest(BaseModel):
    urls: list[str] = Field(..., max_length=100, description="List of URLs to scan (capped at 100)")
    mode: str = Field(default="fast")
    client: str = Field(default="api")
    store: bool = Field(default=False)
    user_key: str | None = None


class FeedbackRequest(BaseModel):
    scan_id: str
    url_canonical_hash: str
    feedback_label: str = Field(..., description="'false_positive', 'false_negative', or 'correct'")
    comment: str | None = None


class UserListEntryRequest(BaseModel):
    user_key: str = Field(..., min_length=1, max_length=128, description="User or client identifier")
    list_type: str = Field(..., description="'allow' or 'deny'")
    entry: str = Field(..., min_length=1, max_length=2048, description="Domain or URL to allow or block")
    comment: str | None = None


class RetentionCleanupRequest(BaseModel):
    retention_days: int = Field(default=30, ge=1, le=365, description="Days to retain scan history")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # Initialize database tables
    init_db()
    # Startup: ensure detector and model artifacts are initialized
    detector = get_detector()
    logger.info("phishguard_started", model_version=detector.model_version)
    yield


app = FastAPI(
    title="PhishGuard AI API",
    description="Production-grade AI/ML service for phishing and malicious URL detection.",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json",
)

# Enable CORS for dashboard and extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """RFC 7807 problem+json error formatting per RULES R-API-3."""
    problem = {
        "type": "about:blank",
        "title": exc.detail if isinstance(exc.detail, str) else "Error",
        "status": exc.status_code,
        "detail": str(exc.detail),
        "instance": request.url.path,
    }
    return JSONResponse(
        status_code=exc.status_code,
        content=problem,
        media_type="application/problem+json",
    )


@app.get("/v1/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/ready")
async def ready() -> dict[str, Any]:
    detector = get_detector()
    return {
        "status": "ready",
        "model_version": detector.model_version,
        "model_loaded": detector.booster is not None,
    }


@app.get("/v1/model/info")
async def model_info() -> dict[str, Any]:
    detector = get_detector()
    return {
        "model_version": detector.model_version,
        "features_count": len(detector.feature_names),
        "thresholds": {
            "t_suspicious": detector.t_suspicious,
            "t_malicious": detector.t_malicious,
        },
        "status": "active",
    }


@app.post("/v1/scan", status_code=status.HTTP_200_OK)
async def scan_single_url(req: ScanRequest, db: DbSession) -> dict[str, Any]:
    detector = get_detector()

    # Load custom lists from database if user_key provided
    user_allow: set[str] | None = None
    user_deny: set[str] | None = None
    if req.user_key:
        lists_data = get_user_lists(db, req.user_key)
        user_allow = set(lists_data["allow"])
        user_deny = set(lists_data["deny"])

    result: ScanResult = detector.scan(req.url, user_allow=user_allow, user_deny=user_deny)

    # Persist scan record with privacy-by-default guarantees (ARCH §10.3, R-PRIV-1)
    record_scan(db, result, store=req.store, client=req.client)

    # Log with defanged URL per RULES R-CODE-8, R-SAF-4
    logger.info(
        "url_scanned",
        url_defanged=defang(result.url_canonical or req.url),
        verdict=result.verdict,
        risk_score=result.risk_score,
        latency_ms=result.latency_ms,
        client=req.client,
        stored=req.store,
    )

    return result.to_dict()


@app.post("/v1/scan/batch", status_code=status.HTTP_200_OK)
async def scan_batch_urls(req: BatchScanRequest, db: DbSession) -> dict[str, Any]:
    if len(req.urls) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch limit exceeded. Maximum 100 URLs per request.",
        )

    detector = get_detector()
    user_allow: set[str] | None = None
    user_deny: set[str] | None = None
    if req.user_key:
        lists_data = get_user_lists(db, req.user_key)
        user_allow = set(lists_data["allow"])
        user_deny = set(lists_data["deny"])

    results = []
    for u in req.urls:
        scan_res = detector.scan(u, user_allow=user_allow, user_deny=user_deny)
        record_scan(db, scan_res, store=req.store, client=req.client)
        results.append(scan_res.to_dict())

    return {
        "count": len(results),
        "results": results,
    }


@app.get("/v1/scan/{scan_id}", status_code=status.HTTP_200_OK)
async def get_scan_by_id(scan_id: str, db: DbSession) -> dict[str, Any]:
    """Retrieve scan result from database with privacy rules."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    return {
        "scan_id": record.id,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "url_canonical_hash": record.url_sha256,
        "url_defanged": record.url_defanged,
        "url_stored": record.url_stored,  # None unless store=True consented
        "registered_domain": record.registered_domain,
        "verdict": record.verdict,
        "risk_score": record.risk_score,
        "probability": record.probability,
        "model_version": record.model_version,
        "layers": record.layers_json,
        "reasons": record.reasons_json,
        "client": record.client,
        "latency_ms": record.latency_ms,
    }


@app.post("/v1/lists", status_code=status.HTTP_201_CREATED)
async def add_list_entry_endpoint(
    req: UserListEntryRequest, db: DbSession
) -> dict[str, Any]:
    if req.list_type not in ("allow", "deny"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid list_type. Expected 'allow' or 'deny'.",
        )
    user_entry = req.entry.strip().lower()

    # Multi-tenant hosts cannot be auto-allowed (ARCHITECTURE §4.2, D-011)
    if req.list_type == "allow":
        try:
            parsed = canonicalize(user_entry if "://" in user_entry else f"https://{user_entry}")
            if parsed.registered_domain in MULTITENANT_HOSTS or parsed.suffix in MULTITENANT_HOSTS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Domain {user_entry} is a multi-tenant provider and cannot be auto-allowed (ARCHITECTURE §4.2, D-011).",
                )
        except HTTPException:
            raise
        except Exception:
            pass

    add_user_list_entry(
        db=db,
        user_key=req.user_key,
        kind=req.list_type,
        pattern=user_entry,
        note=req.comment,
    )

    logger.info(
        "user_list_updated",
        user_key_prefix=req.user_key[:4] + "...",
        list_type=req.list_type,
        entry=defang(user_entry),
    )
    return {
        "status": "added",
        "user_key": req.user_key,
        "list_type": req.list_type,
        "entry": user_entry,
    }


@app.get("/v1/lists")
async def get_user_lists_endpoint(user_key: str, db: DbSession) -> dict[str, Any]:
    lists = get_user_lists(db, user_key)
    return {
        "user_key": user_key,
        "allow": lists["allow"],
        "deny": lists["deny"],
    }


@app.delete("/v1/lists")
async def delete_list_entry_endpoint(
    user_key: str, list_type: str, entry: str, db: DbSession
) -> dict[str, Any]:
    if list_type not in ("allow", "deny"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid list_type. Expected 'allow' or 'deny'.",
        )
    deleted = delete_user_list_entry(db, user_key=user_key, kind=list_type, pattern=entry)
    if deleted:
        return {"status": "deleted", "entry": entry.strip().lower()}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="List entry not found.")


@app.post("/v1/feedback", status_code=status.HTTP_201_CREATED)
async def submit_feedback(req: FeedbackRequest, db: DbSession) -> dict[str, Any]:
    if req.feedback_label not in ("false_positive", "false_negative", "correct"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid feedback label. Expected 'false_positive', 'false_negative', or 'correct'.",
        )

    record_feedback(db, scan_id=req.scan_id, label=req.feedback_label, note=req.comment)

    logger.info(
        "feedback_received",
        scan_id=req.scan_id,
        label=req.feedback_label,
        hash=req.url_canonical_hash,
    )

    return {
        "status": "recorded",
        "review_status": "new",
        "message": "Feedback submitted successfully for human review.",
    }


@app.post("/v1/admin/retention/cleanup", status_code=status.HTTP_200_OK)
async def trigger_retention_cleanup(
    db: DbSession,
    req: RetentionCleanupRequest | None = None,
) -> dict[str, Any]:
    """Execute retention policy cleanup deleting scans older than retention_days (ARCH §10.3)."""
    cleanup_req = req or RetentionCleanupRequest()
    deleted_count = cleanup_expired_scans(db, retention_days=cleanup_req.retention_days)
    logger.info("retention_cleanup_executed", deleted_records=deleted_count, retention_days=cleanup_req.retention_days)
    return {
        "status": "cleaned",
        "deleted_records": deleted_count,
        "retention_days": cleanup_req.retention_days,
    }

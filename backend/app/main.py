"""FastAPI service for PhishGuard AI.

Implements ARCHITECTURE.md §10.1, RULES R-API-1..7, R-SEC-1, R-SEC-2:
- Versioned under /v1
- POST /v1/scan and POST /v1/scan/batch (capped <= 100)
- GET /v1/model/info, GET /v1/health, GET /v1/ready
- RFC 7807 problem+json error formatting
- Defanged logging only (no raw URLs logged per RULES R-CODE-8)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from phishguard_core.inference import ScanResult, get_detector
from phishguard_core.safety import defang
from pydantic import BaseModel, Field

# Configure structured logging
logger = structlog.get_logger()


# User custom allow / deny lists in-memory storage (user_key -> {"allow": set(), "deny": set()})
USER_LISTS: dict[str, dict[str, set[str]]] = {}


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



@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
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
async def scan_single_url(req: ScanRequest) -> dict[str, Any]:
    detector = get_detector()
    user_allow = USER_LISTS.get(req.user_key, {}).get("allow") if req.user_key else None
    user_deny = USER_LISTS.get(req.user_key, {}).get("deny") if req.user_key else None
    result: ScanResult = detector.scan(req.url, user_allow=user_allow, user_deny=user_deny)

    # Log with defanged URL per RULES R-CODE-8, R-SAF-4
    logger.info(
        "url_scanned",
        url_defanged=defang(result.url_canonical or req.url),
        verdict=result.verdict,
        risk_score=result.risk_score,
        latency_ms=result.latency_ms,
        client=req.client,
    )

    return result.to_dict()


@app.post("/v1/scan/batch", status_code=status.HTTP_200_OK)
async def scan_batch_urls(req: BatchScanRequest) -> dict[str, Any]:
    if len(req.urls) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch limit exceeded. Maximum 100 URLs per request.",
        )

    detector = get_detector()
    user_allow = USER_LISTS.get(req.user_key, {}).get("allow") if req.user_key else None
    user_deny = USER_LISTS.get(req.user_key, {}).get("deny") if req.user_key else None
    results = [
        detector.scan(u, user_allow=user_allow, user_deny=user_deny).to_dict()
        for u in req.urls
    ]

    return {
        "count": len(results),
        "results": results,
    }


@app.post("/v1/lists", status_code=status.HTTP_201_CREATED)
async def add_list_entry(req: UserListEntryRequest) -> dict[str, Any]:
    if req.list_type not in ("allow", "deny"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid list_type. Expected 'allow' or 'deny'.",
        )
    user_entry = req.entry.strip().lower()
    # Check if attempting to auto-allow multi-tenant host
    if req.list_type == "allow":
        from phishguard_core.features import MULTITENANT_HOSTS
        from phishguard_core.url import canonicalize
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

    if req.user_key not in USER_LISTS:
        USER_LISTS[req.user_key] = {"allow": set(), "deny": set()}
    USER_LISTS[req.user_key][req.list_type].add(user_entry)

    logger.info("user_list_updated", user_key=req.user_key, list_type=req.list_type, entry=defang(user_entry))
    return {
        "status": "added",
        "user_key": req.user_key,
        "list_type": req.list_type,
        "entry": user_entry,
    }


@app.get("/v1/lists")
async def get_user_lists(user_key: str) -> dict[str, Any]:
    lists = USER_LISTS.get(user_key, {"allow": set(), "deny": set()})
    return {
        "user_key": user_key,
        "allow": sorted(lists["allow"]),
        "deny": sorted(lists["deny"]),
    }


@app.delete("/v1/lists")
async def delete_list_entry(user_key: str, list_type: str, entry: str) -> dict[str, Any]:
    if list_type not in ("allow", "deny"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid list_type. Expected 'allow' or 'deny'.",
        )
    user_entry = entry.strip().lower()
    if user_key in USER_LISTS and user_entry in USER_LISTS[user_key].get(list_type, set()):
        USER_LISTS[user_key][list_type].remove(user_entry)
        return {"status": "deleted", "entry": user_entry}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="List entry not found.")



@app.post("/v1/feedback", status_code=status.HTTP_201_CREATED)
async def submit_feedback(req: FeedbackRequest) -> dict[str, Any]:
    if req.feedback_label not in ("false_positive", "false_negative", "correct"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid feedback label. Expected 'false_positive', 'false_negative', or 'correct'.",
        )

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

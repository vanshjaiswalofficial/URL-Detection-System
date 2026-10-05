"""Database package for PhishGuard AI."""

from backend.app.db.models import (
    Base,
    FeedbackRecord,
    FeedEntryRecord,
    ListRecord,
    ModelRegistryRecord,
    ScanRecord,
)
from backend.app.db.repository import (
    add_user_list_entry,
    delete_user_list_entry,
    get_user_lists,
    hash_key,
    record_feedback,
    record_scan,
)
from backend.app.db.retention import cleanup_expired_scans
from backend.app.db.session import SessionLocal, get_db, init_db

__all__ = [
    "Base",
    "FeedEntryRecord",
    "FeedbackRecord",
    "ListRecord",
    "ModelRegistryRecord",
    "ScanRecord",
    "SessionLocal",
    "add_user_list_entry",
    "cleanup_expired_scans",
    "delete_user_list_entry",
    "get_db",
    "get_user_lists",
    "hash_key",
    "init_db",
    "record_feedback",
    "record_scan",
]

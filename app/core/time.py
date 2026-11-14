"""Small time helpers.

All database timestamps are stored as *naive UTC* so SQLite round-trips are
lossless. `utc_iso()` makes them explicit when hashing or returning JSON.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Current UTC time as a naive datetime (database-safe)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_iso(value: datetime) -> str:
    """ISO-8601 UTC string; naive values are interpreted as UTC."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()

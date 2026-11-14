"""In-process fixed-window rate limiting.

Suitable for a single-process lab deployment. If the API is ever run with
multiple workers or replicas, replace this store with Redis (same interface:
`hit()` returns 0 when allowed, or the number of seconds to wait).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from fastapi import Request

from app.core.config import get_settings
from app.core.errors import AppError


def client_ip(request: Request) -> str:
    """Resolve the client address (proxy headers only when explicitly trusted)."""
    if get_settings().trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return first
    return request.client.host if request.client else "unknown"


@dataclass
class FixedWindow:
    """Counts hits per key inside a fixed time window."""

    limit: int
    window_seconds: int
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _hits: dict[str, tuple[float, int]] = field(default_factory=dict, repr=False)

    def hit(self, key: str) -> int:
        """Register a hit. Returns 0 if allowed, else seconds until retry."""
        now = time.monotonic()
        with self._lock:
            window_start, count = self._hits.get(key, (now, 0))
            if now - window_start >= self.window_seconds:
                window_start, count = now, 0
            if count >= self.limit:
                return max(1, int(self.window_seconds - (now - window_start)) + 1)
            self._hits[key] = (window_start, count + 1)
            # Opportunistic cleanup keeps the dict from growing forever.
            if len(self._hits) > 10_000:
                self._hits = {
                    k: v
                    for k, v in self._hits.items()
                    if now - v[0] < self.window_seconds
                }
            return 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


_limiters: dict[tuple[str, int, int], FixedWindow] = {}
_limiters_lock = threading.Lock()


def get_limiter(scope: str, limit: int, window_seconds: int) -> FixedWindow:
    key = (scope, limit, window_seconds)
    with _limiters_lock:
        limiter = _limiters.get(key)
        if limiter is None:
            limiter = FixedWindow(limit=limit, window_seconds=window_seconds)
            _limiters[key] = limiter
        return limiter


def reset_rate_limiters() -> None:
    """Clear all limiter state (used by tests)."""
    with _limiters_lock:
        for limiter in _limiters.values():
            limiter.reset()
        _limiters.clear()


def enforce(
    request: Request,
    scope: str,
    limit: int,
    window_seconds: int,
    identity: str | None = None,
) -> None:
    """Raise RATE-LIMITED when the caller exceeded the scope's budget."""
    limiter = get_limiter(scope, limit, window_seconds)
    key = identity or client_ip(request)
    retry_after = limiter.hit(key)
    if retry_after:
        raise AppError(
            "RATE-LIMITED",
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            detail=f"scope={scope} key={key}",
        )


async def login_rate_limit(request: Request) -> None:
    """Dependency: limit login attempts per client IP."""
    settings = get_settings()
    enforce(
        request,
        "auth.login",
        settings.login_rate_limit,
        settings.login_rate_window_seconds,
    )


async def register_rate_limit(request: Request) -> None:
    """Dependency: limit account creation per client IP."""
    settings = get_settings()
    enforce(
        request,
        "auth.register",
        settings.register_rate_limit,
        settings.register_rate_window_seconds,
    )

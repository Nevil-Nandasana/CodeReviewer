"""
Sliding-window rate limiting.

Backed by Redis when it is reachable, with an in-process fallback.

The distinction matters and is worth stating plainly: the in-process limiter is
per-worker, so N uvicorn workers allow N times the configured rate, and it
resets on restart. It is a safety net for local development, not a control you
can reason about in production. With Redis the window is shared, so the limit
means what it says regardless of how many workers are running.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = structlog.get_logger(__name__)

# Exempt paths from rate limiting
EXEMPT_PATHS = {"/health", "/metrics", "/docs", "/redoc", "/openapi.json"}

# Stop the in-process fallback from growing without bound when a lot of distinct
# IPs are seen. Idle buckets are evicted oldest-first.
MAX_TRACKED_CLIENTS = 10_000


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 100, window_seconds: int = 60, redis_client=None):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self.redis = redis_client
        self._store: dict[str, deque[float]] = defaultdict(deque)

    def _client_key(self, request: Request) -> str:
        """
        Identify the caller.

        Behind the nginx container every request arrives from the proxy, so
        `request.client.host` is the same value for everybody and the whole
        deployment shares one bucket. Prefer the forwarded client address, and
        take the *first* hop, since later entries are appended by intermediaries
        and are trivially spoofable.
        """
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip", "")
        if real_ip:
            return real_ip.strip()
        return request.client.host if request.client else "unknown"

    def _allow_redis(self, key: str, now: float) -> bool | None:
        """True/False when Redis answered, None when it is unavailable."""
        if self.redis is None:
            return None
        try:
            redis_key = f"ratelimit:{key}"
            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(redis_key, 0, now - self.window)
            pipe.zadd(redis_key, {f"{now}": now})
            pipe.zcard(redis_key)
            pipe.expire(redis_key, self.window + 1)
            count = pipe.execute()[2]
            return count <= self.max_requests
        except Exception as exc:  # noqa: BLE001 - fall back, never fail the request
            logger.warning("ratelimit_redis_unavailable", error=str(exc))
            self.redis = None
            return None

    def _allow_local(self, key: str, now: float) -> bool:
        window_start = now - self.window
        bucket = self._store[key]
        while bucket and bucket[0] <= window_start:
            bucket.popleft()

        if len(bucket) >= self.max_requests:
            return False

        bucket.append(now)

        if len(self._store) > MAX_TRACKED_CLIENTS:
            for stale, times in list(self._store.items()):
                if not times or times[-1] <= window_start:
                    del self._store[stale]

        return True

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        key = self._client_key(request)
        now = time.time()

        allowed = self._allow_redis(key, now)
        if allowed is None:
            allowed = self._allow_local(key, now)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests"},
                headers={"Retry-After": str(self.window)},
            )

        return await call_next(request)

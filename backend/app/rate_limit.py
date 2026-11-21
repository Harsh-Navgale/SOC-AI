"""In-memory, per-process rate limiting — this deployment is a single backend container with
no Redis/shared cache, so a module-level dict is the right amount of infrastructure for it.
Protects the unauthenticated login endpoint from brute-force guessing, and the threat-intel
lookup endpoint from an analyst's browser accidentally burning through a free-tier key's rate
limit (VirusTotal: 4 req/min) via rapid repeat lookups.
"""
import time
from collections import defaultdict

from fastapi import HTTPException, Request

_buckets: dict[str, list[float]] = defaultdict(list)


def _client_key(request: Request, scope: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{scope}:{ip}"


def rate_limit(scope: str, max_calls: int, window_seconds: int):
    async def dependency(request: Request):
        key = _client_key(request, scope)
        now = time.time()
        bucket = _buckets[key]
        cutoff = now - window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= max_calls:
            retry_after = int(bucket[0] + window_seconds - now) + 1
            raise HTTPException(
                status_code=429,
                detail=f"Too many requests — try again in {retry_after}s",
                headers={"Retry-After": str(retry_after)},
            )
        bucket.append(now)
    return dependency


def clear_all():
    """Test-only: reset all rate-limit state between test runs."""
    _buckets.clear()

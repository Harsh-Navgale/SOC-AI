"""In-memory AWS credential cache.

Deliberately NOT persisted to Mongo or disk — the secret access key only ever lives in this
process's memory, for at most SESSION_TTL_SECONDS. This only works correctly with a single
uvicorn worker process (see backend/Dockerfile — no --workers flag); a multi-worker deployment
would need a shared store instead, which would mean this could no longer stay memory-only.
"""
import time
from datetime import datetime, timezone
from typing import Optional

SESSION_TTL_SECONDS = 12 * 60 * 60  # 12 hours

_session: dict = {
    "access_key_id": None,
    "secret_access_key": None,
    "session_token": None,
    "region": None,
    "expires_at": None,
}


def set_credentials(access_key_id: str, secret_access_key: str, session_token: Optional[str], region: str):
    _session["access_key_id"] = access_key_id
    _session["secret_access_key"] = secret_access_key
    _session["session_token"] = session_token
    _session["region"] = region
    _session["expires_at"] = time.time() + SESSION_TTL_SECONDS


def clear_credentials():
    for key in _session:
        _session[key] = None


def _is_valid() -> bool:
    return _session["expires_at"] is not None and time.time() < _session["expires_at"]


def get_credentials() -> Optional[dict]:
    if not _is_valid():
        clear_credentials()
        return None
    return {
        "access_key_id": _session["access_key_id"],
        "secret_access_key": _session["secret_access_key"],
        "session_token": _session["session_token"],
        "region": _session["region"],
    }


def status() -> dict:
    if not _is_valid():
        return {"configured": False, "expires_at": None}
    return {
        "configured": True,
        "expires_at": datetime.fromtimestamp(_session["expires_at"], tz=timezone.utc).isoformat(),
    }

"""In-memory Wazuh Manager credential cache.

Mirrors app.aws_session exactly: NOT persisted to Mongo or disk, held only in this process's
memory for at most SESSION_TTL_SECONDS. This lets an admin connect a real Wazuh Manager from
the UI instead of editing .env + restarting the backend, the same way AWS credentials work.
Same single-uvicorn-worker caveat as aws_session.py applies.
"""
import time
from datetime import datetime, timezone
from typing import Optional

SESSION_TTL_SECONDS = 12 * 60 * 60  # 12 hours

_session: dict = {
    "host": None,
    "user": None,
    "password": None,
    "verify_ssl": None,
    "expires_at": None,
}


def set_credentials(host: str, user: str, password: str, verify_ssl: bool):
    _session["host"] = host.rstrip("/")
    _session["user"] = user
    _session["password"] = password
    _session["verify_ssl"] = verify_ssl
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
        "host": _session["host"],
        "user": _session["user"],
        "password": _session["password"],
        "verify_ssl": _session["verify_ssl"],
    }


def status() -> dict:
    if not _is_valid():
        return {"configured": False, "expires_at": None}
    return {
        "configured": True,
        "expires_at": datetime.fromtimestamp(_session["expires_at"], tz=timezone.utc).isoformat(),
    }

"""Tracks in-progress resumable large-alert-file uploads (app/main.py's
POST /api/alerts/upload/init and friends). A separate concern from upload_jobs.py: a *session*
here is "receiving bytes from the browser, resumable if the connection drops"; a *job* there is
"parsing/inserting the alerts those bytes contain", which only starts once a session completes.

Deliberately simple — this supports one sequential, append-only stream per session (the client
always sends its next unsent byte range in order), not general out-of-order/parallel chunks.
That's the actual requirement: survive a dropped connection and resume from where it left off,
not accept chunks arriving in arbitrary order.
"""
import asyncio
import os
import tempfile
import threading
import time
import uuid

_lock = threading.Lock()
_sessions: dict[str, dict] = {}
_session_locks: dict[str, asyncio.Lock] = {}

# Generous but bounded — sessions are meant to be short-lived (hours, not days) and this whole
# flow is admin-only, so pile-up isn't a realistic concern the way it would be for public upload.
_MAX_SESSIONS = 50


def create_session(filename: str, total_bytes: int) -> dict:
    session_id = str(uuid.uuid4())
    fd, path = tempfile.mkstemp(prefix="alert-upload-session-", suffix=".jsonl")
    os.close(fd)  # just claiming a unique path on disk — chunk writes open it themselves

    with _lock:
        if len(_sessions) >= _MAX_SESSIONS:
            oldest_id = min(_sessions, key=lambda k: _sessions[k]["created_at"])
            _discard_locked(oldest_id)
        _sessions[session_id] = {
            "filename": filename,
            "total_bytes": total_bytes,
            "bytes_received": 0,
            "path": path,
            "created_at": time.time(),
        }
        _session_locks[session_id] = asyncio.Lock()

    return {"session_id": session_id, "bytes_received": 0, "total_bytes": total_bytes}


def get_session(session_id: str) -> dict | None:
    with _lock:
        session = _sessions.get(session_id)
        return dict(session) if session is not None else None


def get_lock(session_id: str) -> asyncio.Lock | None:
    with _lock:
        return _session_locks.get(session_id)


def record_chunk(session_id: str, written: int):
    with _lock:
        session = _sessions.get(session_id)
        if session:
            session["bytes_received"] += written


def _discard_locked(session_id: str):
    session = _sessions.pop(session_id, None)
    _session_locks.pop(session_id, None)
    if session:
        try:
            os.remove(session["path"])
        except OSError:
            pass


def discard_session(session_id: str):
    """Drops a session AND deletes its temp file — for an abandoned or rejected upload."""
    with _lock:
        _discard_locked(session_id)


def forget_session(session_id: str):
    """Drops a session WITHOUT touching its temp file — for a session that completed
    successfully, where the file has just been handed off to a processing job (see
    main.py's complete_alert_upload) that owns cleaning it up once the import finishes."""
    with _lock:
        _sessions.pop(session_id, None)
        _session_locks.pop(session_id, None)

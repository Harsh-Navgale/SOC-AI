"""In-memory progress tracking for large background alert-file imports (app/alerts_upload.py's
streaming path). A plain dict guarded by a lock is enough here — simple attribute updates are
what the background import thread does, the event loop only ever reads a snapshot for the status
endpoint, and losing this state on a backend restart is fine (the import itself would have been
killed too, so there's nothing meaningful left to report).
"""
import threading
import time
import uuid

_lock = threading.Lock()
_jobs: dict[str, dict] = {}

# Old jobs are never explicitly deleted (an analyst might poll status well after completion), so
# this bounds memory for a long-running backend that sees many imports over time.
_MAX_JOBS = 200


def create_job(filename: str, total_bytes: int) -> str:
    job_id = str(uuid.uuid4())
    with _lock:
        if len(_jobs) >= _MAX_JOBS:
            oldest_id = min(_jobs, key=lambda k: _jobs[k]["started_at"])
            del _jobs[oldest_id]
        _jobs[job_id] = {
            "filename": filename,
            "total_bytes": total_bytes,
            "bytes_processed": 0,
            "inserted": 0,
            "duplicates": 0,
            "failed": 0,
            "skipped_low_severity": 0,
            "status": "processing",  # processing | done | error
            "error": None,
            "started_at": time.time(),
            "finished_at": None,
        }
    return job_id


def update_job(job_id: str, **fields):
    with _lock:
        if job_id in _jobs:
            _jobs[job_id].update(fields)


def increment_job(job_id: str, **deltas):
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return
        for key, delta in deltas.items():
            job[key] = job.get(key, 0) + delta


def bump_bytes_processed(job_id: str, value: int):
    """Monotonic update for bytes_processed — only ever moves it forward, and the compare and
    the write happen under the same lock acquisition. Concurrent batches (see main.py's
    _run_large_alert_import, which writes several batches to Mongo at once) can finish in any
    order; a plain "read current, then write mine" from the caller would have a window where a
    later batch's already-larger value gets stomped back down by an earlier batch's smaller one
    finishing after it. Callers should always prefer this over update_job(bytes_processed=...).
    """
    with _lock:
        job = _jobs.get(job_id)
        if job and value > job["bytes_processed"]:
            job["bytes_processed"] = value


def get_job(job_id: str) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job is not None else None

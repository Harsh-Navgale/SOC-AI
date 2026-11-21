import pytest

from app import upload_jobs


@pytest.fixture(autouse=True)
def _reset_jobs():
    # _jobs is a plain module-level dict, shared for the life of the process — without this,
    # jobs created by earlier tests (in this file or test_alerts_upload.py) would still be
    # sitting in it, which would especially break the eviction test below: its len(_jobs) == 2
    # assertion assumes nothing else is in there.
    upload_jobs._jobs.clear()
    yield
    upload_jobs._jobs.clear()


def test_create_job_returns_a_usable_id_with_expected_defaults():
    job_id = upload_jobs.create_job("alerts.json", 1000)
    job = upload_jobs.get_job(job_id)
    assert job["filename"] == "alerts.json"
    assert job["total_bytes"] == 1000
    assert job["bytes_processed"] == 0
    assert job["inserted"] == 0
    assert job["status"] == "processing"
    assert job["finished_at"] is None


def test_get_job_returns_none_for_unknown_id():
    assert upload_jobs.get_job("does-not-exist") is None


def test_update_job_merges_fields():
    job_id = upload_jobs.create_job("a.json", 100)
    upload_jobs.update_job(job_id, status="done", finished_at=123.0)
    job = upload_jobs.get_job(job_id)
    assert job["status"] == "done"
    assert job["finished_at"] == 123.0


def test_increment_job_accumulates_across_calls():
    job_id = upload_jobs.create_job("a.json", 100)
    upload_jobs.increment_job(job_id, inserted=5, duplicates=1)
    upload_jobs.increment_job(job_id, inserted=3, failed=2)
    job = upload_jobs.get_job(job_id)
    assert job["inserted"] == 8
    assert job["duplicates"] == 1
    assert job["failed"] == 2


def test_increment_job_on_unknown_id_is_a_silent_noop():
    upload_jobs.increment_job("does-not-exist", inserted=1)  # must not raise


def test_get_job_returns_a_copy_not_a_live_reference():
    job_id = upload_jobs.create_job("a.json", 100)
    snapshot = upload_jobs.get_job(job_id)
    snapshot["inserted"] = 999
    assert upload_jobs.get_job(job_id)["inserted"] == 0


# ---- bump_bytes_processed: monotonic, race-free progress ----

def test_bump_bytes_processed_moves_forward():
    job_id = upload_jobs.create_job("a.json", 1000)
    upload_jobs.bump_bytes_processed(job_id, 100)
    upload_jobs.bump_bytes_processed(job_id, 500)
    assert upload_jobs.get_job(job_id)["bytes_processed"] == 500


def test_bump_bytes_processed_never_regresses():
    # Simulates a batch that started earlier in the file finishing its write *after* a batch
    # further along — exactly what concurrent writers can produce (see main.py's
    # _run_large_alert_import) — the smaller, later-arriving value must not win.
    job_id = upload_jobs.create_job("a.json", 1000)
    upload_jobs.bump_bytes_processed(job_id, 500)
    upload_jobs.bump_bytes_processed(job_id, 200)
    assert upload_jobs.get_job(job_id)["bytes_processed"] == 500


def test_bump_bytes_processed_on_unknown_id_is_a_silent_noop():
    upload_jobs.bump_bytes_processed("does-not-exist", 100)  # must not raise


# ---- _MAX_JOBS eviction ----

def test_create_job_evicts_the_oldest_job_once_over_the_cap(monkeypatch):
    monkeypatch.setattr(upload_jobs, "_MAX_JOBS", 2)
    first = upload_jobs.create_job("a.json", 1)
    upload_jobs.create_job("b.json", 1)
    upload_jobs.create_job("c.json", 1)  # pushes the cap, first (oldest) should be evicted

    assert upload_jobs.get_job(first) is None
    assert len(upload_jobs._jobs) == 2

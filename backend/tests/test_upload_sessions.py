import os

import pytest

from app import upload_sessions


@pytest.fixture(autouse=True)
def _reset_sessions():
    upload_sessions._sessions.clear()
    upload_sessions._session_locks.clear()
    yield
    # Clean up any temp files left behind by tests that didn't discard their own session.
    for session in upload_sessions._sessions.values():
        try:
            os.remove(session["path"])
        except OSError:
            pass
    upload_sessions._sessions.clear()
    upload_sessions._session_locks.clear()


def test_create_session_returns_expected_shape_and_creates_a_real_temp_file():
    result = upload_sessions.create_session("alerts.json", 50000)
    assert result["bytes_received"] == 0
    assert result["total_bytes"] == 50000
    assert "session_id" in result

    session = upload_sessions.get_session(result["session_id"])
    assert session["filename"] == "alerts.json"
    assert os.path.exists(session["path"])


def test_get_session_returns_none_for_unknown_id():
    assert upload_sessions.get_session("does-not-exist") is None


def test_get_lock_returns_none_for_unknown_id():
    assert upload_sessions.get_lock("does-not-exist") is None


def test_get_lock_returns_the_same_lock_for_a_known_session():
    result = upload_sessions.create_session("a.json", 50000)
    lock1 = upload_sessions.get_lock(result["session_id"])
    lock2 = upload_sessions.get_lock(result["session_id"])
    assert lock1 is lock2


def test_record_chunk_accumulates_bytes_received():
    result = upload_sessions.create_session("a.json", 50000)
    session_id = result["session_id"]

    upload_sessions.record_chunk(session_id, 1000)
    upload_sessions.record_chunk(session_id, 500)

    assert upload_sessions.get_session(session_id)["bytes_received"] == 1500


def test_record_chunk_on_unknown_id_is_a_silent_noop():
    upload_sessions.record_chunk("does-not-exist", 100)  # must not raise


def test_discard_session_removes_tracking_and_the_temp_file():
    result = upload_sessions.create_session("a.json", 50000)
    session_id = result["session_id"]
    path = upload_sessions.get_session(session_id)["path"]
    assert os.path.exists(path)

    upload_sessions.discard_session(session_id)

    assert upload_sessions.get_session(session_id) is None
    assert upload_sessions.get_lock(session_id) is None
    assert not os.path.exists(path)


def test_forget_session_removes_tracking_but_keeps_the_temp_file():
    result = upload_sessions.create_session("a.json", 50000)
    session_id = result["session_id"]
    path = upload_sessions.get_session(session_id)["path"]

    upload_sessions.forget_session(session_id)

    assert upload_sessions.get_session(session_id) is None
    assert os.path.exists(path)
    os.remove(path)  # ours to clean up since forget_session deliberately didn't


def test_create_session_evicts_the_oldest_once_over_the_cap(monkeypatch):
    monkeypatch.setattr(upload_sessions, "_MAX_SESSIONS", 2)
    first = upload_sessions.create_session("a.json", 1)
    upload_sessions.create_session("b.json", 1)
    upload_sessions.create_session("c.json", 1)

    assert upload_sessions.get_session(first["session_id"]) is None
    assert len(upload_sessions._sessions) == 2

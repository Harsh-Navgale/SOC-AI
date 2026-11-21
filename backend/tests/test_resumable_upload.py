import asyncio
import json

import pytest

from app.auth import hash_password


@pytest.fixture(autouse=True)
def _low_large_file_threshold(monkeypatch):
    # Every test in this file is specifically exercising the resumable-upload mechanics, not the
    # "is this actually a big file" judgment call itself — so the small text payloads used here
    # (a couple hundred bytes) need to still count as "large" to reach the code under test.
    monkeypatch.setattr("app.main.LARGE_FILE_THRESHOLD_BYTES", 1)

ALERT_A = {"id": "1690000000.1", "timestamp": "2026-01-01T00:00:00+0000",
           "rule": {"level": 10, "description": "brute force"}, "agent": {"name": "web-01", "ip": "10.0.0.5"}}
ALERT_B = {"id": "1690000000.2", "timestamp": "2026-01-01T00:00:01+0000",
           "rule": {"level": 3, "description": "login ok"}, "agent": {"name": "web-02", "ip": "10.0.0.6"}}


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def _as_analyst(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    return _login(client, "eve", "eve-pw")


# ---- init ----

def test_init_requires_admin(client, mock_db):
    token = _as_analyst(client, mock_db)
    resp = client.post(
        "/api/alerts/upload/init", headers={"Authorization": f"Bearer {token}"},
        json={"filename": "a.jsonl", "total_bytes": 100_000_000},
    )
    assert resp.status_code == 403


def test_init_rejects_a_file_at_or_under_the_small_file_threshold(client, mock_db, monkeypatch):
    # Overrides this file's autouse threshold-lowering fixture back to a real value — this is
    # the one test actually checking the threshold judgment itself, not just using it as a
    # convenient way to reach the resumable-upload code path with a small test payload.
    monkeypatch.setattr("app.main.LARGE_FILE_THRESHOLD_BYTES", 50 * 1024 * 1024)
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/alerts/upload/init", headers=headers, json={"filename": "a.jsonl", "total_bytes": 1000})
    assert resp.status_code == 400
    assert "regular upload" in resp.json()["detail"]


def test_init_returns_a_session_id(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/alerts/upload/init", headers=headers, json={"filename": "a.jsonl", "total_bytes": 100_000_000})
    assert resp.status_code == 200
    body = resp.json()
    assert "session_id" in body
    assert body["bytes_received"] == 0
    assert body["total_bytes"] == 100_000_000


def test_init_is_audited(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/alerts/upload/init", headers=headers, json={"filename": "a.jsonl", "total_bytes": 100_000_000})
    session_id = resp.json()["session_id"]

    entries = client.get("/api/audit-log", headers=headers).json()
    match = next(e for e in entries if e["action"] == "alerts.upload.session_start")
    assert match["details"]["session_id"] == session_id


# ---- session status ----

def test_session_status_requires_admin(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    session_id = client.post(
        "/api/alerts/upload/init", headers=headers, json={"filename": "a.jsonl", "total_bytes": 100_000_000}
    ).json()["session_id"]

    token = _as_analyst(client, mock_db)
    resp = client.get(f"/api/alerts/upload/session/{session_id}/status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_session_status_404_for_unknown_session(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/alerts/upload/session/does-not-exist/status", headers=headers)
    assert resp.status_code == 404


# ---- chunk upload ----

def _init_session(client, headers, total_bytes):
    return client.post(
        "/api/alerts/upload/init", headers=headers, json={"filename": "alerts.jsonl", "total_bytes": total_bytes}
    ).json()["session_id"]


def test_chunk_upload_requires_admin(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    session_id = _init_session(client, headers, 100_000_000)

    token = _as_analyst(client, mock_db)
    resp = client.put(
        f"/api/alerts/upload/session/{session_id}/chunk",
        headers={"Authorization": f"Bearer {token}", "X-Upload-Offset": "0"},
        content=b"hello",
    )
    assert resp.status_code == 403


def test_chunk_upload_404_for_unknown_session(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}", "X-Upload-Offset": "0"}
    resp = client.put("/api/alerts/upload/session/does-not-exist/chunk", headers=headers, content=b"hello")
    assert resp.status_code == 404


def test_chunk_upload_requires_the_offset_header(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    session_id = _init_session(client, headers, 100_000_000)

    resp = client.put(f"/api/alerts/upload/session/{session_id}/chunk", headers=headers, content=b"hello")
    assert resp.status_code == 400


def test_chunk_upload_rejects_a_mismatched_offset_and_reports_the_real_one(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    session_id = _init_session(client, headers, 100_000_000)

    resp = client.put(
        f"/api/alerts/upload/session/{session_id}/chunk",
        headers={**headers, "X-Upload-Offset": "500"},  # server actually has 0
        content=b"hello",
    )
    assert resp.status_code == 409
    assert "server has 0 bytes" in resp.json()["detail"]


def test_sequential_chunks_accumulate_and_the_file_matches_what_was_sent(client, mock_db):
    text = json.dumps(ALERT_A) + "\n" + json.dumps(ALERT_B) + "\n"
    part_a, part_b = text[:20], text[20:]
    headers = {"Authorization": f"Bearer {_login(client)}"}
    session_id = _init_session(client, headers, len(text.encode()))

    r1 = client.put(
        f"/api/alerts/upload/session/{session_id}/chunk",
        headers={**headers, "X-Upload-Offset": "0"}, content=part_a.encode(),
    )
    assert r1.status_code == 200
    assert r1.json()["bytes_received"] == len(part_a.encode())

    r2 = client.put(
        f"/api/alerts/upload/session/{session_id}/chunk",
        headers={**headers, "X-Upload-Offset": str(len(part_a.encode()))}, content=part_b.encode(),
    )
    assert r2.status_code == 200
    assert r2.json()["bytes_received"] == len(text.encode())

    status = client.get(f"/api/alerts/upload/session/{session_id}/status", headers=headers).json()
    assert status["bytes_received"] == len(text.encode())


# ---- complete ----

def test_complete_requires_admin(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    text = json.dumps(ALERT_A) + "\n"
    session_id = _init_session(client, headers, len(text.encode()))
    client.put(
        f"/api/alerts/upload/session/{session_id}/chunk",
        headers={**headers, "X-Upload-Offset": "0"}, content=text.encode(),
    )

    token = _as_analyst(client, mock_db)
    resp = client.post(f"/api/alerts/upload/session/{session_id}/complete", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_complete_404_for_unknown_session(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/alerts/upload/session/does-not-exist/complete", headers=headers)
    assert resp.status_code == 404


def test_complete_rejects_an_incomplete_upload(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    text = json.dumps(ALERT_A) + "\n"
    session_id = _init_session(client, headers, len(text.encode()) + 100)  # claim more than we'll send

    resp = client.post(f"/api/alerts/upload/session/{session_id}/complete", headers=headers)
    assert resp.status_code == 409
    assert "Upload incomplete" in resp.json()["detail"]


def test_complete_rejects_a_json_array_and_discards_the_session(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    text = json.dumps([ALERT_A, ALERT_B])
    session_id = _init_session(client, headers, len(text.encode()))
    client.put(
        f"/api/alerts/upload/session/{session_id}/chunk",
        headers={**headers, "X-Upload-Offset": "0"}, content=text.encode(),
    )

    resp = client.post(f"/api/alerts/upload/session/{session_id}/complete", headers=headers)
    assert resp.status_code == 400
    assert "JSON Lines" in resp.json()["detail"]

    # The session (and its now-useless temp file) must not be left dangling.
    status = client.get(f"/api/alerts/upload/session/{session_id}/status", headers=headers)
    assert status.status_code == 404


def test_complete_starts_a_job_and_hands_off_the_session(client, mock_db):
    # What actually happens once _run_large_alert_import runs (parsing, inserting, marking the
    # job done) is covered directly in test_alerts_upload.py, the same way as for the
    # single-shot large-upload path — not here, for the same reason noted there: a background
    # task fired via asyncio.create_task() from inside a request has no guarantee of getting
    # event-loop time from *later, separate* TestClient calls in the same test, so polling for
    # completion through the HTTP layer is flaky by construction, not just here. What this test
    # checks is everything that genuinely happens synchronously, before the response is sent.
    headers = {"Authorization": f"Bearer {_login(client)}"}
    text = json.dumps(ALERT_A) + "\n" + json.dumps(ALERT_B) + "\n"
    session_id = _init_session(client, headers, len(text.encode()))
    client.put(
        f"/api/alerts/upload/session/{session_id}/chunk",
        headers={**headers, "X-Upload-Offset": "0"}, content=text.encode(),
    )

    resp = client.post(f"/api/alerts/upload/session/{session_id}/complete", headers=headers)
    assert resp.status_code == 200
    assert "job_id" in resp.json()
    assert resp.json()["total_bytes"] == len(text.encode())

    # The session is gone from tracking (its file now belongs to the job, which will delete it
    # itself once done — forget_session, not discard_session, is what makes that ownership
    # handoff work without a double-delete).
    status = client.get(f"/api/alerts/upload/session/{session_id}/status", headers=headers)
    assert status.status_code == 404


def test_complete_is_audited(client, mock_db):
    # The audit entry is written synchronously, before the response is returned — same as the
    # single-shot large-upload path, it doesn't depend on the background job ever running.
    headers = {"Authorization": f"Bearer {_login(client)}"}
    text = json.dumps(ALERT_A) + "\n"
    session_id = _init_session(client, headers, len(text.encode()))
    client.put(
        f"/api/alerts/upload/session/{session_id}/chunk",
        headers={**headers, "X-Upload-Offset": "0"}, content=text.encode(),
    )
    resp = client.post(f"/api/alerts/upload/session/{session_id}/complete", headers=headers)
    job_id = resp.json()["job_id"]

    entries = client.get("/api/audit-log", headers=headers).json()
    match = next(e for e in entries if e["action"] == "alerts.upload.start" and e["details"].get("job_id") == job_id)
    assert match["details"]["filename"] == "alerts.jsonl"

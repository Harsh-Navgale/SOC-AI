import asyncio
import time

from app.auth import hash_password


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def test_get_latest_eval_report_404_when_no_run_has_happened(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/eval/latest", headers=headers)
    assert resp.status_code == 404


def test_start_eval_run_requires_admin(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/eval/run", json={"sample_size": 5}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_get_latest_eval_report_requires_admin(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.get("/api/eval/latest", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_start_eval_run_launches_in_the_background_and_eventually_completes(client, mock_db, monkeypatch):
    headers = {"Authorization": f"Bearer {_login(client)}"}

    async def fake_run_eval(sample_size):
        await mock_db["eval_reports"].update_one(
            {"_id": "latest"}, {"$set": {"status": "done", "sample_size_scored": 0, "agreement_rate": None}}, upsert=True,
        )

    monkeypatch.setattr("app.main.eval_harness.run_eval", fake_run_eval)

    resp = client.post("/api/eval/run", json={"sample_size": 5}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "running"

    for _ in range(20):
        report = client.get("/api/eval/latest", headers=headers).json()
        if report["status"] == "done":
            break
        time.sleep(0.05)

    assert report["status"] == "done"


def test_start_eval_run_rejects_a_second_run_while_one_is_in_progress(client, mock_db, monkeypatch):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    asyncio.run(mock_db["eval_reports"].insert_one({"_id": "latest", "status": "running"}))

    resp = client.post("/api/eval/run", json={"sample_size": 5}, headers=headers)
    assert resp.status_code == 409


def test_start_eval_run_validates_sample_size_bounds(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/eval/run", json={"sample_size": 0}, headers=headers)
    assert resp.status_code == 422

    resp = client.post("/api/eval/run", json={"sample_size": 1000}, headers=headers)
    assert resp.status_code == 422

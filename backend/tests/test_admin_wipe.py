import asyncio

from app.auth import hash_password


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def _seed_data(mock_db):
    asyncio.run(mock_db["raw_alerts"].insert_many([
        {"_id": "a1", "correlated": True}, {"_id": "a2", "correlated": False},
    ]))
    asyncio.run(mock_db["incidents"].insert_many([
        {"_id": "case-1", "source_ip": "10.0.0.5", "case_status": "open"},
        {"_id": "inc-1", "source_ip": "10.0.0.6", "case_status": "open", "investigation": {"raw": "done"}},
    ]))


def test_wipe_deletes_everything_from_both_collections(client, mock_db):
    _seed_data(mock_db)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/admin/wipe-alert-data", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["raw_alerts_deleted"] == 2
    assert body["incidents_deleted"] == 2

    assert asyncio.run(mock_db["raw_alerts"].count_documents({})) == 0
    assert asyncio.run(mock_db["incidents"].count_documents({})) == 0


def test_wipe_returns_zero_counts_when_already_empty(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/admin/wipe-alert-data", headers=headers)
    assert resp.json() == {"raw_alerts_deleted": 0, "incidents_deleted": 0}


def test_wipe_leaves_other_collections_alone(client, mock_db):
    _seed_data(mock_db)
    asyncio.run(mock_db["audit_log"].insert_one({"_id": "audit-1", "action": "something", "timestamp": "x"}))
    headers = {"Authorization": f"Bearer {_login(client)}"}

    client.post("/api/admin/wipe-alert-data", headers=headers)

    # The wipe's own audit entry, plus the pre-existing one, must both survive — deleting the
    # audit log would erase the record of the wipe having happened at all.
    entries = client.get("/api/audit-log", headers=headers).json()
    assert any(e["_id"] == "audit-1" for e in entries)
    assert any(e["action"] == "admin.wipe_alert_data" for e in entries)


def test_wipe_is_audited_with_counts(client, mock_db):
    _seed_data(mock_db)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    client.post("/api/admin/wipe-alert-data", headers=headers)

    entries = client.get("/api/audit-log", headers=headers).json()
    match = next(e for e in entries if e["action"] == "admin.wipe_alert_data")
    assert match["details"]["raw_alerts_deleted"] == 2
    assert match["details"]["incidents_deleted"] == 2


def test_wipe_requires_admin(client, mock_db):
    _seed_data(mock_db)
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/admin/wipe-alert-data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    # Nothing was touched by the rejected request.
    assert asyncio.run(mock_db["raw_alerts"].count_documents({})) == 2
    assert asyncio.run(mock_db["incidents"].count_documents({})) == 2


def test_wipe_broadcasts_change_events(client, mock_db, monkeypatch):
    _seed_data(mock_db)
    broadcasts = []

    async def fake_broadcast(msg):
        broadcasts.append(msg)

    monkeypatch.setattr("app.main.ws_manager.broadcast", fake_broadcast)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    client.post("/api/admin/wipe-alert-data", headers=headers)

    types = {b["type"] for b in broadcasts}
    assert "alerts_changed" in types
    assert "incidents_changed" in types

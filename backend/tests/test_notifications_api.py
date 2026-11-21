import asyncio

from app.auth import hash_password


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def _seed_incident(mock_db, incident_id="inc-1", **overrides):
    doc = {
        "_id": incident_id, "source_ip": "10.0.0.5", "case_status": "open", "assigned_to": None,
        "notes": [], "severity": "low", "alert_count": 1, "max_level": 5, "mitre_ids": [],
        "mitre_tactics": [], "rule_description": "test rule", "last_seen": 0,
    }
    doc.update(overrides)
    asyncio.run(mock_db["incidents"].insert_one(doc))


def _create_analyst(mock_db, username="eve", password="eve-pw"):
    asyncio.run(mock_db["users"].insert_one({
        "_id": username, "password_hash": hash_password(password), "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))


def test_assigning_a_case_notifies_the_assignee(client, mock_db):
    _create_analyst(mock_db)
    _seed_incident(mock_db)
    admin_headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.patch("/api/incidents/inc-1", json={"assigned_to": "eve"}, headers=admin_headers)
    assert resp.status_code == 200

    eve_headers = {"Authorization": f"Bearer {_login(client, 'eve', 'eve-pw')}"}
    notes = client.get("/api/notifications", headers=eve_headers).json()
    assert notes["unread"] == 1
    assert "admin assigned you a case" in notes["items"][0]["message"]


def test_assigning_to_yourself_does_not_notify(client, mock_db):
    _seed_incident(mock_db)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    client.patch("/api/incidents/inc-1", json={"assigned_to": "admin"}, headers=headers)

    notes = client.get("/api/notifications", headers=headers).json()
    assert notes["unread"] == 0


def test_mark_notification_read_and_read_all(client, mock_db):
    _create_analyst(mock_db)
    _seed_incident(mock_db)
    admin_headers = {"Authorization": f"Bearer {_login(client)}"}
    client.patch("/api/incidents/inc-1", json={"assigned_to": "eve"}, headers=admin_headers)

    eve_headers = {"Authorization": f"Bearer {_login(client, 'eve', 'eve-pw')}"}
    notification_id = client.get("/api/notifications", headers=eve_headers).json()["items"][0]["_id"]

    resp = client.post(f"/api/notifications/{notification_id}/read", headers=eve_headers)
    assert resp.status_code == 200
    assert client.get("/api/notifications", headers=eve_headers).json()["unread"] == 0

    client.patch("/api/incidents/inc-1", json={"assigned_to": "eve"}, headers=admin_headers)
    assert client.get("/api/notifications", headers=eve_headers).json()["unread"] == 1
    client.post("/api/notifications/read-all", headers=eve_headers)
    assert client.get("/api/notifications", headers=eve_headers).json()["unread"] == 0

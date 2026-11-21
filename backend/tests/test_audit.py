import asyncio


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def _seed_incident(mock_db, incident_id="inc-1", **overrides):
    doc = {
        "_id": incident_id,
        "source_ip": "10.0.0.5",
        "case_status": "open",
        "assigned_to": None,
        "notes": [],
        "severity": "low",
        "alert_count": 1,
        "max_level": 5,
        "mitre_ids": [],
        "mitre_tactics": [],
        "rule_description": "test rule",
        "last_seen": 0,
    }
    doc.update(overrides)
    asyncio.run(mock_db["incidents"].insert_one(doc))


def test_creating_a_user_is_audited(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    client.post("/api/users", json={"username": "bob", "password": "pw123456", "role": "analyst"}, headers=headers)

    resp = client.get("/api/audit-log", headers=headers)
    assert resp.status_code == 200
    entries = resp.json()
    assert any(e["action"] == "user.create" and e["target"] == "bob" and e["actor"] == "admin" for e in entries)


def test_deleting_a_user_is_audited(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    client.post("/api/users", json={"username": "bob", "password": "pw123456", "role": "analyst"}, headers=headers)
    client.delete("/api/users/bob", headers=headers)

    entries = client.get("/api/audit-log", headers=headers).json()
    assert any(e["action"] == "user.delete" and e["target"] == "bob" for e in entries)


def test_closing_an_incident_is_audited(client, mock_db, monkeypatch):
    _seed_incident(mock_db)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    async def fake_embed(incident, resolution, disposition):
        return None
    monkeypatch.setattr("app.main.embed_case_resolution", fake_embed)

    client.post(
        "/api/incidents/inc-1/close",
        json={"resolution": "false positive", "disposition": "false_positive"},
        headers=headers,
    )

    entries = client.get("/api/audit-log", headers=headers).json()
    match = next(e for e in entries if e["action"] == "incident.close")
    assert match["target"] == "inc-1"
    assert match["details"]["resolution"] == "false positive"
    assert match["details"]["disposition"] == "false_positive"


def test_incident_status_update_is_audited(client, mock_db):
    _seed_incident(mock_db)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    client.patch("/api/incidents/inc-1", json={"case_status": "investigating"}, headers=headers)

    entries = client.get("/api/audit-log", headers=headers).json()
    match = next(e for e in entries if e["action"] == "incident.update")
    assert match["details"] == {"case_status": "investigating"}


def test_audit_log_requires_admin(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    client.post("/api/users", json={"username": "carol", "password": "pw123456", "role": "analyst"}, headers=headers)
    analyst_headers = {"Authorization": f"Bearer {_login(client, 'carol', 'pw123456')}"}

    resp = client.get("/api/audit-log", headers=analyst_headers)
    assert resp.status_code == 403


def test_audit_log_write_failure_does_not_break_the_action(client, mock_db, monkeypatch):
    async def failing_insert(*args, **kwargs):
        raise RuntimeError("mongo is down")
    monkeypatch.setattr("app.audit.audit_log.insert_one", failing_insert)

    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/users", json={"username": "dave", "password": "pw123456", "role": "analyst"}, headers=headers)
    assert resp.status_code == 200

import asyncio


def _login(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    return resp.json()["access_token"]


def _seed_alert(mock_db, alert_id, level, description, agent_name="web-01", agent_ip="10.0.0.15", ts="2026-01-01T00:00:00+00:00"):
    asyncio.run(mock_db["raw_alerts"].insert_one({
        "_id": alert_id,
        "timestamp": ts,
        "correlated": False,
        "agent": {"id": "001", "name": agent_name, "ip": agent_ip},
        "rule": {"id": "5710", "level": level, "description": description},
    }))


def test_list_alerts_returns_items_and_total(client, mock_db):
    _seed_alert(mock_db, "a1", 5, "test rule")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/alerts", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["_id"] == "a1"


def test_list_alerts_filters_by_severity(client, mock_db):
    _seed_alert(mock_db, "a1", 12, "high sev rule")
    _seed_alert(mock_db, "a2", 3, "low sev rule")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    high = client.get("/api/alerts?severity=high", headers=headers).json()
    assert [a["_id"] for a in high["items"]] == ["a1"]

    low = client.get("/api/alerts?severity=low", headers=headers).json()
    assert [a["_id"] for a in low["items"]] == ["a2"]


def test_list_alerts_search_matches_rule_or_agent(client, mock_db):
    _seed_alert(mock_db, "a1", 5, "sshd: brute force attempt", agent_name="web-01")
    _seed_alert(mock_db, "a2", 5, "port scan detected", agent_name="db-02")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    by_rule = client.get("/api/alerts?search=brute", headers=headers).json()
    assert [a["_id"] for a in by_rule["items"]] == ["a1"]

    by_agent = client.get("/api/alerts?search=db-02", headers=headers).json()
    assert [a["_id"] for a in by_agent["items"]] == ["a2"]


def test_list_alerts_pagination(client, mock_db):
    for i in range(5):
        _seed_alert(mock_db, f"a{i}", 5, "test rule", ts=f"2026-01-01T00:0{i}:00+00:00")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    page1 = client.get("/api/alerts?limit=2&skip=0", headers=headers).json()
    assert page1["total"] == 5
    assert len(page1["items"]) == 2
    assert page1["items"][0]["_id"] == "a4"  # sorted by timestamp desc

    page2 = client.get("/api/alerts?limit=2&skip=2", headers=headers).json()
    assert len(page2["items"]) == 2
    assert {a["_id"] for a in page1["items"]}.isdisjoint({a["_id"] for a in page2["items"]})


def test_list_alerts_requires_auth(client, mock_db):
    resp = client.get("/api/alerts")
    assert resp.status_code == 401


def test_delete_alert(client, mock_db):
    _seed_alert(mock_db, "a1", 5, "test rule")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.delete("/api/alerts/a1", headers=headers)
    assert resp.status_code == 200

    stored = asyncio.run(mock_db["raw_alerts"].find_one({"_id": "a1"}))
    assert stored is None


def test_delete_alert_not_found(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.delete("/api/alerts/does-not-exist", headers=headers)
    assert resp.status_code == 404


def test_delete_alert_requires_admin(client, mock_db):
    from app.auth import hash_password
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    _seed_alert(mock_db, "a1", 5, "test rule")
    token = _login_as(client, "eve", "eve-pw")

    resp = client.delete("/api/alerts/a1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_delete_alerts_bulk(client, mock_db):
    _seed_alert(mock_db, "a1", 5, "rule 1")
    _seed_alert(mock_db, "a2", 5, "rule 2")
    _seed_alert(mock_db, "a3", 5, "rule 3")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/delete-bulk", json={"ids": ["a1", "a2"]}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 2

    remaining = client.get("/api/alerts", headers=headers).json()
    assert remaining["total"] == 1
    assert remaining["items"][0]["_id"] == "a3"


def test_delete_alert_is_audited(client, mock_db):
    _seed_alert(mock_db, "a1", 5, "test rule")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    client.delete("/api/alerts/a1", headers=headers)

    entries = client.get("/api/audit-log", headers=headers).json()
    assert any(e["action"] == "alert.delete" and e["target"] == "a1" for e in entries)


def _login_as(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password}).json()["access_token"]

import asyncio

from app.auth import hash_password
from app.s3_inventory import S3CredentialsRequired, S3AuthenticationFailed, S3NotConfigured


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def _as_analyst(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))
    return _login(client, "eve", "eve-pw")


# ---- POST /api/assets/refresh-cache ----

def test_refresh_cache_requires_admin(client, mock_db):
    token = _as_analyst(client, mock_db)
    resp = client.post("/api/assets/refresh-cache", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_refresh_cache_returns_count_and_audit_logs(client, mock_db, monkeypatch):
    token = _login(client)

    async def fake_refresh():
        return 7

    monkeypatch.setattr("app.main.asset_cache.refresh", fake_refresh)

    resp = client.post("/api/assets/refresh-cache", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"count": 7}

    entries = asyncio.run(mock_db["audit_log"].find({}).to_list(length=None))
    assert any(e["action"] == "assets.refresh_cache" for e in entries)


def test_refresh_cache_reports_aws_session_required(client, mock_db, monkeypatch):
    token = _login(client)

    async def raise_creds_required():
        raise S3CredentialsRequired()

    monkeypatch.setattr("app.main.asset_cache.refresh", raise_creds_required)

    resp = client.post("/api/assets/refresh-cache", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 409
    assert "AWS session" in resp.json()["detail"]


def test_refresh_cache_reports_auth_failure_as_reconnect(client, mock_db, monkeypatch):
    token = _login(client)

    async def raise_auth_failed():
        raise S3AuthenticationFailed("AWS rejected the credentials: ExpiredToken")

    monkeypatch.setattr("app.main.asset_cache.refresh", raise_auth_failed)

    resp = client.post("/api/assets/refresh-cache", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 409
    assert "AWS session" in resp.json()["detail"]


def test_refresh_cache_reports_s3_not_configured(client, mock_db, monkeypatch):
    token = _login(client)

    async def raise_not_configured():
        raise S3NotConfigured()

    monkeypatch.setattr("app.main.asset_cache.refresh", raise_not_configured)

    resp = client.post("/api/assets/refresh-cache", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 409
    assert "S3_INVENTORY_BUCKET" in resp.json()["detail"]


def test_refresh_cache_maps_unexpected_errors_to_502(client, mock_db, monkeypatch):
    token = _login(client)

    async def raise_boom():
        raise RuntimeError("boom")

    monkeypatch.setattr("app.main.asset_cache.refresh", raise_boom)

    resp = client.post("/api/assets/refresh-cache", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 502


# ---- GET /api/assets/cache-status ----

def test_cache_status_reports_empty_before_any_refresh(client, mock_db):
    token = _login(client)
    resp = client.get("/api/assets/cache-status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"refreshed_at": None, "count": 0}


def test_cache_status_reflects_a_populated_cache(client, mock_db):
    token = _login(client)
    asyncio.run(mock_db["asset_inventory_cache"].insert_one({"_id": "10.0.0.5", "hostname": "db-02", "raw": {}}))
    asyncio.run(mock_db["asset_inventory_cache_meta"].update_one(
        {"_id": "asset_inventory"},
        {"$set": {"refreshed_at": "2026-08-26T00:00:00+00:00", "count": 1}},
        upsert=True,
    ))

    resp = client.get("/api/assets/cache-status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"refreshed_at": "2026-08-26T00:00:00+00:00", "count": 1}


def test_cache_status_is_available_to_any_authenticated_user(client, mock_db):
    token = _as_analyst(client, mock_db)
    resp = client.get("/api/assets/cache-status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200

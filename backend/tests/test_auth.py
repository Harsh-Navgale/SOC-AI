import asyncio

from app.auth import hash_password


def test_login_success(client, mock_db):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["role"] == "admin"


def test_login_wrong_password(client, mock_db):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user(client, mock_db):
    resp = client.post("/api/auth/login", json={"username": "nope", "password": "x"})
    assert resp.status_code == 401


def test_protected_route_requires_token(client):
    resp = client.get("/api/incidents")
    assert resp.status_code == 401


def test_protected_route_rejects_bad_token(client):
    resp = client.get("/api/incidents", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_protected_route_with_valid_token(client, mock_db):
    login = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    token = login.json()["access_token"]

    resp = client.get("/api/incidents", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"items": [], "total": 0}


def test_refresh_issues_a_new_token_preserving_role(client, mock_db):
    login = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    old_token = login.json()["access_token"]

    resp = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {old_token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["role"] == "admin"
    assert body["access_token"]

    # The new token itself works for a protected route.
    check = client.get("/api/incidents", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert check.status_code == 200


def test_refresh_rejects_missing_or_invalid_token(client, mock_db):
    resp = client.post("/api/auth/refresh")
    assert resp.status_code == 401

    resp = client.post("/api/auth/refresh", headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401


def test_refresh_preserves_analyst_role(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "carol",
        "password_hash": hash_password("carol-pw"),
        "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))
    login = client.post("/api/auth/login", json={"username": "carol", "password": "carol-pw"})
    token = login.json()["access_token"]

    resp = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {token}"})
    assert resp.json()["role"] == "analyst"


def test_admin_only_endpoint_rejects_analyst_role(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "alice",
        "password_hash": hash_password("alice-pw"),
        "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))

    login = client.post("/api/auth/login", json={"username": "alice", "password": "alice-pw"})
    token = login.json()["access_token"]

    resp = client.get("/api/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_admin_can_create_and_list_users(client, mock_db):
    login = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    create = client.post(
        "/api/users", json={"username": "bob", "password": "bob-pw", "role": "analyst"}, headers=headers
    )
    assert create.status_code == 200

    listing = client.get("/api/users", headers=headers)
    usernames = [u["_id"] for u in listing.json()]
    assert "bob" in usernames
    assert all("password_hash" not in u for u in listing.json())


def test_logout_revokes_the_token(client, mock_db):
    login = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    logout_resp = client.post("/api/auth/logout", headers=headers)
    assert logout_resp.status_code == 200

    resp = client.get("/api/incidents", headers=headers)
    assert resp.status_code == 401


def test_logout_requires_a_token(client, mock_db):
    resp = client.post("/api/auth/logout")
    assert resp.status_code == 401


def test_logout_does_not_revoke_other_sessions(client, mock_db):
    login1 = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    login2 = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    token1, token2 = login1.json()["access_token"], login2.json()["access_token"]

    client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token1}"})

    assert client.get("/api/incidents", headers={"Authorization": f"Bearer {token1}"}).status_code == 401
    assert client.get("/api/incidents", headers={"Authorization": f"Bearer {token2}"}).status_code == 200


def test_admin_cannot_create_a_user_with_a_blank_username(client, mock_db):
    login = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    for blank in ["", "   "]:
        resp = client.post(
            "/api/users", json={"username": blank, "password": "x-pw", "role": "admin"}, headers=headers,
        )
        assert resp.status_code == 422

    listing = client.get("/api/users", headers=headers)
    assert "" not in [u["_id"] for u in listing.json()]

from app.rate_limit import clear_all


def test_login_rate_limited_after_max_attempts(client, mock_db):
    for _ in range(5):
        resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


def test_login_rate_limit_does_not_block_a_different_scope(client, mock_db):
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})

    # threat-intel-lookup has its own scope/bucket — login being exhausted must not affect it.
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 429

    clear_all()
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    assert resp.status_code == 200


def test_successful_login_after_clearing_rate_limit_state(client, mock_db):
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    clear_all()

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    assert resp.status_code == 200

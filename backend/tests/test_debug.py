import asyncio

from app import debug_state
from app.auth import hash_password


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def _reset_debug_state():
    asyncio.run(debug_state.set_debug_mode(False))
    debug_state._recent_errors.clear()


def test_debug_mode_defaults_to_disabled(client, mock_db):
    _reset_debug_state()
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/debug/mode", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


def test_admin_can_toggle_debug_mode(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    try:
        resp = client.post("/api/debug/mode", json={"enabled": True}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["enabled"] is True
        assert debug_state.get_debug_mode() is True

        assert client.get("/api/debug/mode", headers=headers).json()["enabled"] is True

        entries = client.get("/api/audit-log", headers=headers).json()
        match = next(e for e in entries if e["action"] == "debug_mode.set")
        assert match["details"]["enabled"] is True
    finally:
        _reset_debug_state()


def test_non_admin_cannot_toggle_debug_mode(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/debug/mode", json={"enabled": True}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_debug_diagnostics_requires_admin(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.get("/api/debug/diagnostics", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_debug_diagnostics_includes_effective_config_and_recent_errors(client, mock_db, monkeypatch):
    _reset_debug_state()
    debug_state.record_error("auto_investigate_cases", "case abc: Bedrock unreachable")

    asyncio.run(mock_db["system_heartbeats"].insert_one({
        "_id": "correlator", "last_run": 123.0, "alerts_processed_total": 42,
    }))

    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/debug/diagnostics", headers=headers)
    assert resp.status_code == 200
    body = resp.json()

    assert body["correlation"]["threshold"] > 0
    assert body["correlator"]["alerts_processed_total"] == 42
    assert "_id" not in body["correlator"]
    assert body["recent_errors"][0]["source"] == "auto_investigate_cases"
    assert "aws" in body["integrations"]
    assert body["active_alerts"] == []
    assert body["ai_usage"]["calls"] == 0

    _reset_debug_state()


def test_debug_diagnostics_includes_active_alerts_and_ai_usage(client, mock_db, monkeypatch):
    from app import alerting, ai_usage

    monkeypatch.setattr(alerting.ws_manager, "broadcast", lambda msg: asyncio.sleep(0))

    for _ in range(3):
        asyncio.run(alerting.record_failure("poll_wazuh", "unreachable"))
    asyncio.run(ai_usage.record("investigate", "phi4-mini", 500, 100, parse_ok=True))

    headers = {"Authorization": f"Bearer {_login(client)}"}
    body = client.get("/api/debug/diagnostics", headers=headers).json()

    assert body["active_alerts"][0]["source"] == "poll_wazuh"
    assert body["ai_usage"]["calls"] == 1
    assert body["ai_usage"]["prompt_tokens"] == 500

    alerting._consecutive_failures.clear()
    alerting._active_alerts.clear()


def test_active_alerts_endpoint_visible_to_any_authenticated_user(client, mock_db, monkeypatch):
    from app import alerting

    monkeypatch.setattr(alerting.ws_manager, "broadcast", lambda msg: asyncio.sleep(0))
    for _ in range(3):
        asyncio.run(alerting.record_failure("poll_wazuh", "unreachable"))

    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.get("/api/alerts/active", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["items"][0]["source"] == "poll_wazuh"

    alerting._consecutive_failures.clear()
    alerting._active_alerts.clear()

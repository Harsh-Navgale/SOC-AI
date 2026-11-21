import asyncio

import pytest

from app import manual_agents, wazuh_session, wazuh_manager_client
from app.auth import hash_password
from app.wazuh_manager_client import WazuhManagerNotConfigured


@pytest.fixture(autouse=True)
def _reset_state():
    wazuh_session.clear_credentials()
    manual_agents.clear_agents()
    yield
    wazuh_session.clear_credentials()
    manual_agents.clear_agents()


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


# ---- manual_agents.parse_csv ----

def test_parse_csv_maps_standard_columns():
    raw = b"name,ip,status\nweb01,10.0.0.1,active\nweb02,10.0.0.2,disconnected\n"
    agents = manual_agents.parse_csv(raw)
    assert agents == [
        {"id": "manual-web01", "name": "web01", "ip": "10.0.0.1", "status": "active", "raw": {"name": "web01", "ip": "10.0.0.1", "status": "active"}},
        {"id": "manual-web02", "name": "web02", "ip": "10.0.0.2", "status": "disconnected", "raw": {"name": "web02", "ip": "10.0.0.2", "status": "disconnected"}},
    ]


def test_parse_csv_uses_explicit_id_column_when_present():
    raw = b"id,name,ip,status\n042,web01,10.0.0.1,active\n"
    agents = manual_agents.parse_csv(raw)
    assert agents[0]["id"] == "042"


def test_parse_csv_maps_real_wazuh_export_column_names():
    """Regression test: a real Wazuh Manager UI export uses "ID", "Status", "Name", "IP
    address" (with a space) as its column headers — none of which matched the old
    exact-case field list, so every agent's `ip` silently came back None and Coverage
    Comparison showed every single S3 record as 'missing' even when the agent was really
    there, just under a differently-spelled column."""
    raw = (
        b"ID,Status,Name,IP address,Group\n"
        b"007,active,ip-10-10-13-64.ap-south-1.compute.internal,10.10.13.64,default\n"
    )
    agents = manual_agents.parse_csv(raw)
    assert agents[0]["ip"] == "10.10.13.64"
    assert agents[0]["id"] == "007"
    assert agents[0]["name"] == "ip-10-10-13-64.ap-south-1.compute.internal"
    assert agents[0]["status"] == "active"


def test_parse_csv_ip_field_matching_is_case_and_separator_insensitive():
    for header in ("ip_address", "IP_ADDRESS", "IP-Address", "Ip Address", "ipaddress"):
        raw = f"name,{header}\nweb01,10.0.0.5\n".encode()
        agents = manual_agents.parse_csv(raw)
        assert agents[0]["ip"] == "10.0.0.5", f"failed for header {header!r}"


def test_parse_csv_never_drops_rows_without_a_name():
    """A row that doesn't have a recognizable name column still comes through — with a
    synthesized positional id and name=None — rather than vanishing from the sheet."""
    raw = b"name,ip,status\n,10.0.0.1,active\nweb02,10.0.0.2,active\n"
    agents = manual_agents.parse_csv(raw)
    assert len(agents) == 2
    assert agents[0]["name"] is None
    assert agents[0]["id"] == "manual-row-0"
    assert agents[0]["raw"] == {"name": "", "ip": "10.0.0.1", "status": "active"}
    assert agents[1]["name"] == "web02"


def test_parse_csv_preserves_every_extra_column():
    raw = b"name,ip,status,os,version,group\nweb01,10.0.0.1,active,ubuntu,4.9,default\n"
    agents = manual_agents.parse_csv(raw)
    assert agents[0]["raw"] == {
        "name": "web01", "ip": "10.0.0.1", "status": "active",
        "os": "ubuntu", "version": "4.9", "group": "default",
    }


def test_parse_csv_preserves_duplicate_headers():
    raw = b"name,ip,ip\nweb01,10.0.0.1,192.168.1.1\n"
    agents = manual_agents.parse_csv(raw)
    assert agents[0]["raw"] == {"name": "web01", "ip": "10.0.0.1", "ip_1": "192.168.1.1"}


def test_parse_csv_defaults_missing_status_to_unknown():
    raw = b"name,ip\nweb01,10.0.0.1\n"
    agents = manual_agents.parse_csv(raw)
    assert agents[0]["status"] == "unknown"


# ---- manual_agents session lifecycle ----

def test_manual_agents_status_and_expiry():
    assert manual_agents.status()["configured"] is False

    manual_agents.set_agents([{"id": "manual-web01", "name": "web01", "ip": None, "status": "active"}], "admin")
    status = manual_agents.status()
    assert status["configured"] is True
    assert status["count"] == 1
    assert status["uploaded_by"] == "admin"

    manual_agents.clear_agents()
    assert manual_agents.get_agents() is None


# ---- wazuh_manager_client.list_agents_with_fallback ----

def test_fallback_uses_manual_sheet_when_not_configured(monkeypatch):
    manual_agents.set_agents([{"id": "manual-web01", "name": "web01", "ip": "10.0.0.1", "status": "active"}], "admin")

    async def raise_not_configured():
        raise WazuhManagerNotConfigured()

    monkeypatch.setattr(wazuh_manager_client, "list_agents", raise_not_configured)

    agents, source = asyncio.run(wazuh_manager_client.list_agents_with_fallback())
    assert source == "manual"
    assert agents[0]["name"] == "web01"


def test_fallback_uses_manual_sheet_when_live_call_errors(monkeypatch):
    manual_agents.set_agents([{"id": "manual-web01", "name": "web01", "ip": "10.0.0.1", "status": "active"}], "admin")

    async def raise_network_error():
        raise ConnectionError("manager unreachable")

    monkeypatch.setattr(wazuh_manager_client, "list_agents", raise_network_error)

    agents, source = asyncio.run(wazuh_manager_client.list_agents_with_fallback())
    assert source == "manual"


def test_fallback_reraises_when_no_manual_sheet(monkeypatch):
    async def raise_not_configured():
        raise WazuhManagerNotConfigured()

    monkeypatch.setattr(wazuh_manager_client, "list_agents", raise_not_configured)

    with pytest.raises(WazuhManagerNotConfigured):
        asyncio.run(wazuh_manager_client.list_agents_with_fallback())


def test_fallback_prefers_live_when_it_succeeds(monkeypatch):
    manual_agents.set_agents([{"id": "manual-web01", "name": "manual-name", "ip": None, "status": "active"}], "admin")

    async def fake_live():
        return [{"id": "001", "name": "live-name", "ip": "10.0.0.1", "status": "active"}]

    monkeypatch.setattr(wazuh_manager_client, "list_agents", fake_live)

    agents, source = asyncio.run(wazuh_manager_client.list_agents_with_fallback())
    assert source == "live"
    assert agents[0]["name"] == "live-name"


# ---- wazuh_session / _effective_connection ----

def test_effective_connection_prefers_runtime_session_over_env():
    wazuh_session.set_credentials("https://runtime-manager:55000", "user1", "pw1", True)
    conn = wazuh_manager_client._effective_connection()
    assert conn == ("https://runtime-manager:55000", "user1", "pw1", True)


def test_effective_connection_none_when_nothing_configured(monkeypatch):
    # Explicitly mocked to the placeholder/empty state rather than relying on .env actually
    # having no real Wazuh Manager configured — this machine's .env may legitimately have real
    # credentials in it (e.g. a live-connected dev setup), which isn't what this test is about.
    monkeypatch.setattr(wazuh_manager_client, "WAZUH_MANAGER_HOST", wazuh_manager_client._PLACEHOLDER_HOST)
    monkeypatch.setattr(wazuh_manager_client, "WAZUH_MANAGER_PASSWORD", "")

    assert wazuh_manager_client._effective_connection() is None


# ---- new endpoints: admin gating ----

def _create_analyst(mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "alice",
        "password_hash": hash_password("alice-pw"),
        "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))


def test_wazuh_credentials_endpoint_admin_only(client, mock_db):
    _create_analyst(mock_db)
    token = _login(client, "alice", "alice-pw")

    resp = client.post(
        "/api/integrations/wazuh/credentials",
        json={"host": "https://manager:55000", "user": "x", "password": "y"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_wazuh_credentials_set_status_clear(client, mock_db):
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    set_resp = client.post(
        "/api/integrations/wazuh/credentials",
        json={"host": "https://manager:55000", "user": "x", "password": "y"},
        headers=headers,
    )
    assert set_resp.status_code == 200
    assert set_resp.json()["configured"] is True

    status_resp = client.get("/api/integrations/wazuh/status", headers=headers)
    assert status_resp.json()["configured"] is True

    clear_resp = client.delete("/api/integrations/wazuh/credentials", headers=headers)
    assert clear_resp.json()["configured"] is False


def test_agent_sheet_upload_admin_only(client, mock_db):
    _create_analyst(mock_db)
    token = _login(client, "alice", "alice-pw")

    resp = client.post(
        "/api/integrations/wazuh/agents-sheet",
        files={"file": ("agents.csv", b"name,ip,status\nweb01,10.0.0.1,active\n", "text/csv")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_agent_sheet_upload_and_status(client, mock_db):
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    upload_resp = client.post(
        "/api/integrations/wazuh/agents-sheet",
        files={"file": ("agents.csv", b"name,ip,status\nweb01,10.0.0.1,active\n", "text/csv")},
        headers=headers,
    )
    assert upload_resp.status_code == 200
    assert upload_resp.json()["count"] == 1

    status_resp = client.get("/api/integrations/wazuh/agents-sheet/status", headers=headers)
    assert status_resp.json()["configured"] is True
    assert status_resp.json()["uploaded_by"] == "admin"

    clear_resp = client.delete("/api/integrations/wazuh/agents-sheet", headers=headers)
    assert clear_resp.json()["configured"] is False


def test_agent_sheet_upload_rejects_empty_csv(client, mock_db):
    token = _login(client)
    resp = client.post(
        "/api/integrations/wazuh/agents-sheet",
        files={"file": ("agents.csv", b"name,ip,status\n", "text/csv")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


def test_wazuh_agents_endpoint_uses_manual_sheet_when_configured(client, mock_db, monkeypatch):
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    client.post(
        "/api/integrations/wazuh/agents-sheet",
        files={"file": ("agents.csv", b"name,ip,status\nweb01,10.0.0.1,active\n", "text/csv")},
        headers=headers,
    )

    async def raise_not_configured():
        raise WazuhManagerNotConfigured()

    monkeypatch.setattr(wazuh_manager_client, "list_agents", raise_not_configured)

    resp = client.get("/api/assets/wazuh-agents", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "manual"
    assert body["agents"][0]["name"] == "web01"

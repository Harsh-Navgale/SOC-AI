import asyncio

import pytest

from app import wazuh_diagnostics, wazuh_session, wazuh_manager_client
from app.wazuh_manager_client import WazuhManagerNotConfigured


@pytest.fixture(autouse=True)
def _reset():
    wazuh_session.clear_credentials()
    yield
    wazuh_session.clear_credentials()


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeManagerClient:
    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    async def post(self, url, auth=None):
        return _FakeResponse({"data": {"token": "fake-token"}})

    async def get(self, url, headers=None, params=None):
        self.__class__.last_call = (url, params)
        if url.endswith("/manager/logs") or "/cluster/node/" in url:
            return _FakeResponse({"data": {"affected_items": [{"timestamp": "t1", "description": "ok"}]}})
        raise AssertionError(f"unexpected manager URL: {url}")


# ---- get_logs ----

def test_get_logs_raises_not_configured_with_no_session(monkeypatch):
    # _ensure_configured() (imported from wazuh_manager_client) resolves _effective_connection
    # against that module's own namespace internally, not wazuh_diagnostics's imported copy —
    # patch the source module so the check it runs actually observes "not configured".
    monkeypatch.setattr(wazuh_manager_client, "_effective_connection", lambda: None)

    with pytest.raises(WazuhManagerNotConfigured):
        asyncio.run(wazuh_diagnostics.get_logs())


def test_get_logs_hits_manager_logs_when_no_node_picked(monkeypatch):
    wazuh_session.set_credentials("https://10.1.2.3:55000", "wazuh-wui", "secret", False)
    monkeypatch.setattr(wazuh_diagnostics.httpx, "AsyncClient", _FakeManagerClient)

    logs = asyncio.run(wazuh_diagnostics.get_logs())

    assert logs == [{"timestamp": "t1", "description": "ok"}]
    url, params = _FakeManagerClient.last_call
    assert url.endswith("/manager/logs")
    assert params == {"limit": 200}


def test_get_logs_hits_cluster_node_logs_when_a_node_is_picked(monkeypatch):
    wazuh_session.set_credentials("https://10.1.2.3:55000", "wazuh-wui", "secret", False)
    monkeypatch.setattr(wazuh_diagnostics.httpx, "AsyncClient", _FakeManagerClient)

    asyncio.run(wazuh_diagnostics.get_logs(node_id="worker-01", level="error", search="denied"))

    url, params = _FakeManagerClient.last_call
    assert url.endswith("/cluster/node/worker-01/logs")
    assert params == {"limit": 200, "level": "error", "search": "denied"}


# ---- run_diagnostic_query ----

def test_run_diagnostic_query_rejects_a_path_not_starting_with_slash(monkeypatch):
    wazuh_session.set_credentials("https://10.1.2.3:55000", "wazuh-wui", "secret", False)

    with pytest.raises(wazuh_diagnostics.DiagnosticQueryRejected):
        asyncio.run(wazuh_diagnostics.run_diagnostic_query("manager", "manager/info"))


def test_run_diagnostic_query_runs_a_get_against_the_manager(monkeypatch):
    wazuh_session.set_credentials("https://10.1.2.3:55000", "wazuh-wui", "secret", False)

    class _FakeClient(_FakeManagerClient):
        async def get(self, url, headers=None, params=None):
            self.__class__.last_call = url
            return _FakeResponse({"data": {"affected_items": [{"version": "v4.14.7"}]}})

    monkeypatch.setattr(wazuh_diagnostics.httpx, "AsyncClient", _FakeClient)

    result = asyncio.run(wazuh_diagnostics.run_diagnostic_query("manager", "/manager/info"))

    assert result == {"data": {"affected_items": [{"version": "v4.14.7"}]}}
    assert _FakeClient.last_call == "https://10.1.2.3:55000/manager/info"


def test_run_diagnostic_query_runs_a_get_against_the_indexer(monkeypatch):
    monkeypatch.setattr(wazuh_diagnostics, "WAZUH_INDEXER_HOST", "https://10.1.2.4:9200")
    monkeypatch.setattr(wazuh_diagnostics, "WAZUH_INDEXER_USER", "admin")
    monkeypatch.setattr(wazuh_diagnostics, "WAZUH_INDEXER_PASSWORD", "secret")

    class _FakeIndexerClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def get(self, url, auth=None):
            _FakeIndexerClient.last_call = (url, auth)
            return _FakeResponse({"status": "green"})

    monkeypatch.setattr(wazuh_diagnostics.httpx, "AsyncClient", _FakeIndexerClient)

    result = asyncio.run(wazuh_diagnostics.run_diagnostic_query("indexer", "/_cluster/health"))

    assert result == {"status": "green"}
    url, auth = _FakeIndexerClient.last_call
    assert url == "https://10.1.2.4:9200/_cluster/health"
    assert auth == ("admin", "secret")


def test_run_diagnostic_query_rejects_indexer_when_not_configured(monkeypatch):
    monkeypatch.setattr(wazuh_diagnostics, "WAZUH_INDEXER_HOST", "https://your-wazuh-indexer:9200")
    monkeypatch.setattr(wazuh_diagnostics, "WAZUH_INDEXER_PASSWORD", "")

    with pytest.raises(wazuh_diagnostics.DiagnosticQueryRejected):
        asyncio.run(wazuh_diagnostics.run_diagnostic_query("indexer", "/_cluster/health"))


# ---- endpoints ----

from app.auth import hash_password  # noqa: E402


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def test_wazuh_logs_endpoint_requires_admin(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.get("/api/wazuh/logs", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_wazuh_logs_endpoint_returns_logs(client, mock_db, monkeypatch):
    async def fake_get_logs(node_id=None, level=None, tag=None, search=None, limit=200):
        return [{"timestamp": "t1", "description": "ok"}]

    monkeypatch.setattr(wazuh_diagnostics, "get_logs", fake_get_logs)

    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/wazuh/logs", headers=headers)

    assert resp.status_code == 200
    assert resp.json() == {"count": 1, "logs": [{"timestamp": "t1", "description": "ok"}]}


def test_wazuh_diagnostic_query_endpoint_requires_admin(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/wazuh/diagnostic-query", json={"path": "/manager/info"}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_wazuh_diagnostic_query_endpoint_runs_and_audit_logs(client, mock_db, monkeypatch):
    async def fake_run_diagnostic_query(target, path):
        return {"data": {"affected_items": [{"version": "v4.14.7"}]}}

    monkeypatch.setattr(wazuh_diagnostics, "run_diagnostic_query", fake_run_diagnostic_query)

    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/wazuh/diagnostic-query", json={"target": "manager", "path": "/manager/info"}, headers=headers)

    assert resp.status_code == 200
    assert resp.json() == {"data": {"affected_items": [{"version": "v4.14.7"}]}}

    entries = client.get("/api/audit-log", headers=headers).json()
    match = next(e for e in entries if e["action"] == "wazuh.diagnostic_query")
    assert match["details"] == {"target": "manager", "path": "/manager/info"}


def test_wazuh_diagnostic_query_endpoint_rejects_bad_path(client, mock_db, monkeypatch):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/wazuh/diagnostic-query", json={"path": "manager/info"}, headers=headers)
    assert resp.status_code == 400


def test_wazuh_diagnostic_query_endpoint_returns_409_when_manager_not_configured(client, mock_db, monkeypatch):
    async def fake_run_diagnostic_query(target, path):
        raise WazuhManagerNotConfigured("not configured")

    monkeypatch.setattr(wazuh_diagnostics, "run_diagnostic_query", fake_run_diagnostic_query)

    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/wazuh/diagnostic-query", json={"path": "/manager/info"}, headers=headers)
    assert resp.status_code == 409

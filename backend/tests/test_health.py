def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


import asyncio

from app import health as health_module


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


# ---- wazuh_indexer_health ----

class _FakeIndexerClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, url, params=None, auth=None):
        if url.endswith("/_cluster/health"):
            return _FakeResponse({"status": "green", "cluster_name": "wazuh-cluster", "active_shards": 74})
        if "/_cat/indices/" in url:
            return _FakeResponse([{"index": "wazuh-alerts-4.x-2026.09.08", "store.size": "10066329"}])
        if url.endswith("/_cat/nodes"):
            return _FakeResponse([{
                "name": "node-1", "disk.total": "498589663232", "disk.used": "140983476224",
                "disk.avail": "357606187008", "disk.used_percent": "28.28",
                "heap.percent": "19", "ram.percent": "96", "cpu": "1", "load_1m": "0.31",
            }])
        raise AssertionError(f"unexpected indexer URL: {url}")


def test_wazuh_indexer_health_not_configured_by_default(monkeypatch):
    monkeypatch.setattr(health_module, "WAZUH_INDEXER_HOST", "https://your-wazuh-indexer:9200")
    monkeypatch.setattr(health_module, "WAZUH_INDEXER_PASSWORD", "")

    result = asyncio.run(health_module.wazuh_indexer_health())

    assert result == {"status": "not_configured"}


def test_wazuh_indexer_health_reports_cluster_and_real_node_disk_stats(monkeypatch):
    monkeypatch.setattr(health_module, "WAZUH_INDEXER_HOST", "https://10.1.2.3:9200")
    monkeypatch.setattr(health_module, "WAZUH_INDEXER_PASSWORD", "secret")
    monkeypatch.setattr(health_module.httpx, "AsyncClient", _FakeIndexerClient)

    result = asyncio.run(health_module.wazuh_indexer_health())

    assert result["status"] == "green"
    assert result["cluster_name"] == "wazuh-cluster"
    assert result["alert_index_count"] == 1
    node = result["nodes"][0]
    assert node["name"] == "node-1"
    assert node["disk_total_gb"] == round(498589663232 / 1024 / 1024 / 1024, 1)
    assert node["disk_used_percent"] == 28.28
    assert node["heap_percent"] == 19
    assert node["ram_percent"] == 96


def test_wazuh_indexer_health_unreachable_on_failure(monkeypatch):
    monkeypatch.setattr(health_module, "WAZUH_INDEXER_HOST", "https://10.1.2.3:9200")
    monkeypatch.setattr(health_module, "WAZUH_INDEXER_PASSWORD", "secret")

    class _BoomClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, *args, **kwargs):
            raise ConnectionError("connection refused")

    monkeypatch.setattr(health_module.httpx, "AsyncClient", _BoomClient)

    result = asyncio.run(health_module.wazuh_indexer_health())

    assert result["status"] == "unreachable"
    assert "connection refused" in result["error"]


# ---- wazuh_manager_health ----

class _FakeManagerClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def post(self, url, auth=None):
        return _FakeResponse({"data": {"token": "fake-token"}})

    async def get(self, url, headers=None):
        if url.endswith("/agents/summary/status"):
            return _FakeResponse({"data": {"connection": {"active": 3, "disconnected": 1, "total": 4}}})
        if url.endswith("/manager/info"):
            return _FakeResponse({"data": {"affected_items": [{"version": "v4.14.7"}]}})
        if url.endswith("/manager/status"):
            return _FakeResponse({"data": {"affected_items": [
                {"wazuh-analysisd": "running", "wazuh-remoted": "running", "wazuh-agentlessd": "stopped"},
            ]}})
        if url.endswith("/manager/stats"):
            return _FakeResponse({"data": {"affected_items": [{"hour": 9, "totalAlerts": 201, "events": 5854}]}})
        if url.endswith("/cluster/status"):
            return _FakeResponse({"data": {"enabled": "no"}})
        raise AssertionError(f"unexpected manager URL: {url}")


def test_wazuh_manager_health_not_configured_when_no_session_or_env(monkeypatch):
    monkeypatch.setattr(health_module, "_effective_connection", lambda: None)

    result = asyncio.run(health_module.wazuh_manager_health())

    assert result == {"status": "not_configured"}


def test_wazuh_manager_health_reports_agents_daemons_and_stats(monkeypatch):
    monkeypatch.setattr(health_module, "_effective_connection", lambda: ("https://10.1.2.3:55000", "wazuh-wui", "secret", False))
    monkeypatch.setattr(health_module.httpx, "AsyncClient", _FakeManagerClient)

    result = asyncio.run(health_module.wazuh_manager_health())

    assert result["status"] == "ok"
    assert result["version"] == "v4.14.7"
    assert result["agents"] == {"active": 3, "disconnected": 1, "total": 4}
    assert result["daemons"]["running"] == ["wazuh-analysisd", "wazuh-remoted"]
    assert result["daemons"]["stopped"] == ["wazuh-agentlessd"]
    assert result["current_hour"] == {"total_alerts": 201, "events": 5854}


def test_wazuh_manager_health_degrades_gracefully_when_stats_file_missing(monkeypatch):
    # Mirrors a freshly-installed manager: /manager/stats 400s (Wazuh's WazuhError 1308 — no
    # totals log written yet) while auth/agents/daemons all genuinely succeed. That one failure
    # must not take down the whole card.
    class _FakeManagerClientNoStats(_FakeManagerClient):
        async def get(self, url, headers=None):
            if url.endswith("/manager/stats"):
                raise ConnectionError("400 Bad Request")
            return await super().get(url, headers=headers)

    monkeypatch.setattr(health_module, "_effective_connection", lambda: ("https://10.1.2.3:55000", "wazuh-wui", "secret", False))
    monkeypatch.setattr(health_module.httpx, "AsyncClient", _FakeManagerClientNoStats)

    result = asyncio.run(health_module.wazuh_manager_health())

    assert result["status"] == "ok"
    assert result["version"] == "v4.14.7"
    assert result["agents"] == {"active": 3, "disconnected": 1, "total": 4}
    assert result["current_hour"] is None


def test_wazuh_manager_health_reports_both_nodes_when_clustered(monkeypatch):
    class _FakeManagerClientClustered(_FakeManagerClient):
        async def get(self, url, headers=None):
            if url.endswith("/cluster/status"):
                return _FakeResponse({"data": {"enabled": "yes"}})
            if url.endswith("/cluster/nodes"):
                return _FakeResponse({"data": {"affected_items": [
                    {"name": "master-01", "type": "master", "version": "v4.14.7"},
                    {"name": "worker-01", "type": "worker", "version": "v4.14.7"},
                ]}})
            if url.endswith("/cluster/healthcheck"):
                return _FakeResponse({"data": {"nodes": {
                    "master-01": {"status": {"sync_integrity_free": True, "last_keep_alive": "2026-11-22T10:00:00Z"}},
                    "worker-01": {"status": {"sync_integrity_free": False, "last_keep_alive": "2026-11-22T09:59:00Z"}},
                }}})
            return await super().get(url, headers=headers)

    monkeypatch.setattr(health_module, "_effective_connection", lambda: ("https://10.1.2.3:55000", "wazuh-wui", "secret", False))
    monkeypatch.setattr(health_module.httpx, "AsyncClient", _FakeManagerClientClustered)

    result = asyncio.run(health_module.wazuh_manager_health())

    assert result["status"] == "ok"
    nodes = {n["name"]: n for n in result["nodes"]}
    assert nodes["master-01"] == {"name": "master-01", "type": "master", "version": "v4.14.7", "status": "ok", "last_keep_alive": "2026-11-22T10:00:00Z"}
    assert nodes["worker-01"]["status"] == "syncing"


def test_wazuh_manager_health_skips_a_malformed_cluster_node_entry(monkeypatch):
    class _FakeManagerClientBadNode(_FakeManagerClient):
        async def get(self, url, headers=None):
            if url.endswith("/cluster/status"):
                return _FakeResponse({"data": {"enabled": "yes"}})
            if url.endswith("/cluster/nodes"):
                return _FakeResponse({"data": {"affected_items": [
                    {"name": "master-01", "type": "master", "version": "v4.14.7"},
                    {"type": "worker"},  # missing "name" — should be skipped, not fatal
                ]}})
            if url.endswith("/cluster/healthcheck"):
                return _FakeResponse({"data": {"nodes": {}}})
            return await super().get(url, headers=headers)

    monkeypatch.setattr(health_module, "_effective_connection", lambda: ("https://10.1.2.3:55000", "wazuh-wui", "secret", False))
    monkeypatch.setattr(health_module.httpx, "AsyncClient", _FakeManagerClientBadNode)

    result = asyncio.run(health_module.wazuh_manager_health())

    assert result["status"] == "ok"
    assert [n["name"] for n in result["nodes"]] == ["master-01"]


def test_wazuh_manager_health_has_no_nodes_key_when_not_clustered(monkeypatch):
    # Regression guard: today's single-manager lab/demo deployment must see zero output change.
    monkeypatch.setattr(health_module, "_effective_connection", lambda: ("https://10.1.2.3:55000", "wazuh-wui", "secret", False))
    monkeypatch.setattr(health_module.httpx, "AsyncClient", _FakeManagerClient)

    result = asyncio.run(health_module.wazuh_manager_health())

    assert "nodes" not in result


def test_wazuh_manager_health_unreachable_on_auth_failure(monkeypatch):
    monkeypatch.setattr(health_module, "_effective_connection", lambda: ("https://10.1.2.3:55000", "wazuh-wui", "wrong", False))

    class _BoomAuthClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, *args, **kwargs):
            raise ConnectionError("connection refused")

    monkeypatch.setattr(health_module.httpx, "AsyncClient", _BoomAuthClient)

    result = asyncio.run(health_module.wazuh_manager_health())

    assert result["status"] == "unreachable"

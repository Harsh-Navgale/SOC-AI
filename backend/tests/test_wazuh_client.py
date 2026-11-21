import asyncio

import pytest

from app import wazuh_client


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    wazuh_client._truncated_notified = False
    wazuh_client._last_poll = {"fetched": 0, "truncated": False, "at": None}

    async def fake_notify(*args, **kwargs):
        return None

    monkeypatch.setattr(wazuh_client.notifications, "create", fake_notify)
    monkeypatch.setattr(wazuh_client.ws_manager, "broadcast", fake_notify)


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _hit(id_, sort_value):
    return {"_id": id_, "_source": {"rule": {"id": "100"}}, "sort": [sort_value, id_]}


def test_fetch_recent_alerts_single_page_under_cap(monkeypatch):
    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def post(self, url, json=None, auth=None):
            return _FakeResponse({"hits": {"total": {"value": 2}, "hits": [_hit("a", 1), _hit("b", 2)]}})

    monkeypatch.setattr(wazuh_client.httpx, "AsyncClient", _FakeClient)

    alerts = asyncio.run(wazuh_client.fetch_recent_alerts())

    assert len(alerts) == 2
    assert alerts[0]["_id"] == "a"
    assert wazuh_client.last_poll_stats()["fetched"] == 2
    assert wazuh_client.last_poll_stats()["truncated"] is False


def test_fetch_recent_alerts_paginates_across_multiple_pages(monkeypatch):
    calls = []

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def post(self, url, json=None, auth=None):
            calls.append(json)
            if len(calls) == 1:
                return _FakeResponse({"hits": {"total": {"value": 250}, "hits": [_hit(f"p1-{i}", i) for i in range(200)]}})
            return _FakeResponse({"hits": {"total": {"value": 250}, "hits": [_hit(f"p2-{i}", 200 + i) for i in range(50)]}})

    monkeypatch.setattr(wazuh_client.httpx, "AsyncClient", _FakeClient)

    alerts = asyncio.run(wazuh_client.fetch_recent_alerts())

    assert len(alerts) == 250
    assert len(calls) == 2
    assert "search_after" not in calls[0]
    assert calls[1]["search_after"] == [199, "p1-199"]
    assert wazuh_client.last_poll_stats()["truncated"] is False


def test_fetch_recent_alerts_fires_one_shot_notification_when_safety_cap_hit(monkeypatch):
    notified = []

    async def fake_notify(message, type_, user=None):
        notified.append(message)

    monkeypatch.setattr(wazuh_client.notifications, "create", fake_notify)

    class _FakeClientAlwaysFull:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def post(self, url, json=None, auth=None):
            return _FakeResponse({"hits": {"total": {"value": 100000}, "hits": [_hit(f"x-{i}", i) for i in range(200)]}})

    monkeypatch.setattr(wazuh_client.httpx, "AsyncClient", _FakeClientAlwaysFull)

    alerts = asyncio.run(wazuh_client.fetch_recent_alerts())

    assert len(alerts) == wazuh_client._MAX_PAGES * wazuh_client._PAGE_SIZE
    assert wazuh_client.last_poll_stats()["truncated"] is True
    assert len(notified) == 1


def test_fetch_recent_alerts_truncation_notification_is_one_shot_and_resets_on_recovery(monkeypatch):
    notified = []

    async def fake_notify(message, type_, user=None):
        notified.append(message)

    monkeypatch.setattr(wazuh_client.notifications, "create", fake_notify)

    class _FakeClientAlwaysFull:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def post(self, url, json=None, auth=None):
            return _FakeResponse({"hits": {"total": {"value": 100000}, "hits": [_hit(f"x-{i}", i) for i in range(200)]}})

    class _FakeClientCaughtUp:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def post(self, url, json=None, auth=None):
            return _FakeResponse({"hits": {"total": {"value": 1}, "hits": [_hit("y", 1)]}})

    monkeypatch.setattr(wazuh_client.httpx, "AsyncClient", _FakeClientAlwaysFull)
    asyncio.run(wazuh_client.fetch_recent_alerts())
    asyncio.run(wazuh_client.fetch_recent_alerts())  # still truncated — must NOT notify again
    assert len(notified) == 1

    monkeypatch.setattr(wazuh_client.httpx, "AsyncClient", _FakeClientCaughtUp)
    asyncio.run(wazuh_client.fetch_recent_alerts())
    assert wazuh_client.last_poll_stats()["truncated"] is False

    monkeypatch.setattr(wazuh_client.httpx, "AsyncClient", _FakeClientAlwaysFull)
    asyncio.run(wazuh_client.fetch_recent_alerts())
    assert len(notified) == 2  # fired again after a genuine recovery in between


def test_fetch_recent_alerts_returns_what_it_has_on_a_mid_poll_failure(monkeypatch):
    class _FakeClientBoom:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def post(self, url, json=None, auth=None):
            raise ConnectionError("connection refused")

    monkeypatch.setattr(wazuh_client.httpx, "AsyncClient", _FakeClientBoom)

    alerts = asyncio.run(wazuh_client.fetch_recent_alerts())

    assert alerts == []

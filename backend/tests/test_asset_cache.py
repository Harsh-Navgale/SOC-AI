import asyncio

from mongomock_motor import AsyncMongoMockClient

from app import asset_cache


def _db(monkeypatch):
    mock_client = AsyncMongoMockClient()
    db = mock_client["soc_ai_asset_cache_test"]
    monkeypatch.setattr(asset_cache, "asset_inventory_cache", db["asset_inventory_cache"])
    monkeypatch.setattr(asset_cache, "_cache_meta", db["asset_inventory_cache_meta"])
    return db


def test_refresh_caches_records_keyed_by_normalized_ip(monkeypatch):
    _db(monkeypatch)

    async def fake_fetch():
        return [
            {"hostname": "web-01", "ip": "  203.0.113.9  ", "raw": {"hostname": "web-01", "env": "prod"}},
            {"hostname": "db-02", "ip": "10.0.0.5", "raw": {"hostname": "db-02", "env": "staging"}},
        ]

    monkeypatch.setattr(asset_cache, "fetch_latest_inventory", fake_fetch)

    count = asyncio.run(asset_cache.refresh())

    assert count == 2
    asset = asyncio.run(asset_cache.get_for_ip("203.0.113.9"))
    assert asset["hostname"] == "web-01"
    assert asset["raw"]["env"] == "prod"


def test_refresh_skips_records_with_no_ip(monkeypatch):
    _db(monkeypatch)

    async def fake_fetch():
        return [{"hostname": "unknown-host", "ip": None, "raw": {"hostname": "unknown-host"}}]

    monkeypatch.setattr(asset_cache, "fetch_latest_inventory", fake_fetch)

    count = asyncio.run(asset_cache.refresh())

    assert count == 0


def test_refresh_replaces_stale_entries_entirely(monkeypatch):
    _db(monkeypatch)

    async def fake_fetch_v1():
        return [{"hostname": "old-host", "ip": "10.0.0.1", "raw": {}}]

    monkeypatch.setattr(asset_cache, "fetch_latest_inventory", fake_fetch_v1)
    asyncio.run(asset_cache.refresh())
    assert asyncio.run(asset_cache.get_for_ip("10.0.0.1")) is not None

    async def fake_fetch_v2():
        return [{"hostname": "new-host", "ip": "10.0.0.2", "raw": {}}]

    monkeypatch.setattr(asset_cache, "fetch_latest_inventory", fake_fetch_v2)
    asyncio.run(asset_cache.refresh())

    # The old IP is gone — a decommissioned/renumbered host shouldn't linger forever.
    assert asyncio.run(asset_cache.get_for_ip("10.0.0.1")) is None
    assert asyncio.run(asset_cache.get_for_ip("10.0.0.2"))["hostname"] == "new-host"


def test_get_for_ip_returns_none_when_not_cached(monkeypatch):
    _db(monkeypatch)
    assert asyncio.run(asset_cache.get_for_ip("203.0.113.99")) is None


def test_get_for_ip_returns_none_for_blank_ip(monkeypatch):
    _db(monkeypatch)
    assert asyncio.run(asset_cache.get_for_ip(None)) is None
    assert asyncio.run(asset_cache.get_for_ip("")) is None


def test_meta_reports_last_refresh(monkeypatch):
    _db(monkeypatch)

    async def fake_fetch():
        return [{"hostname": "h", "ip": "10.0.0.1", "raw": {}}]

    monkeypatch.setattr(asset_cache, "fetch_latest_inventory", fake_fetch)

    assert asyncio.run(asset_cache.meta()) == {"refreshed_at": None, "count": 0}

    asyncio.run(asset_cache.refresh())
    meta = asyncio.run(asset_cache.meta())
    assert meta["count"] == 1
    assert meta["refreshed_at"] is not None

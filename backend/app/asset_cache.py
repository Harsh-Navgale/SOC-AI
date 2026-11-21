"""Caches the S3 asset inventory into Mongo, keyed by normalized IP, so a case can be enriched
with "which real host is this" at creation time — by the correlator, a plain sync Mongo client
with no AWS dependency at all — instead of every AI investigation making its own live S3 call
just to look up one IP. The inventory only changes once a day (it's a daily export); refreshing
the cache on the same cadence is what the live-fetch version was already implicitly assuming,
just made explicit and no longer paid for on every investigation.

The correlator's read side is a single indexed `_id` lookup — no IP-normalization or
hostname-derived-IP fallback logic needs to be duplicated there, because all of that already ran
once here when the cache was written.
"""
import logging
from datetime import datetime, timezone

from app.db import db
from app.s3_inventory import fetch_latest_inventory

logger = logging.getLogger("soc.asset_cache")

asset_inventory_cache = db["asset_inventory_cache"]
_cache_meta = db["asset_inventory_cache_meta"]


def _normalize_ip(ip: str) -> str:
    """Same normalization as asset_coverage.py's _normalize_ip — kept as its own copy since
    the two modules have no shared-utility layer today; this one-line rule is cheap to keep
    in sync if it ever needs to change."""
    return ip.strip().lower()


async def refresh() -> int:
    """Replaces the entire cache with the current S3 inventory. Returns the number of IPs
    cached. Raises whatever fetch_latest_inventory() raises (S3NotConfigured, expired
    credentials, etc.) — callers decide whether that's worth surfacing or just logging."""
    records = await fetch_latest_inventory()

    by_ip: dict[str, dict] = {}
    for record in records:
        ip = record.get("ip")
        if not ip:
            continue  # nothing to key the cache on — asset_coverage's own reconcile view still shows it
        by_ip[_normalize_ip(ip)] = {"hostname": record.get("hostname"), "raw": record.get("raw", {})}

    docs = [{"_id": ip, **data} for ip, data in by_ip.items()]

    await asset_inventory_cache.delete_many({})
    if docs:
        await asset_inventory_cache.insert_many(docs)
    await _cache_meta.update_one(
        {"_id": "asset_inventory"},
        {"$set": {"refreshed_at": datetime.now(timezone.utc).isoformat(), "count": len(docs)}},
        upsert=True,
    )
    logger.info("Asset inventory cache refreshed: %d IPs cached", len(docs))
    return len(docs)


async def get_for_ip(ip: str | None) -> dict | None:
    if not ip:
        return None
    doc = await asset_inventory_cache.find_one({"_id": _normalize_ip(ip)})
    if not doc:
        return None
    return {"hostname": doc.get("hostname"), "raw": doc.get("raw", {})}


async def meta() -> dict:
    doc = await _cache_meta.find_one({"_id": "asset_inventory"})
    if not doc:
        return {"refreshed_at": None, "count": 0}
    return {"refreshed_at": doc.get("refreshed_at"), "count": doc.get("count", 0)}

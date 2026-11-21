import logging
from datetime import datetime, timedelta, timezone

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.config import (
    WAZUH_INDEXER_HOST,
    WAZUH_INDEXER_USER,
    WAZUH_INDEXER_PASSWORD,
    WAZUH_INDEX_PATTERN,
    WAZUH_INDEXER_VERIFY_SSL,
    WAZUH_CA_BUNDLE,
)
from app import notifications, ws_manager

logger = logging.getLogger("soc.wazuh")

_PAGE_SIZE = 200
# Caps a single poll at 2000 alerts (10 * 200) — comfortably above any expected burst, but still
# bounded so a pathological case (indexer stuck returning data forever) can't loop forever.
_MAX_PAGES = 10

# One-shot notification state, same pattern as rag.py's _notify_fallback_once / scheduler.py's
# _budget_notified: fires once when a poll genuinely can't keep up, resets on the next poll that
# does, rather than re-notifying every 30s while the condition persists.
_truncated_notified = False

# Visibility even when the notification above hasn't fired — "fetched N alerts across M pages"
# is useful to see on the Debug panel regardless of whether anything was actually truncated.
_last_poll: dict = {"fetched": 0, "truncated": False, "at": None}


def last_poll_stats() -> dict:
    return dict(_last_poll)


async def _record_poll_result(fetched: int, truncated: bool) -> None:
    global _truncated_notified
    _last_poll["fetched"] = fetched
    _last_poll["truncated"] = truncated
    _last_poll["at"] = datetime.now(timezone.utc).isoformat()

    if not truncated:
        _truncated_notified = False
        return
    if _truncated_notified:
        return
    _truncated_notified = True
    logger.warning(
        "Wazuh alert ingestion hit its safety cap (%d pages) with more alerts still available "
        "in this window; some may be delayed or lost", _MAX_PAGES,
    )
    try:
        await notifications.create(
            f"Wazuh alert ingestion is falling behind — fetched {fetched} alerts but more were "
            f"still available after {_MAX_PAGES} pages. Alerts may be silently dropped if this "
            "continues.",
            "ingestion_truncated", user=None,
        )
        await ws_manager.broadcast({"type": "notifications_changed"})
    except Exception:
        logger.warning("Failed to record ingestion_truncated notification", exc_info=True)


def _verify_arg():
    if WAZUH_CA_BUNDLE:
        return WAZUH_CA_BUNDLE
    return WAZUH_INDEXER_VERIFY_SSL


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
    reraise=True,
)
async def _search(query: dict) -> dict:
    url = f"{WAZUH_INDEXER_HOST}/{WAZUH_INDEX_PATTERN}/_search"
    async with httpx.AsyncClient(verify=_verify_arg(), timeout=15.0) as client:
        resp = await client.post(
            url,
            json=query,
            auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
        )
        resp.raise_for_status()
        return resp.json()


async def fetch_recent_alerts(minutes: int = 2) -> list[dict]:
    """Pull alerts from the Wazuh Indexer (OpenSearch) that arrived in the last `minutes` minutes,
    paginating via `search_after` rather than a single fixed-size page — a single `size: 200`
    page with no pagination could silently and permanently lose alerts once sustained volume
    exceeds it (the oldest ones in an overloaded window would age out of the lookback before
    ever being fetched). Bounded by `_MAX_PAGES` so a pathological case still can't loop forever;
    if that cap is hit while more alerts remain, `_record_poll_result` logs and fires a one-shot
    admin notification (see above) rather than losing them silently.

    Never raises: on any failure it logs a warning and returns whatever was already fetched this
    cycle, so a misconfigured or temporarily unreachable Wazuh indexer never takes the backend
    down.
    """
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()

    all_hits: list[dict] = []
    search_after = None
    total = 0
    hit_safety_cap = False

    for page in range(_MAX_PAGES):
        query = {
            "size": _PAGE_SIZE,
            # timestamp alone can tie for alerts in the same instant; _id is a stable
            # tiebreaker already relied on elsewhere below as the Mongo dedup key.
            "sort": [{"timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
            "query": {"range": {"timestamp": {"gte": since}}},
        }
        if search_after is not None:
            query["search_after"] = search_after

        try:
            data = await _search(query)
        except Exception as exc:
            logger.warning("Could not reach Wazuh indexer at %s: %s", WAZUH_INDEXER_HOST, exc)
            break

        hits = data.get("hits", {}).get("hits", [])
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        all_hits.extend(hits)

        if not hits or len(all_hits) >= total:
            break
        search_after = hits[-1]["sort"]
        if page == _MAX_PAGES - 1:
            hit_safety_cap = True

    truncated = hit_safety_cap and len(all_hits) < total
    await _record_poll_result(len(all_hits), truncated)

    return [
        hit["_source"] | {"_id": hit["_id"]}
        for hit in all_hits
    ]

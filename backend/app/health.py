import asyncio
import logging
import time
from datetime import datetime, timezone

import httpx

from app.config import (
    WAZUH_INDEXER_HOST,
    WAZUH_INDEXER_USER,
    WAZUH_INDEXER_PASSWORD,
    WAZUH_INDEXER_VERIFY_SSL,
    WAZUH_CA_BUNDLE,
    WAZUH_INDEX_PATTERN,
)
from app.db import db, raw_alerts, incidents, users
from app.wazuh_manager_client import _effective_connection

logger = logging.getLogger("soc.health")
START_TIME = time.time()

_PLACEHOLDER_HOSTS = {"https://your-wazuh-indexer:9200", "https://your-wazuh-manager:55000"}
_HEARTBEAT_STALE_SECONDS = 60


def _indexer_verify_arg():
    return WAZUH_CA_BUNDLE if WAZUH_CA_BUNDLE else WAZUH_INDEXER_VERIFY_SSL


async def backend_health() -> dict:
    return {"status": "ok", "uptime_seconds": int(time.time() - START_TIME)}


async def mongo_health() -> dict:
    try:
        stats = await db.command("dbStats")
        server_status = await db.command("serverStatus")
        return {
            "status": "ok",
            "storage_mb": round(stats.get("storageSize", 0) / 1024 / 1024, 1),
            "connections_current": server_status.get("connections", {}).get("current"),
            "collections": {
                "raw_alerts": await raw_alerts.estimated_document_count(),
                "incidents": await incidents.estimated_document_count(),
                "users": await users.estimated_document_count(),
            },
        }
    except Exception as exc:
        logger.warning("Mongo health check failed: %s", exc)
        return {"status": "unreachable", "error": str(exc)}


async def chroma_health() -> dict:
    try:
        from app.rag import collection
        return {"status": "ok", "documents": collection.count()}
    except Exception as exc:
        logger.warning("Chroma health check failed: %s", exc)
        return {"status": "unreachable", "error": str(exc)}


async def correlator_health() -> dict:
    try:
        heartbeat = await db["system_heartbeats"].find_one({"_id": "correlator"})
    except Exception as exc:
        logger.warning("Correlator heartbeat check failed: %s", exc)
        return {"status": "unknown", "error": str(exc)}

    if not heartbeat:
        return {"status": "unknown"}

    last_run = heartbeat.get("last_run", 0)
    age = time.time() - last_run
    return {
        "status": "ok" if age < _HEARTBEAT_STALE_SECONDS else "stale",
        "last_run_iso": datetime.fromtimestamp(last_run, tz=timezone.utc).isoformat(),
        "seconds_since_last_run": int(age),
        "alerts_processed_total": heartbeat.get("alerts_processed_total", 0),
    }


_NODE_STAT_FIELDS = "name,disk.total,disk.used,disk.avail,disk.used_percent,heap.percent,ram.percent,cpu,load_1m"


def _node_stats(raw_nodes: list[dict]) -> list[dict]:
    """_cat/nodes returns every value as a string (even the numeric ones) — this converts them
    and renames to something a frontend doesn't need a Wazuh-API cheat sheet to read. disk.* is
    real host disk usage for that node, not the size of the alert indices alone (alert_storage_mb
    below is just the wazuh-alerts-* indices; a node's total disk usage includes everything
    else on it too — OS, other indices, logs)."""
    nodes = []
    for n in raw_nodes:
        try:
            nodes.append({
                "name": n.get("name"),
                "disk_total_gb": round(int(n["disk.total"]) / 1024 / 1024 / 1024, 1),
                "disk_used_gb": round(int(n["disk.used"]) / 1024 / 1024 / 1024, 1),
                "disk_avail_gb": round(int(n["disk.avail"]) / 1024 / 1024 / 1024, 1),
                "disk_used_percent": float(n["disk.used_percent"]),
                "heap_percent": int(n["heap.percent"]),
                "ram_percent": int(n["ram.percent"]),
                "cpu_percent": int(n["cpu"]),
                "load_1m": float(n["load_1m"]) if n.get("load_1m") not in (None, "") else None,
            })
        except (KeyError, ValueError, TypeError):
            logger.warning("Could not parse Wazuh indexer node stats for %r", n.get("name"))
    return nodes


async def wazuh_indexer_health() -> dict:
    if WAZUH_INDEXER_HOST in _PLACEHOLDER_HOSTS or not WAZUH_INDEXER_PASSWORD:
        return {"status": "not_configured"}
    try:
        auth = (WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD)
        async with httpx.AsyncClient(verify=_indexer_verify_arg(), timeout=8.0) as client:
            cluster = await client.get(f"{WAZUH_INDEXER_HOST}/_cluster/health", auth=auth)
            cluster.raise_for_status()
            cluster_data = cluster.json()

            indices = await client.get(
                f"{WAZUH_INDEXER_HOST}/_cat/indices/{WAZUH_INDEX_PATTERN}",
                params={"format": "json", "bytes": "b"},
                auth=auth,
            )
            indices.raise_for_status()
            index_list = indices.json()
            total_bytes = sum(int(i.get("store.size", 0) or 0) for i in index_list)

            # Real host-level disk/memory/CPU per node — distinct from alert_storage_mb below,
            # which is only the wazuh-alerts-* indices, not everything actually on disk.
            nodes_resp = await client.get(
                f"{WAZUH_INDEXER_HOST}/_cat/nodes",
                params={"format": "json", "bytes": "b", "h": _NODE_STAT_FIELDS},
                auth=auth,
            )
            nodes_resp.raise_for_status()
            nodes = _node_stats(nodes_resp.json())

        return {
            "status": cluster_data.get("status", "unknown"),
            "cluster_name": cluster_data.get("cluster_name"),
            "active_shards": cluster_data.get("active_shards"),
            "alert_index_count": len(index_list),
            "alert_storage_mb": round(total_bytes / 1024 / 1024, 1),
            "nodes": nodes,
        }
    except Exception as exc:
        logger.warning("Wazuh indexer health check failed: %s", exc)
        return {"status": "unreachable", "error": str(exc)}


async def _cluster_nodes(client: httpx.AsyncClient, host: str, headers: dict) -> list[dict] | None:
    """Best-effort per-node list (name, type master/worker, version, sync status) for a Wazuh
    manager running in cluster mode — mirrors wazuh_indexer_health()'s existing `nodes` shape so
    the frontend can render both the same way. Returns None (not an error) when this manager
    isn't clustered, or when the cluster API itself is unreachable/unexpected-shaped — callers
    treat None as "stay on today's single-node output," the regression guard for the existing
    non-clustered lab/demo deployment."""
    try:
        status_resp = await client.get(f"{host}/cluster/status", headers=headers)
        status_resp.raise_for_status()
        if status_resp.json().get("data", {}).get("enabled") != "yes":
            return None

        nodes_resp = await client.get(f"{host}/cluster/nodes", headers=headers)
        nodes_resp.raise_for_status()
        raw_nodes = nodes_resp.json()["data"]["affected_items"]

        nodes = {}
        for n in raw_nodes:
            try:
                name = n["name"]
                nodes[name] = {"name": name, "type": n.get("type"), "version": n.get("version"), "status": "unknown"}
            except (KeyError, TypeError):
                logger.warning("Could not parse Wazuh cluster node entry: %r", n)

        # Best-effort enrichment with live sync/keepalive status — isolated in its own
        # try/except (same reasoning as /manager/stats below) so an unexpected healthcheck
        # shape just leaves "status": "unknown" rather than dropping the whole node list.
        try:
            health_resp = await client.get(f"{host}/cluster/healthcheck", headers=headers)
            health_resp.raise_for_status()
            health_nodes = health_resp.json().get("data", {}).get("nodes", {})
            for name, info in health_nodes.items():
                if name in nodes:
                    sync_free = (info.get("status") or {}).get("sync_integrity_free")
                    nodes[name]["status"] = "ok" if sync_free else "syncing"
                    nodes[name]["last_keep_alive"] = (info.get("status") or {}).get("last_keep_alive")
        except Exception as exc:
            logger.info("Wazuh cluster healthcheck unavailable; node list shown without sync status: %s", exc)

        return sorted(nodes.values(), key=lambda n: n["name"])
    except Exception as exc:
        logger.info("Wazuh cluster API unavailable or this manager isn't clustered: %s", exc)
        return None


async def wazuh_manager_health() -> dict:
    connection = _effective_connection()
    if connection is None:
        return {"status": "not_configured"}
    host, user, password, verify_ssl = connection

    try:
        async with httpx.AsyncClient(verify=verify_ssl, timeout=8.0) as client:
            token_resp = await client.post(
                f"{host}/security/user/authenticate",
                auth=(user, password),
            )
            token_resp.raise_for_status()
            token = token_resp.json()["data"]["token"]
            headers = {"Authorization": f"Bearer {token}"}

            summary_resp = await client.get(f"{host}/agents/summary/status", headers=headers)
            summary_resp.raise_for_status()
            connection_summary = summary_resp.json()["data"].get("connection", {})

            info_resp = await client.get(f"{host}/manager/info", headers=headers)
            info_resp.raise_for_status()
            manager_info = info_resp.json()["data"]["affected_items"][0]

            # Wazuh's REST API has no generic "disk usage" endpoint for the manager host itself
            # (unlike the indexer's _cat/nodes) — daemon status and alert/event throughput are
            # the closest things it actually exposes to "is this thing healthy and doing work".
            status_resp = await client.get(f"{host}/manager/status", headers=headers)
            status_resp.raise_for_status()
            daemons = status_resp.json()["data"]["affected_items"][0]

            # Isolated from the rest: Wazuh's /manager/stats reads today's totals log from disk
            # and 400s (WazuhError 1308) if it doesn't exist yet — completely normal for a
            # manager that's only been up a few hours and hasn't written one yet. That's not a
            # reason to report the whole manager as unreachable when auth/agents/daemons above
            # all genuinely succeeded.
            current_hour_stats = None
            try:
                stats_resp = await client.get(f"{host}/manager/stats", headers=headers)
                stats_resp.raise_for_status()
                stats_items = stats_resp.json()["data"]["affected_items"]
                current_hour_stats = stats_items[0] if stats_items else {}
            except Exception as exc:
                logger.info("Wazuh manager stats unavailable (likely no stats file yet): %s", exc)

            cluster_nodes = await _cluster_nodes(client, host, headers)

        result = {
            "status": "ok",
            "version": manager_info.get("version"),
            "agents": {
                "active": connection_summary.get("active", 0),
                "disconnected": connection_summary.get("disconnected", 0),
                "total": connection_summary.get("total", 0),
            },
            "daemons": {
                "running": sorted(name for name, state in daemons.items() if state == "running"),
                "stopped": sorted(name for name, state in daemons.items() if state != "running"),
            },
            "current_hour": {
                "total_alerts": current_hour_stats.get("totalAlerts", 0),
                "events": current_hour_stats.get("events", 0),
            } if current_hour_stats is not None else None,
        }
        if cluster_nodes is not None:
            result["nodes"] = cluster_nodes
        return result
    except Exception as exc:
        logger.warning("Wazuh manager health check failed: %s", exc)
        return {"status": "unreachable", "error": str(exc)}


async def aggregate_health() -> dict:
    keys = ["backend", "mongodb", "chromadb", "correlator", "wazuh_manager", "wazuh_indexer"]
    results = await asyncio.gather(
        backend_health(),
        mongo_health(),
        chroma_health(),
        correlator_health(),
        wazuh_manager_health(),
        wazuh_indexer_health(),
        return_exceptions=True,
    )
    output = {}
    for key, result in zip(keys, results):
        output[key] = {"status": "error", "error": str(result)} if isinstance(result, Exception) else result
    return output

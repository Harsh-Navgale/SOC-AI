"""Admin troubleshooting surface for Wazuh itself: pulls the manager's own ossec.log entries via
its REST API (never direct file/SSH access), and runs ad-hoc read-only queries against the
Manager or Indexer API for a "problem checkup" without needing a separate API client. Every
diagnostic query is audit-logged by main.py's endpoint, not here — this module only executes the
already-authorized call.
"""
import logging
from typing import Literal

import httpx

from app.config import WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD
from app.wazuh_client import _verify_arg
from app.wazuh_manager_client import _effective_connection, _get_token, _ensure_configured

logger = logging.getLogger("soc.wazuh_diagnostics")

_INDEXER_PLACEHOLDER_HOST = "https://your-wazuh-indexer:9200"


class DiagnosticQueryRejected(Exception):
    """Raised for anything this module refuses to run — a request-shape problem on this app's
    side, distinct from a Wazuh-side failure (which raises/propagates its own exception)."""
    pass


async def get_logs(
    node_id: str | None = None, level: str | None = None, tag: str | None = None,
    search: str | None = None, limit: int = 200,
) -> list[dict]:
    """Manager's own log entries — /manager/logs normally, or /cluster/node/{node_id}/logs when
    a specific cluster node is picked (e.g. the worker, not just whichever node
    WAZUH_MANAGER_HOST happens to point at)."""
    _ensure_configured()
    host, user, password, verify_ssl = _effective_connection()

    params: dict = {"limit": limit}
    if level:
        params["level"] = level
    if tag:
        params["tag"] = tag
    if search:
        params["search"] = search

    path = f"/cluster/node/{node_id}/logs" if node_id else "/manager/logs"

    async with httpx.AsyncClient(verify=verify_ssl, timeout=15.0) as client:
        token = await _get_token(client, host, user, password)
        resp = await client.get(f"{host}{path}", headers={"Authorization": f"Bearer {token}"}, params=params)
        resp.raise_for_status()
        data = resp.json()

    return data.get("data", {}).get("affected_items", [])


async def run_diagnostic_query(target: Literal["manager", "indexer"], path: str) -> dict:
    """GET-only, read-only ad-hoc query against the Manager or Indexer API. Never any other HTTP
    verb, and always against the already-configured host (never client-supplied) — the real
    remaining exposure is "an already-admin user can read whatever this Wazuh API already
    exposes to reads," not an SSRF or mutation vector."""
    if not path.startswith("/"):
        raise DiagnosticQueryRejected("path must start with '/'")

    if target == "indexer":
        if WAZUH_INDEXER_HOST == _INDEXER_PLACEHOLDER_HOST or not WAZUH_INDEXER_PASSWORD:
            raise DiagnosticQueryRejected("Wazuh Indexer is not configured")
        async with httpx.AsyncClient(verify=_verify_arg(), timeout=15.0) as client:
            resp = await client.get(f"{WAZUH_INDEXER_HOST}{path}", auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD))
            resp.raise_for_status()
            return resp.json()

    _ensure_configured()
    host, user, password, verify_ssl = _effective_connection()
    async with httpx.AsyncClient(verify=verify_ssl, timeout=15.0) as client:
        token = await _get_token(client, host, user, password)
        resp = await client.get(f"{host}{path}", headers={"Authorization": f"Bearer {token}"})
        resp.raise_for_status()
        return resp.json()

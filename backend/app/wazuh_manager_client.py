import logging

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.config import (
    WAZUH_MANAGER_HOST,
    WAZUH_MANAGER_USER,
    WAZUH_MANAGER_PASSWORD,
    WAZUH_MANAGER_VERIFY_SSL,
)
from app import wazuh_session, manual_agents

logger = logging.getLogger("soc.wazuh_manager")

_PLACEHOLDER_HOST = "https://your-wazuh-manager:55000"
PAGE_SIZE = 500


class WazuhManagerNotConfigured(Exception):
    pass


def _effective_connection():
    """Returns (host, user, password, verify_ssl) from the runtime session if one is active,
    else falls back to the static .env config, else None if neither is configured. Lets an
    admin connect Wazuh Manager from the UI (like AWS) without editing .env + restarting."""
    session = wazuh_session.get_credentials()
    if session:
        return session["host"], session["user"], session["password"], session["verify_ssl"]
    if WAZUH_MANAGER_HOST != _PLACEHOLDER_HOST and WAZUH_MANAGER_PASSWORD:
        return WAZUH_MANAGER_HOST, WAZUH_MANAGER_USER, WAZUH_MANAGER_PASSWORD, WAZUH_MANAGER_VERIFY_SSL
    return None


def _ensure_configured():
    if _effective_connection() is None:
        raise WazuhManagerNotConfigured("Wazuh Manager is not configured (no runtime session or .env values)")


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
    reraise=True,
)
async def _get_token(client: httpx.AsyncClient, host: str, user: str, password: str) -> str:
    resp = await client.post(
        f"{host}/security/user/authenticate",
        auth=(user, password),
    )
    resp.raise_for_status()
    return resp.json()["data"]["token"]


async def list_agents() -> list[dict]:
    """Returns every registered Wazuh agent as {id, name, ip, status}.

    Raises WazuhManagerNotConfigured if neither a runtime session nor .env has Wazuh Manager
    credentials, so callers can show a distinct "not configured" message instead of a generic
    failure.
    """
    _ensure_configured()
    host, user, password, verify_ssl = _effective_connection()

    agents: list[dict] = []
    async with httpx.AsyncClient(verify=verify_ssl, timeout=15.0) as client:
        token = await _get_token(client, host, user, password)
        headers = {"Authorization": f"Bearer {token}"}

        offset = 0
        while True:
            resp = await client.get(
                f"{host}/agents",
                headers=headers,
                params={"offset": offset, "limit": PAGE_SIZE, "select": "id,name,ip,status"},
            )
            resp.raise_for_status()
            data = resp.json()["data"]
            items = data.get("affected_items", [])
            agents.extend(
                {"id": a.get("id"), "name": a.get("name"), "ip": a.get("ip"), "status": a.get("status")}
                for a in items
            )
            offset += PAGE_SIZE
            if offset >= data.get("total_affected_items", 0) or not items:
                break

    return agents


async def list_agents_with_fallback() -> tuple[list[dict], str]:
    """Tries the live Wazuh Manager API first; falls back to a manually-uploaded agent sheet
    if the live path isn't configured OR the live call itself fails (network error, bad
    creds, manager down, etc.) — a configured-but-unreachable manager still counts as a case
    where the manual sheet should carry the page. Returns (agents, source) where source is
    "live" or "manual". Re-raises the original error if no manual sheet is available either.
    """
    try:
        agents = await list_agents()
        return agents, "live"
    except Exception as exc:
        manual = manual_agents.get_agents()
        if manual is not None:
            logger.info("Live Wazuh Manager call failed (%s); using manual agent sheet", exc)
            return manual, "manual"
        raise

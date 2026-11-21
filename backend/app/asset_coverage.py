import asyncio
from datetime import datetime, timezone

from app import wazuh_manager_client, s3_inventory


def _normalize_ip(ip: str) -> str:
    """Match key for IP-based reconciliation: just trims whitespace and lowercases (IPv6
    addresses can vary in hex case; IPv4 is unaffected). No other normalization needed —
    unlike hostnames, IPs don't have FQDN-vs-short-name ambiguity."""
    return ip.strip().lower()


async def reconcile() -> dict:
    (agents, agents_source), inventory = await asyncio.gather(
        wazuh_manager_client.list_agents_with_fallback(),
        s3_inventory.fetch_latest_inventory(),
    )

    agents_by_ip: dict[str, dict] = {}
    for agent in agents:
        ip = agent.get("ip")
        if not ip:
            continue
        agents_by_ip.setdefault(_normalize_ip(ip), agent)

    matched_ips: set[str] = set()
    connected, disconnected, pending, other, missing = [], [], [], [], []
    # Wazuh's agent status field already distinguishes these cases; keyed lookup here so a
    # future/unexpected status (anything not active/disconnected/pending) falls through to
    # `other` instead of silently being miscategorized as one of the known three.
    status_buckets = {"active": connected, "disconnected": disconnected, "pending": pending}

    for record in inventory:
        ip = record.get("ip")
        # s3_inventory.fetch_latest_inventory() never drops a row, even when it couldn't
        # detect an IP column — such a record can't be matched to any Wazuh agent, so it's
        # surfaced as missing (with its full raw data) rather than silently vanishing or
        # crashing _normalize_ip() on None.
        agent = agents_by_ip.get(_normalize_ip(ip)) if ip else None

        if agent is None:
            missing.append({"hostname": record.get("hostname"), "ip": ip, "s3_record": record.get("raw", {})})
            continue

        matched_ips.add(_normalize_ip(ip))
        entry = {
            "hostname": record.get("hostname"),
            "ip": ip,
            "agent_id": agent.get("id"),
            "agent_ip": agent.get("ip"),
            "agent_status": agent.get("status"),
            # Full original S3 inventory record (every column from the CSV/JSON export, not
            # just hostname/ip) — kept nested under its own key so an S3 column can't silently
            # collide with/overwrite the agent_id/agent_ip/agent_status fields above.
            "s3_record": record.get("raw", {}),
        }
        status_buckets.get(agent.get("status"), other).append(entry)

    orphaned_agents = [
        {"agent_id": agent.get("id"), "name": agent.get("name"), "ip": agent.get("ip"), "status": agent.get("status")}
        for ip, agent in agents_by_ip.items()
        if ip not in matched_ips
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "s3_record_count": len(inventory),
        "wazuh_agent_count": len(agents),
        "agents_source": agents_source,
        "match_basis": "ip",
        "connected": connected,
        "disconnected": disconnected,
        "pending": pending,
        "other": other,
        "missing": missing,
        "orphaned_agents": orphaned_agents,
        "summary": {
            "connected": len(connected),
            "disconnected": len(disconnected),
            "pending": len(pending),
            "other": len(other),
            "missing": len(missing),
            "orphaned": len(orphaned_agents),
        },
    }

"""In-memory manual Wazuh agent sheet — a CSV-uploaded fallback for when no live Wazuh Manager
access is configured (or reachable). Same in-memory/12h-TTL shape as aws_session.py and
wazuh_session.py: an admin uploads a CSV once, it's held in this process's memory only, and
expires automatically rather than persisting stale data indefinitely.
"""
import time
from datetime import datetime, timezone
from typing import Optional

from app.csv_utils import parse_csv_rows, find_field

SESSION_TTL_SECONDS = 12 * 60 * 60  # 12 hours

# find_field() matches these case/separator-insensitively, so "Name"/"IP address"/"Status"/
# "ID" (Wazuh's own agent-export column names) all match without needing every casing spelled
# out — see csv_utils.find_field for why a bare exact-match list is not good enough here.
_NAME_FIELDS = ["name", "hostname", "agent name"]
_IP_FIELDS = ["ip", "ip address", "agent ip"]
_STATUS_FIELDS = ["status", "agent status"]
_ID_FIELDS = ["id", "agent id"]

_sheet: dict = {
    "agents": None,
    "uploaded_by": None,
    "uploaded_at": None,
    "expires_at": None,
}


def parse_csv(raw: bytes) -> list[dict]:
    """Parses an uploaded CSV into {id, name, ip, status, raw} entries — id/name/ip/status
    are best-effort guesses (a few common header spellings tried) used for matching against
    Wazuh; `raw` always carries every original column from the uploaded file, and no row is
    dropped even if a name/id couldn't be guessed for it, so nothing the admin uploaded is
    ever silently lost.
    """
    # utf-8-sig strips a leading BOM if present (Excel/PowerShell exports commonly have one),
    # which would otherwise glue itself onto the first column name and break header matching.
    text = raw.decode("utf-8-sig", errors="replace")
    rows = parse_csv_rows(text)

    agents = []
    for i, row in enumerate(rows):
        name = find_field(row, _NAME_FIELDS)
        agent_id = find_field(row, _ID_FIELDS) or (f"manual-{name}" if name else f"manual-row-{i}")
        agents.append({
            "id": agent_id,
            "name": name,
            "ip": find_field(row, _IP_FIELDS),
            "status": find_field(row, _STATUS_FIELDS) or "unknown",
            "raw": row,
        })
    return agents


def set_agents(agents: list[dict], uploaded_by: str):
    _sheet["agents"] = agents
    _sheet["uploaded_by"] = uploaded_by
    _sheet["uploaded_at"] = datetime.now(timezone.utc).isoformat()
    _sheet["expires_at"] = time.time() + SESSION_TTL_SECONDS


def clear_agents():
    for key in _sheet:
        _sheet[key] = None


def _is_valid() -> bool:
    return _sheet["expires_at"] is not None and time.time() < _sheet["expires_at"]


def get_agents() -> Optional[list[dict]]:
    if not _is_valid():
        clear_agents()
        return None
    return _sheet["agents"]


def status() -> dict:
    if not _is_valid():
        return {"configured": False, "count": 0, "uploaded_by": None, "uploaded_at": None, "expires_at": None}
    return {
        "configured": True,
        "count": len(_sheet["agents"]),
        "uploaded_by": _sheet["uploaded_by"],
        "uploaded_at": _sheet["uploaded_at"],
        "expires_at": datetime.fromtimestamp(_sheet["expires_at"], tz=timezone.utc).isoformat(),
    }

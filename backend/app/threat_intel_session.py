"""In-memory API key cache for the Threat Intel tab (VirusTotal, AbuseIPDB, and abuse.ch).

Same shape and same caveats as aws_session.py / wazuh_session.py: never persisted to Mongo or
disk, single-process-only, 12h TTL. abuse.ch now requires a free "Auth-Key" (one key shared by
URLhaus and ThreatFox, from a free abuse.ch account) — as of this writing none of these four
sources are actually keyless, contrary to how they used to work.
"""
import time
from datetime import datetime, timezone
from typing import Optional

SESSION_TTL_SECONDS = 12 * 60 * 60  # 12 hours

_session: dict = {
    "virustotal_api_key": None,
    "abuseipdb_api_key": None,
    "abusech_auth_key": None,
    "expires_at": None,
}


def set_credentials(virustotal_api_key: Optional[str], abuseipdb_api_key: Optional[str], abusech_auth_key: Optional[str] = None):
    _session["virustotal_api_key"] = virustotal_api_key or None
    _session["abuseipdb_api_key"] = abuseipdb_api_key or None
    _session["abusech_auth_key"] = abusech_auth_key or None
    _session["expires_at"] = time.time() + SESSION_TTL_SECONDS


def clear_credentials():
    for key in _session:
        _session[key] = None


def _is_valid() -> bool:
    return _session["expires_at"] is not None and time.time() < _session["expires_at"]


def get_credentials() -> Optional[dict]:
    if not _is_valid():
        clear_credentials()
        return None
    return {
        "virustotal_api_key": _session["virustotal_api_key"],
        "abuseipdb_api_key": _session["abuseipdb_api_key"],
        "abusech_auth_key": _session["abusech_auth_key"],
    }


def status() -> dict:
    if not _is_valid():
        return {"virustotal_configured": False, "abuseipdb_configured": False, "abusech_configured": False, "expires_at": None}
    return {
        "virustotal_configured": bool(_session["virustotal_api_key"]),
        "abuseipdb_configured": bool(_session["abuseipdb_api_key"]),
        "abusech_configured": bool(_session["abusech_auth_key"]),
        "expires_at": datetime.fromtimestamp(_session["expires_at"], tz=timezone.utc).isoformat(),
    }

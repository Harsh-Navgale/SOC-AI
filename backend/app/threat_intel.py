"""Threat Intel lookups — VirusTotal, AbuseIPDB, and abuse.ch (URLhaus + ThreatFox share one
"Auth-Key") — all four need a free API key/account as of this writing; abuse.ch dropped fully
anonymous access at some point after this integration was first scoped as "keyless", so don't
assume that's still true without checking their current docs. Every lookup_<source>() returns
the same shape regardless of outcome — {"status": "ok"|"error"|"not_configured"|
"not_applicable", ...} — so lookup_all() can run all four concurrently and one source failing
or lacking a key never prevents the others from showing.
"""
import asyncio
import base64
import logging
import re
import time

import httpx

from app import threat_intel_session
from app.config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, ABUSECH_AUTH_KEY

logger = logging.getLogger("soc.threat_intel")

HTTP_TIMEOUT = 12.0
CACHE_TTL_SECONDS = 10 * 60  # protects VirusTotal's 4-req/min free tier on repeat lookups

_cache: dict[str, dict] = {}


def clear_cache():
    """Called whenever credentials change — a cached 'not_configured' result from before a
    key was added would otherwise keep masking real data for up to CACHE_TTL_SECONDS after
    the key becomes available."""
    _cache.clear()

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def detect_indicator_type(value: str) -> str:
    v = value.strip()
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if _IPV4_RE.match(v) or (":" in v and re.fullmatch(r"[0-9a-fA-F:]+", v)):
        return "ip"
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in _HASH_LENGTHS:
        return "hash"
    return "domain"


def _effective_keys() -> tuple[str | None, str | None, str | None]:
    """Runtime session first, then .env fallback — same resolution order as
    wazuh_manager_client._effective_connection()."""
    session = threat_intel_session.get_credentials() or {}
    vt = session.get("virustotal_api_key") or VIRUSTOTAL_API_KEY
    abuse = session.get("abuseipdb_api_key") or ABUSEIPDB_API_KEY
    abusech = session.get("abusech_auth_key") or ABUSECH_AUTH_KEY
    return vt, abuse, abusech


async def lookup_virustotal(indicator: str, itype: str) -> dict:
    vt_key, _, _ = _effective_keys()
    if not vt_key:
        return {"status": "not_configured"}

    if itype == "ip":
        path = f"/ip_addresses/{indicator}"
    elif itype == "domain":
        path = f"/domains/{indicator}"
    elif itype == "hash":
        path = f"/files/{indicator}"
    else:  # url
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        path = f"/urls/{url_id}"

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.get(f"https://www.virustotal.com/api/v3{path}", headers={"x-apikey": vt_key})
        if resp.status_code == 404:
            return {"status": "ok", "data": {"found": False}}
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "status": "ok",
            "data": {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation"),
            },
        }
    except httpx.HTTPStatusError as exc:
        return {"status": "error", "error": f"VirusTotal returned {exc.response.status_code}"}
    except Exception as exc:
        logger.warning("VirusTotal lookup failed: %s", exc)
        return {"status": "error", "error": str(exc)}


async def lookup_abuseipdb(indicator: str, itype: str) -> dict:
    if itype != "ip":
        return {"status": "not_applicable"}
    _, abuse_key, _ = _effective_keys()
    if not abuse_key:
        return {"status": "not_configured"}

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": indicator, "maxAgeInDays": 90},
                headers={"Key": abuse_key, "Accept": "application/json"},
            )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "status": "ok",
            "data": {
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "last_reported_at": data.get("lastReportedAt"),
            },
        }
    except httpx.HTTPStatusError as exc:
        return {"status": "error", "error": f"AbuseIPDB returned {exc.response.status_code}"}
    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed: %s", exc)
        return {"status": "error", "error": str(exc)}


async def lookup_urlhaus(indicator: str, itype: str) -> dict:
    if itype in ("ip", "domain"):
        endpoint, payload = "https://urlhaus-api.abuse.ch/v1/host/", {"host": indicator}
    elif itype == "url":
        endpoint, payload = "https://urlhaus-api.abuse.ch/v1/url/", {"url": indicator}
    elif itype == "hash" and len(indicator) == 32:
        endpoint, payload = "https://urlhaus-api.abuse.ch/v1/payload/", {"md5_hash": indicator}
    elif itype == "hash" and len(indicator) == 64:
        endpoint, payload = "https://urlhaus-api.abuse.ch/v1/payload/", {"sha256_hash": indicator}
    else:
        return {"status": "not_applicable"}  # URLhaus's payload endpoint doesn't support sha1

    _, _, abusech_key = _effective_keys()
    if not abusech_key:
        return {"status": "not_configured"}

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.post(endpoint, data=payload, headers={"Auth-Key": abusech_key})
        resp.raise_for_status()
        body = resp.json()
        query_status = body.get("query_status")
        if query_status == "no_results":
            return {"status": "ok", "data": {"found": False}}
        if query_status != "ok":
            return {"status": "error", "error": f"URLhaus query_status={query_status}"}
        urls = body.get("urls") or []
        return {
            "status": "ok",
            "data": {
                "found": True,
                "url_count": len(urls) if itype != "url" else 1,
                "threat": body.get("threat"),
                "tags": body.get("tags") or [],
                "urlhaus_reference": body.get("urlhaus_reference"),
            },
        }
    except httpx.HTTPStatusError as exc:
        return {"status": "error", "error": f"URLhaus returned {exc.response.status_code}"}
    except Exception as exc:
        logger.warning("URLhaus lookup failed: %s", exc)
        return {"status": "error", "error": str(exc)}


async def lookup_threatfox(indicator: str, itype: str) -> dict:
    _, _, abusech_key = _effective_keys()
    if not abusech_key:
        return {"status": "not_configured"}

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": indicator},
                headers={"Auth-Key": abusech_key},
            )
        resp.raise_for_status()
        body = resp.json()
        query_status = body.get("query_status")
        if query_status == "no_result":
            return {"status": "ok", "data": {"found": False}}
        if query_status != "ok":
            return {"status": "error", "error": f"ThreatFox query_status={query_status}"}
        iocs = body.get("data") or []
        first = iocs[0] if iocs else {}
        return {
            "status": "ok",
            "data": {
                "found": len(iocs) > 0,
                "ioc_count": len(iocs),
                "malware": first.get("malware_printable"),
                "threat_type": first.get("threat_type"),
                "confidence_level": first.get("confidence_level"),
                "first_seen": first.get("first_seen"),
            },
        }
    except httpx.HTTPStatusError as exc:
        return {"status": "error", "error": f"ThreatFox returned {exc.response.status_code}"}
    except Exception as exc:
        logger.warning("ThreatFox lookup failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _normalize_indicator(value: str) -> str:
    return value.strip().lower()


def resolve_target_ip(incident: dict) -> str | None:
    """Threat intel should check the actual external/remote address behind an alert, not the
    Wazuh agent's own IP that `source_ip` always is now (correlator.py's extract_source_ip
    groups cases by agent.ip only, never data.srcip — see unique_values for why). When the
    case's alerts carried exactly one distinct external data.srcip (the common single-attacker
    scenario — a brute force, a scan, etc.), that's the one to check. When there were several
    different external callers (e.g. many browsers all hitting the same Nginx host and getting
    500s), there's no single "the" attacker IP to single out, so this falls back to the host's
    own IP rather than arbitrarily picking one caller out of many."""
    external_ips = (incident.get("unique_values") or {}).get("data.srcip") or []
    if len(external_ips) == 1:
        return external_ips[0]
    return incident.get("source_ip")


def peek_cached(indicator: str) -> dict | None:
    """Read a cached lookup_all() result without ever triggering a new lookup. Used by the
    incident risk score, which must never itself cause billed or rate-limited API traffic just
    because an analyst listed or opened incidents — if nothing is cached yet, it simply omits
    the threat-intel signal rather than fetching it."""
    cached = _cache.get(_normalize_indicator(indicator))
    if cached and time.time() - cached["cached_at"] < CACHE_TTL_SECONDS:
        return cached["result"]
    return None


async def lookup_all(indicator: str) -> dict:
    cache_key = _normalize_indicator(indicator)
    cached = _cache.get(cache_key)
    if cached and time.time() - cached["cached_at"] < CACHE_TTL_SECONDS:
        return cached["result"]

    itype = detect_indicator_type(indicator)
    names = ["virustotal", "abuseipdb", "urlhaus", "threatfox"]
    results = await asyncio.gather(
        lookup_virustotal(indicator, itype),
        lookup_abuseipdb(indicator, itype),
        lookup_urlhaus(indicator, itype),
        lookup_threatfox(indicator, itype),
        return_exceptions=True,
    )

    sources = {}
    for name, result in zip(names, results):
        sources[name] = {"status": "error", "error": str(result)} if isinstance(result, Exception) else result

    payload = {"indicator": indicator, "indicator_type": itype, "sources": sources}
    _cache[cache_key] = {"result": payload, "cached_at": time.time()}
    return payload

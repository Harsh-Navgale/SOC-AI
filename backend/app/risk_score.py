"""Composite incident risk score — a 0-100 heuristic blending signals already sitting on the
incident document (severity, alert volume, max Wazuh rule level) with threat-intel context IF
it happens to already be cached from an earlier lookup. Deliberately never triggers a fresh
threat-intel call itself: this runs on every incident list/detail read, and Wazuh's own alerting
is free/self-hosted while the threat-intel sources are rate-limited free tiers (or billed AWS
calls, for S3 inventory) — a risk score must not be the thing that quietly burns through either.
"""
from app import threat_intel

LOW, MEDIUM, HIGH, CRITICAL = "low", "medium", "high", "critical"


def _label(score: int) -> str:
    if score >= 80:
        return CRITICAL
    if score >= 60:
        return HIGH
    if score >= 30:
        return MEDIUM
    return LOW


def _threat_intel_points(source_ip: str | None) -> tuple[int, bool]:
    """Returns (points, threat_intel_included). Only ever reads from the threat-intel module's
    existing cache — never fetches."""
    if not source_ip:
        return 0, False
    cached = threat_intel.peek_cached(source_ip)
    if not cached:
        return 0, False

    sources = cached.get("sources", {})
    saw_any_data = False
    found_bad = False
    found_partial = False

    vt = sources.get("virustotal", {})
    if vt.get("status") == "ok" and (vt.get("data") or {}).get("found"):
        saw_any_data = True
        if (vt["data"].get("malicious") or 0) > 0:
            found_bad = True

    abuse = sources.get("abuseipdb", {})
    if abuse.get("status") == "ok" and (abuse.get("data") or {}).get("found"):
        saw_any_data = True
        score = abuse["data"].get("abuse_confidence_score") or 0
        if score >= 50:
            found_bad = True
        elif score > 0:
            found_partial = True

    urlhaus = sources.get("urlhaus", {})
    if urlhaus.get("status") == "ok" and (urlhaus.get("data") or {}).get("found"):
        saw_any_data = True
        if (urlhaus["data"].get("url_count") or 0) > 0:
            found_bad = True

    threatfox = sources.get("threatfox", {})
    if threatfox.get("status") == "ok" and (threatfox.get("data") or {}).get("found"):
        saw_any_data = True
        if (threatfox["data"].get("ioc_count") or 0) > 0:
            found_bad = True

    if not saw_any_data:
        return 0, False
    if found_bad:
        return 15, True
    if found_partial:
        return 5, True
    return 0, True


def compute_risk_score(incident: dict) -> dict:
    severity_points = 45 if incident.get("severity") == "high" else 15
    volume_points = min((incident.get("alert_count") or 0) * 2, 20)
    level_points = min((incident.get("max_level") or 0) * 1.5, 20)
    ti_points, ti_included = _threat_intel_points(threat_intel.resolve_target_ip(incident))

    score = max(0, min(100, round(severity_points + volume_points + level_points + ti_points)))

    return {
        "score": score,
        "label": _label(score),
        "threat_intel_included": ti_included,
    }

import logging
import os
import time
import uuid
from datetime import datetime, timezone

from pymongo import MongoClient
from pymongo.errors import PyMongoError

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongodb:27017")
MONGO_DB = os.getenv("MONGO_DB", "soc_ai")
WINDOW_SECONDS = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))
THRESHOLD = int(os.getenv("CORRELATION_THRESHOLD", "5"))
POLL_SECONDS = int(os.getenv("CORRELATOR_POLL_SECONDS", "10"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s correlator: %(message)s",
)
logger = logging.getLogger("soc.correlator")

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = client[MONGO_DB]
raw_alerts = db["raw_alerts"]
incidents = db["incidents"]
heartbeats = db["system_heartbeats"]
exclusion_rules = db["exclusion_rules"]
# Populated by the backend (app/asset_cache.py) from the S3 inventory, keyed by normalized IP —
# a plain indexed lookup here, no AWS dependency or IP-normalization logic needed in this
# service at all; all of that already ran once when the backend wrote the cache.
asset_inventory_cache = db["asset_inventory_cache"]
# Set by the backend (POST /api/settings/case-correlation) — a shared Mongo doc, not an
# in-memory flag, because this pause has to be visible to a separate container with no memory
# in common with the backend process that exposes the toggle.
system_settings = db["system_settings"]


def is_correlation_paused() -> bool:
    doc = system_settings.find_one({"_id": "case_correlation"})
    return bool(doc and doc.get("paused"))


def lookup_asset(source_ip: str) -> dict | None:
    doc = asset_inventory_cache.find_one({"_id": source_ip.strip().lower()})
    if not doc:
        return None
    return {"hostname": doc.get("hostname"), "raw": doc.get("raw", {})}


# Per-alert identifier fields that are guaranteed to differ on every single alert — tracking
# them as a "unique values" set would just grow forever, one entry per alert, with zero
# analytic value. Everything else in the alert is fair game.
_EXCLUDED_TOP_LEVEL_KEYS = {"_id", "correlated", "timestamp"}
# `full_log` lines are long strings — capped tighter than other fields so a noisy case doesn't
# balloon the incident document. Every other field is capped generously since most Wazuh alert
# fields (ports, users, hostnames, URLs...) are short strings with naturally low cardinality.
_MAX_FULL_LOG_VALUES = 10
_MAX_VALUES_PER_FIELD = 50


def flatten_alert_values(alert: dict) -> dict[str, set[str]]:
    """Walks the entire raw alert — arbitrarily nested dicts/lists — and collects every distinct
    scalar leaf value, keyed by its dotted field path (e.g. "data.srcport", "agent.name",
    "full_log"). This is how the case ends up holding every unique value seen across all the
    alerts folded into it (usernames, ports, protocols, URLs, agent identifiers, log lines...),
    not just whatever the most recently processed alert happened to contain."""
    out: dict[str, set[str]] = {}

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                if not path and key in _EXCLUDED_TOP_LEVEL_KEYS:
                    continue
                walk(value, f"{path}.{key}" if path else key)
        elif isinstance(node, list):
            for item in node:
                walk(item, path)
        elif node not in (None, ""):
            out.setdefault(path, set()).add(str(node))

    walk(alert, "")
    return out


def merge_unique_values(existing: dict | None, new_values: dict[str, set[str]]) -> dict[str, list[str]]:
    """Folds a newly-processed alert's field values into the case's running set, capping each
    field so one especially chatty case can't grow its document without bound."""
    merged: dict[str, set[str]] = {path: set(values) for path, values in (existing or {}).items()}
    for path, values in new_values.items():
        cap = _MAX_FULL_LOG_VALUES if path == "full_log" else _MAX_VALUES_PER_FIELD
        bucket = merged.setdefault(path, set())
        for value in values:
            if len(bucket) >= cap:
                break
            bucket.add(value)
    return {path: sorted(values) for path, values in merged.items()}


def extract_source_ip(alert: dict) -> str:
    """Always the Wazuh agent's own IP — the host that raised the alert — never
    `data.srcip` (a client/remote address some alert types carry, e.g. the caller behind an
    Nginx 500). Grouping by agent IP means every alert from a given host lands in the same
    case regardless of alert type, instead of web-facing alerts scattering across a different
    case per remote caller."""
    return alert.get("agent", {}).get("ip") or "unknown"


def extract_mitre(alert: dict) -> dict:
    mitre = (alert.get("rule", {}) or {}).get("mitre", {}) or {}
    return {
        "ids": mitre.get("id", []) or [],
        "tactics": mitre.get("tactic", []) or [],
    }


def is_vulnerability_alert(alert: dict) -> bool:
    """True for a Wazuh Vulnerability Detection module finding (a CVE match — state drift,
    "Active"/"Solved") rather than a behavioral detection rule firing on an event. These have
    different temporal semantics than a rule-fired alert burst, so a case built from one is
    tagged here and excluded from the rule-health FP-rate rollup (app/rule_health.py) — "this
    rule is miscalibrated" isn't a meaningful judgment for a CVE match. Matched by substring on
    rule.groups since the exact group name has varied across Wazuh versions."""
    groups = (alert.get("rule", {}) or {}).get("groups") or []
    return any("vulnerability" in str(g).lower() for g in groups)


def _get_field(alert: dict, field: str):
    """Reads a value out of an alert for exclusion-rule matching. "source_ip" and "mitre.tactic"
    are computed the same way the rest of this module already derives them (not literal nested
    dict paths); everything else is a plain dotted path into the alert's own fields."""
    if field == "source_ip":
        return extract_source_ip(alert)
    if field == "mitre.tactic":
        return extract_mitre(alert)["tactics"]
    value = alert
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _matches_criterion(alert: dict, criterion: dict) -> bool:
    value = _get_field(alert, criterion.get("field", ""))
    target = str(criterion.get("value", "")).strip().lower()
    if not target:
        return False
    if isinstance(value, list):
        haystack = [str(v).strip().lower() for v in value]
        return target in haystack if criterion.get("operator") == "equals" else any(target in v for v in haystack)
    text = str(value or "").strip().lower()
    return text == target if criterion.get("operator") == "equals" else target in text


def find_matching_exclusion(alert: dict, rules: list) -> str | None:
    """Returns the description of the first active rule whose criteria all match this alert
    (AND within a rule, OR across rules), or None if nothing matches. Pure dict-field
    comparison — no model call — so this runs on every alert with no added latency."""
    for rule in rules:
        criteria = rule.get("criteria") or []
        if criteria and all(_matches_criterion(alert, c) for c in criteria):
            return rule.get("description", "")
    return None


def rule_key(alert: dict) -> str:
    """Cases group by (source_ip, rule), not source_ip alone — two different attack types
    against the same host become two separate cases instead of one bucket that mixes them
    together. Prefers Wazuh's own stable rule id; falls back to the description only when a
    rule has no id at all."""
    rule = alert.get("rule", {}) or {}
    return str(rule.get("id") or rule.get("description") or "")


def _alert_time(alert: dict, fallback: datetime) -> datetime:
    """Uses the alert's OWN timestamp for correlation windowing and first/last-seen tracking —
    not wall-clock processing time. This matters as soon as alerts aren't processed within
    seconds of occurring, which is exactly the case for uploaded historical Wazuh data: using
    "now" here would either wrongly merge two genuinely separate real-world incidents that
    happen to be uploaded in the same batch, or display a first/last-seen time that's months
    off from when the alert actually happened. Falls back to wall-clock time only when the
    alert has no parseable timestamp."""
    ts = alert.get("timestamp")
    if ts:
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            logger.warning("Alert %s has an unparseable timestamp %r; using processing time instead", alert.get("_id"), ts)
    return fallback


def process_alert(alert: dict):
    source_ip = extract_source_ip(alert)
    rule = alert.get("rule", {}) or {}
    level = rule.get("level", 0)
    description = rule.get("description", "")
    key = rule_key(alert)
    mitre = extract_mitre(alert)
    asset = lookup_asset(source_ip)
    alert_values = flatten_alert_values(alert)
    now = datetime.now(timezone.utc)
    alert_time = _alert_time(alert, now)

    # A symmetric range, not just "$gte" — live-polled alerts always arrive in forward time
    # order, where only the lower bound ever mattered, but uploaded historical data can be
    # processed in any order (including reverse-chronological, e.g. a "most recent first"
    # export). A one-sided check would let a much-later alert's incident swallow a much-earlier
    # one processed afterward, since "incident.last_seen >= alert_time - window" is trivially
    # true whenever the incident is already newer than the alert being processed.
    open_incident = incidents.find_one({
        "source_ip": source_ip,
        "rule_key": key,
        "case_status": {"$ne": "closed"},
        "last_seen": {
            "$gte": alert_time.timestamp() - WINDOW_SECONDS,
            "$lte": alert_time.timestamp() + WINDOW_SECONDS,
        },
    })

    if open_incident:
        # Alerts within an uploaded historical file aren't guaranteed to be in perfect
        # chronological order — max()/min() keep last_seen/first_seen from moving the wrong
        # direction if an out-of-order alert is processed after ones on the other side of it.
        new_last_seen = max(open_incident.get("last_seen", 0), alert_time.timestamp())
        new_first_seen = min(open_incident.get("first_seen", alert_time.timestamp()), alert_time.timestamp())
        incidents.update_one(
            {"_id": open_incident["_id"]},
            {
                "$push": {"alert_ids": alert["_id"]},
                "$inc": {"alert_count": 1},
                "$max": {"max_level": level},
                "$addToSet": {
                    "mitre_ids": {"$each": mitre["ids"]},
                    "mitre_tactics": {"$each": mitre["tactics"]},
                },
                "$set": {
                    "first_seen": new_first_seen,
                    "first_seen_iso": datetime.fromtimestamp(new_first_seen, tz=timezone.utc).isoformat(),
                    "last_seen": new_last_seen,
                    "last_seen_iso": datetime.fromtimestamp(new_last_seen, tz=timezone.utc).isoformat(),
                    # Refreshed on every fold-in too, not just at creation — keeps it current as
                    # the backend's cache itself gets refreshed, at no extra lookup cost.
                    "asset": asset,
                    "unique_values": merge_unique_values(open_incident.get("unique_values"), alert_values),
                },
            },
        )
        if open_incident["alert_count"] + 1 >= THRESHOLD:
            incidents.update_one(
                {"_id": open_incident["_id"]},
                {"$set": {"severity": "high"}},
            )
    else:
        incidents.insert_one({
            "_id": str(uuid.uuid4()),
            "source_ip": source_ip,
            "rule_key": key,
            "case_status": "open",
            "assigned_to": None,
            "notes": [],
            "severity": "low",
            "alert_ids": [alert["_id"]],
            "alert_count": 1,
            "max_level": level,
            "mitre_ids": mitre["ids"],
            "mitre_tactics": mitre["tactics"],
            "first_seen": alert_time.timestamp(),
            "first_seen_iso": alert_time.isoformat(),
            "last_seen": alert_time.timestamp(),
            "last_seen_iso": alert_time.isoformat(),
            "rule_description": description,
            "priority": 0,
            "asset": asset,
            "unique_values": merge_unique_values(None, alert_values),
            "is_vulnerability_alert": is_vulnerability_alert(alert),
        })

    raw_alerts.update_one({"_id": alert["_id"]}, {"$set": {"correlated": True}})


def run_once() -> int:
    if is_correlation_paused():
        # Raw alerts just keep piling up uncorrelated (correlated=False) until resumed — the
        # correlator itself still reports a healthy heartbeat below, since "paused" isn't a
        # failure state.
        return 0

    # Loaded once per poll cycle, not per alert — active_rules rarely changes and this keeps
    # exclusion checking a plain in-memory comparison per alert, not an extra query each time.
    active_rules = list(exclusion_rules.find({"active": True}))
    pending = list(raw_alerts.find({"correlated": False}).limit(200))
    for alert in pending:
        try:
            excluded_by = find_matching_exclusion(alert, active_rules)
            if excluded_by:
                raw_alerts.update_one(
                    {"_id": alert["_id"]},
                    {"$set": {"correlated": True, "excluded": True, "excluded_by_rule": excluded_by}},
                )
                continue
            process_alert(alert)
        except Exception:
            logger.exception("Failed to correlate alert %s", alert.get("_id"))
    return len(pending)


def write_heartbeat(processed: int, error: str | None = None):
    # `error` surfaces on the backend's debug diagnostics endpoint so an admin can see the
    # correlator's last failure without shelling into its container — cleared (via $unset) on
    # the next successful cycle rather than left to look permanently broken after a blip.
    try:
        update = {"$set": {"last_run": time.time()}, "$inc": {"alerts_processed_total": processed}}
        if error:
            update["$set"]["last_error"] = error
            update["$set"]["last_error_at"] = datetime.now(timezone.utc).isoformat()
        else:
            update["$unset"] = {"last_error": "", "last_error_at": ""}
        heartbeats.update_one({"_id": "correlator"}, update, upsert=True)
    except PyMongoError:
        logger.exception("Failed to write correlator heartbeat")


def run():
    logger.info("Correlator started, watching raw_alerts (window=%ss, threshold=%s)", WINDOW_SECONDS, THRESHOLD)
    while True:
        processed = 0
        error = None
        try:
            processed = run_once()
            if processed:
                logger.info("Correlated %d alert(s)", processed)
        except PyMongoError as exc:
            logger.exception("Lost connection to MongoDB, will retry")
            error = str(exc)
        except Exception as exc:
            logger.exception("Unexpected error in correlator loop")
            error = str(exc)
        write_heartbeat(processed, error)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    run()

"""Aggregates HUMAN-CONFIRMED incident dispositions (schemas.CloseIncidentRequest.disposition)
per Wazuh rule, so a rule that keeps getting confirmed false-positive by analysts surfaces as a
real, evidence-backed tuning candidate — not just a one-off AI guess. Deliberately decoupled from
exclusion_rules.py: that module is a forward-looking, pre-correlation noise filter an admin
authors by hand; this module only ever reads disposition data that already exists on closed
incidents and never suppresses anything itself.

The AI's own per-investigation opinion (rag.py's `investigation.rule_health` field) is surfaced
here too, but kept in separately-named fields (`ai_flagged_miscalibrated`/`ai_rule_health_total`)
so it can never be confused with the human-confirmed counts — that distinction is the whole
point of requiring a confirmed disposition in the first place.
"""
from app.config import RULE_FP_NOTIFY_THRESHOLD
from app.db import db, incidents
from app import notifications
from app.rag import _RULE_HEALTH_VALUES

# Tracks, per rule_key, whether the one-shot false-positive-threshold notification (see
# check_fp_threshold) has already fired — mirrors scheduler.py's check_case_aging "notified"
# flag pattern, just keyed on a rule (which has no document of its own anywhere) rather than on
# the incident document that pattern uses elsewhere.
rule_fp_tracking = db["rule_fp_tracking"]


async def get_rule_health_summary() -> list[dict]:
    pipeline = [
        # Vulnerability Detection findings (CVE matches, state drift) excluded — see
        # correlator.py's is_vulnerability_alert(). "This rule is miscalibrated" isn't a
        # meaningful judgment for a CVE match the way it is for a behavioral detection rule.
        {"$match": {
            "case_status": "closed", "disposition": {"$exists": True},
            "is_vulnerability_alert": {"$ne": True},
        }},
        {"$group": {
            "_id": "$rule_key",
            "rule_description": {"$first": "$rule_description"},
            "confirmed_total": {"$sum": 1},
            "confirmed_false_positive": {"$sum": {"$cond": [{"$eq": ["$disposition", "false_positive"]}, 1, 0]}},
            "confirmed_true_positive": {"$sum": {"$cond": [{"$eq": ["$disposition", "true_positive"]}, 1, 0]}},
            "confirmed_benign_positive": {"$sum": {"$cond": [{"$eq": ["$disposition", "benign_positive"]}, 1, 0]}},
            "ai_flagged_miscalibrated": {"$sum": {"$cond": [{"$eq": ["$investigation.rule_health", "likely_miscalibrated"]}, 1, 0]}},
            # NOT `{"$ne": ["$investigation.rule_health", None]}` — MongoDB's $ne treats a
            # genuinely missing field (e.g. an investigation generated before this field existed)
            # the same as an explicit null for comparison purposes, so that version silently
            # counted old, opinion-less investigations as "has an AI rule-health opinion". $in
            # against the actual closed set of values is immune to that: a missing field can
            # never match a literal value in the list.
            "ai_rule_health_total": {"$sum": {"$cond": [{"$in": ["$investigation.rule_health", list(_RULE_HEALTH_VALUES)]}, 1, 0]}},
        }},
        {"$addFields": {
            "confirmed_fp_rate": {
                "$cond": [
                    {"$eq": ["$confirmed_total", 0]}, None,
                    {"$divide": ["$confirmed_false_positive", "$confirmed_total"]},
                ]
            },
        }},
        {"$sort": {"confirmed_false_positive": -1}},
    ]
    return [doc async for doc in incidents.aggregate(pipeline)]


async def check_fp_threshold(rule_key: str | None, rule_description: str | None, incident_id: str) -> bool:
    """Fires a one-time admin notification once a rule has RULE_FP_NOTIFY_THRESHOLD or more
    confirmed-false-positive closures. Returns True exactly when a new notification was created,
    so the caller knows whether a notifications_changed broadcast is actually needed."""
    if not rule_key:
        return False

    count = await incidents.count_documents({"rule_key": rule_key, "disposition": "false_positive"})
    if count < RULE_FP_NOTIFY_THRESHOLD:
        return False

    tracking = await rule_fp_tracking.find_one({"_id": rule_key})
    if tracking and tracking.get("notified"):
        return False

    await notifications.create(
        f"Rule '{rule_description or rule_key}' has {count} confirmed false positives — "
        "consider tuning it or adding an exclusion rule.",
        "rule_fp_threshold", user=None, incident_id=incident_id,
    )
    await rule_fp_tracking.update_one(
        {"_id": rule_key}, {"$set": {"notified": True, "count_at_notify": count}}, upsert=True,
    )
    return True

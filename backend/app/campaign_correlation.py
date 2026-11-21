"""Groups open incidents into a "campaign" when they share a rule_key or an overlapping
mitre_tactics entry, across DIFFERENT source_ips, within a rolling time window — the correlator
already folds same-IP+same-rule alerts into one incident; this is the next layer up, connecting
incidents that look like the same coordinated/multi-stage event across hosts.

Pure Mongo aggregation/in-process grouping, no AI call — same category of job as
rule_health.py's rollup, just writing back to `incidents` instead of only reading from it. See
.claude/prds/cross-incident-campaign-correlation.prd.md for the product reasoning.
"""
import logging
import time

from app.db import incidents

logger = logging.getLogger("soc.campaign_correlation")

DEFAULT_WINDOW_SECONDS = 3600


def _windows_overlap(a: dict, b: dict, window_seconds: int) -> bool:
    return (
        a["first_seen"] <= b["last_seen"] + window_seconds
        and b["first_seen"] <= a["last_seen"] + window_seconds
    )


async def correlate_campaigns(window_seconds: int = DEFAULT_WINDOW_SECONDS) -> int:
    """Finds open incidents active within window_seconds and groups any sharing a rule_key or an
    overlapping mitre_tactic, from a DIFFERENT source_ip, whose [first_seen, last_seen] windows
    are within window_seconds of each other. Returns the number of incidents newly tagged with
    a campaign_id. Same-source_ip matches are skipped — those are already one incident via the
    correlator, so matching on them here would just be re-finding that same grouping."""
    cutoff = time.time() - window_seconds
    candidates = [
        doc async for doc in incidents.find(
            {"case_status": {"$ne": "closed"}, "last_seen": {"$gte": cutoff}},
            {"_id": 1, "source_ip": 1, "rule_key": 1, "mitre_tactics": 1, "first_seen": 1, "last_seen": 1, "campaign_id": 1},
        )
    ]

    # Union-find over the candidate set: two incidents merge into the same campaign when they
    # match. Keeping this in-process rather than as a Mongo aggregation pipeline because the
    # match is transitive (A-B and B-C merged means A-B-C are one campaign even if A and C don't
    # directly match) — a single aggregation stage can't express that naturally.
    parent = {doc["_id"]: doc["_id"] for doc in candidates}

    def find(x):
        while parent[x] != x:
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for i, a in enumerate(candidates):
        for b in candidates[i + 1:]:
            if a["source_ip"] == b["source_ip"]:
                continue
            shared_rule = a.get("rule_key") and a.get("rule_key") == b.get("rule_key")
            shared_tactic = bool(set(a.get("mitre_tactics") or []) & set(b.get("mitre_tactics") or []))
            if (shared_rule or shared_tactic) and _windows_overlap(a, b, window_seconds):
                union(a["_id"], b["_id"])

    groups: dict[str, list[str]] = {}
    for doc in candidates:
        groups.setdefault(find(doc["_id"]), []).append(doc["_id"])

    updated = 0
    campaigns = 0
    for root, members in groups.items():
        if len(members) < 2:
            continue  # no actual grouping with anything else — nothing to tag
        campaigns += 1
        # The earliest-created member's own _id is reused as the campaign_id — stable, no new
        # id scheme needed, and deterministic across repeated runs of this same job.
        result = await incidents.update_many(
            {"_id": {"$in": members}, "campaign_id": {"$ne": root}},
            {"$set": {"campaign_id": root}},
        )
        updated += result.modified_count

    if updated:
        logger.info("campaign_correlation: tagged %d incident(s) across %d campaign(s)", updated, campaigns)
    return updated

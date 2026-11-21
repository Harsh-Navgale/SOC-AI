import logging
import time
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.wazuh_client import fetch_recent_alerts
from app.db import raw_alerts, incidents, system_heartbeats
from app import ws_manager, debug_state, alerting, notifications, ai_usage, asset_cache, case_enrichment, pipeline_settings, campaign_correlation
from app.rag import investigate_incident
from app.risk_score import compute_risk_score
from app.config import CORRELATOR_STALE_SECONDS, CASE_AGING_HOURS

logger = logging.getLogger("soc.scheduler")
scheduler = AsyncIOScheduler()

_last_alert_ts = None
_last_incident_ts = None

# Runtime on/off switch for auto-investigation — a safety valve, not a default-off feature.
# Every new case gets AI-reviewed automatically; this exists so it can be paused if Bedrock
# ever needs a break, without touching code.
auto_investigate_enabled = True

# One-shot flag for the monthly-budget-exceeded notification (see auto_investigate_cases below)
# — same pattern as rag.py's _notify_fallback_once: notify once when the cap is first crossed,
# reset the moment spend is back under it (i.e. a new calendar month starts), so a long-running
# over-cap month doesn't re-notify every 15s tick.
_budget_notified = False

# Same idea, one stage earlier in the pipeline: stop pulling new alerts from Wazuh without
# touching anything already ingested or already correlated into cases.
alert_ingestion_enabled = True

# Same idea, the stage between correlation and AI investigation: stop enriching newly-correlated
# cases with threat intel / org-docs context without touching anything already enriched.
enrichment_enabled = True

# Same idea again — this job runs purely in the backend process (unlike case correlation, which
# lives in the separate correlator container and needs the Mongo-backed pipeline_settings pause
# instead), so it gets the same in-memory toggle as every other backend-only stage above.
campaign_correlation_enabled = True


def set_auto_investigate_enabled(value: bool):
    global auto_investigate_enabled
    auto_investigate_enabled = value


def set_alert_ingestion_enabled(value: bool):
    global alert_ingestion_enabled
    alert_ingestion_enabled = value


def set_enrichment_enabled(value: bool):
    global enrichment_enabled
    enrichment_enabled = value


def set_campaign_correlation_enabled(value: bool):
    global campaign_correlation_enabled
    campaign_correlation_enabled = value


async def poll_wazuh():
    if not alert_ingestion_enabled:
        return
    try:
        alerts = await fetch_recent_alerts(minutes=2)
    except Exception as exc:
        logger.exception("Unexpected error polling Wazuh; will retry next cycle")
        debug_state.record_error("poll_wazuh", str(exc))
        await alerting.record_failure("poll_wazuh", str(exc))
        return
    await alerting.record_success("poll_wazuh")

    for alert in alerts:
        try:
            alert_id = alert.pop("_id")
            alert["correlated"] = False
            await raw_alerts.update_one(
                {"_id": alert_id},
                {"$setOnInsert": alert},
                upsert=True,
            )
        except Exception:
            logger.exception("Failed to store alert %s", alert.get("_id"))

    if alerts:
        logger.info("Polled %d alert(s) from Wazuh", len(alerts))


async def broadcast_updates():
    """Pushes a lightweight "something changed" ping over WebSocket so connected dashboards can
    refetch immediately instead of waiting out their own poll interval. Deliberately doesn't ship
    the changed documents themselves — just detects that the newest alert/incident moved since
    last check (via a single indexed max-timestamp lookup per collection) and lets the client's
    existing REST + filter logic do the real fetch. Alerts are keyed by their alert-arrival
    timestamp; incidents by last_seen, which also advances when the correlator folds a new alert
    into an already-open case."""
    global _last_alert_ts, _last_incident_ts
    try:
        latest_alert = await raw_alerts.find_one(sort=[("timestamp", -1)])
        alert_ts = latest_alert["timestamp"] if latest_alert else None
        if alert_ts != _last_alert_ts:
            if _last_alert_ts is not None:
                await ws_manager.broadcast({"type": "alerts_changed"})
            _last_alert_ts = alert_ts

        latest_incident = await incidents.find_one(sort=[("last_seen", -1)])
        incident_ts = latest_incident["last_seen"] if latest_incident else None
        if incident_ts != _last_incident_ts:
            if _last_incident_ts is not None:
                await ws_manager.broadcast({"type": "incidents_changed"})
            _last_incident_ts = incident_ts
    except Exception:
        logger.exception("Unexpected error while checking for updates to broadcast")


async def enrich_new_cases():
    """Runs between correlation and AI investigation: every freshly-correlated case gets
    threat-intel + org-docs instance/client context computed exactly once, before
    auto_investigate_cases is allowed to pick it up (see that function's query, which now
    requires "enrichment" to already exist). Same one-at-a-time, leave-unmarked-on-failure
    shape as auto_investigate_cases, and for the same reasons — this also makes live network
    calls (threat-intel APIs, Bedrock for the org-docs extraction) that shouldn't run several at
    once, both for rate-limit headroom and to bound concurrent per-token Bedrock cost.
    """
    if not enrichment_enabled:
        return

    case = await incidents.find_one(
        {"enrichment": {"$exists": False}},
        sort=[("priority", -1), ("first_seen", 1)],
    )
    if not case:
        return

    incident_id = case["_id"]
    logger.debug("enrich_new_cases: picked case=%s", incident_id)

    try:
        result = await case_enrichment.enrich_case(case)
    except Exception as exc:
        logger.exception("Enrichment failed for case %s; will retry next cycle", incident_id)
        debug_state.record_error("enrich_new_cases", f"case {incident_id}: {exc}")
        await alerting.record_failure("enrich_new_cases", str(exc))
        return

    await alerting.record_success("enrich_new_cases")
    await incidents.update_one(
        {"_id": incident_id},
        {"$set": {
            "threat_intel": result["threat_intel"],
            "org_context": result["org_context"],
            "enrichment": {"enriched_at": datetime.now(timezone.utc).isoformat()},
        }},
    )
    logger.info("Enriched case %s", incident_id)


async def auto_investigate_cases():
    """Every case the correlator produces gets an AI investigation automatically — no manual
    click required. Processed one at a time (APScheduler's default max_instances=1 already
    prevents this job from overlapping itself, so a slow generation just delays the next tick
    rather than running two investigations at once): firing off dozens of simultaneous
    generations for a big bulk upload would hit Bedrock rate limits and multiply cost without
    finishing any sooner. A case is left un-investigated (not marked/skipped) on failure,
    so it's naturally retried on a later tick rather than silently dropped forever.
    """
    if not auto_investigate_enabled:
        return

    global _budget_notified
    cap = await pipeline_settings.get_monthly_budget_cap()
    if cap is not None:
        spend = await ai_usage.month_to_date_cost()
        if spend >= cap:
            if not _budget_notified:
                _budget_notified = True
                await notifications.create(
                    f"Monthly AI budget cap (${cap:.2f}) reached — ${spend:.2f} spent this month. "
                    "Auto-investigation is paused; manual investigation still works.",
                    "budget_cap_reached", user=None,
                )
                await ws_manager.broadcast({"type": "notifications_changed"})
            return
        _budget_notified = False

    # Higher priority first (an analyst can bump a case to the front of the queue via the AI
    # Queue panel); first_seen ascending breaks ties so same-priority cases still queue oldest
    # first, same as before priority existed. "enrichment" must already exist — enrich_new_cases
    # runs first and is what actually makes threat_intel/org_context below reads instead of
    # live lookups; a case that hasn't been enriched yet just waits for its turn there.
    case = await incidents.find_one(
        {"investigation": {"$exists": False}, "enrichment": {"$exists": True}},
        sort=[("priority", -1), ("first_seen", 1)],
    )
    if not case:
        return

    incident_id = case["_id"]
    logger.debug("auto_investigate_cases: picked case=%s priority=%s first_seen=%s", incident_id, case.get("priority", 0), case.get("first_seen"))

    # Computed once by enrich_new_cases right after correlation, not here — same idea as
    # asset/unique_values below, just added later. No live threat-intel call in this hot path.
    ti_result = case.get("threat_intel")

    # Stored on the incident at creation time (correlator.py / main.py's promote_alert) from
    # the cached S3 inventory — no live S3 call needed here anymore, see asset_cache.py.
    asset = case.get("asset")

    # Same idea — every distinct value seen across this case's alerts, aggregated at
    # correlation time (correlator.py's merge_unique_values), no extra lookup needed here.
    unique_values = case.get("unique_values")

    # Instance/client name from org docs — also computed by enrich_new_cases, not here.
    org_context = case.get("org_context")

    risk = compute_risk_score(case)

    try:
        report = await investigate_incident(
            case, threat_intel=ti_result, asset=asset, risk=risk, unique_values=unique_values, org_context=org_context,
        )
    except Exception as exc:
        logger.exception("Auto-investigation failed for case %s; will retry next cycle", incident_id)
        debug_state.record_error("auto_investigate_cases", f"case {incident_id}: {exc}")
        await alerting.record_failure("auto_investigate_cases", str(exc))
        return

    await alerting.record_success("auto_investigate_cases")
    await ai_usage.record(
        "investigate", report.get("model_used", ""), report.get("prompt_tokens", 0),
        report.get("completion_tokens", 0), parse_ok=report.get("parse_ok"),
    )
    await incidents.update_one({"_id": incident_id}, {"$set": {"investigation": report}})
    await ws_manager.broadcast({"type": "incidents_changed"})
    logger.info("Auto-investigated case %s", incident_id)


async def check_correlator_health():
    """The correlator is a separate process/container — the only way the backend can see it's in
    trouble is the heartbeat doc it writes on every cycle. Two failure states: it recorded an
    error on its last run, or it hasn't completed a run recently at all (crashed, stuck, or the
    container itself is down)."""
    try:
        hb = await system_heartbeats.find_one({"_id": "correlator"})
    except Exception:
        logger.exception("Could not read correlator heartbeat")
        return

    if not hb:
        return  # hasn't reported in yet (e.g. just started) — not a failure, just no data

    if hb.get("last_error"):
        await alerting.record_failure("correlator", hb["last_error"])
        return

    age = time.time() - hb.get("last_run", 0)
    if age > CORRELATOR_STALE_SECONDS:
        await alerting.record_failure("correlator", f"no successful run in {int(age)}s")
        return

    await alerting.record_success("correlator")


async def check_case_aging():
    """Flags a case that's been open too long without being closed — once. `aging_notified`
    prevents re-notifying every tick for the same case; it's cleared implicitly by the case
    simply not matching the query anymore once closed."""
    threshold = time.time() - CASE_AGING_HOURS * 3600
    cursor = incidents.find({
        "case_status": {"$in": ["open", "investigating"]},
        "first_seen": {"$lt": threshold},
        "aging_notified": {"$ne": True},
    })
    notified = 0
    async for case in cursor:
        message = (
            f"Case for {case.get('source_ip')} ({case.get('rule_description')}) has been open "
            f"for over {CASE_AGING_HOURS}h"
        )
        await notifications.create(message, "case_aging", user=case.get("assigned_to"), incident_id=case["_id"])
        await incidents.update_one({"_id": case["_id"]}, {"$set": {"aging_notified": True}})
        notified += 1

    if notified:
        await ws_manager.broadcast({"type": "notifications_changed"})


async def correlate_campaigns():
    """Groups open incidents sharing a rule_key/MITRE tactic across different source_ips into a
    campaign — see campaign_correlation.py. Doesn't need 15s freshness like auto-investigation;
    a 5-minute cadence is plenty for a signal that's informational, not time-critical."""
    if not campaign_correlation_enabled:
        return
    try:
        count = await campaign_correlation.correlate_campaigns()
    except Exception as exc:
        logger.exception("campaign_correlation failed; will retry next tick")
        debug_state.record_error("correlate_campaigns", str(exc))
        return
    if count:
        await ws_manager.broadcast({"type": "incidents_changed"})


async def refresh_asset_inventory_cache():
    """Once a day is plenty — the S3 export itself is a daily job, so refreshing more often
    than that just re-caches the same data. Silently skipped (not an alert-worthy failure) when
    AWS/S3 isn't configured at all, which is the common case for anyone not using this feature."""
    try:
        count = await asset_cache.refresh()
        logger.info("Asset inventory cache refreshed: %d IPs", count)
    except Exception:
        logger.info("Asset inventory cache refresh skipped (S3/AWS not configured or unreachable)")


def start_scheduler():
    scheduler.add_job(poll_wazuh, "interval", seconds=30, id="poll_wazuh")
    scheduler.add_job(broadcast_updates, "interval", seconds=5, id="broadcast_updates")
    scheduler.add_job(enrich_new_cases, "interval", seconds=10, id="enrich_new_cases")
    scheduler.add_job(auto_investigate_cases, "interval", seconds=15, id="auto_investigate_cases")
    scheduler.add_job(check_correlator_health, "interval", seconds=30, id="check_correlator_health")
    scheduler.add_job(check_case_aging, "interval", minutes=10, id="check_case_aging")
    scheduler.add_job(correlate_campaigns, "interval", minutes=5, id="correlate_campaigns")
    # next_run_time=now so a fresh deploy doesn't wait a full day for its first cache fill —
    # every run after that follows the normal 24h interval.
    scheduler.add_job(
        refresh_asset_inventory_cache, "interval", hours=24, id="refresh_asset_inventory_cache",
        next_run_time=datetime.now(timezone.utc),
    )
    scheduler.start()

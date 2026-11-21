import asyncio
import time

import pytest
from mongomock_motor import AsyncMongoMockClient

from app import scheduler as scheduler_module
from app import debug_state, alerting, notifications, ai_usage, pipeline_settings, campaign_correlation


def _incident(incident_id="case-1", source_ip="203.0.113.9", first_seen=0, **overrides):
    doc = {
        "_id": incident_id,
        "source_ip": source_ip,
        "case_status": "open",
        "assigned_to": None,
        "notes": [],
        "severity": "low",
        "alert_count": 1,
        "max_level": 5,
        "mitre_ids": [],
        "mitre_tactics": [],
        "rule_description": "test rule",
        "alert_ids": [],
        "first_seen": first_seen,
        "last_seen": first_seen,
        # Already enriched by default — most of these tests are about auto_investigate_cases
        # itself, not the enrichment gate; tests that care about that gate override this.
        "enrichment": {"enriched_at": "2026-01-01T00:00:00+00:00"},
    }
    doc.update(overrides)
    return doc


@pytest.fixture
def scheduler_db(monkeypatch):
    mock_client = AsyncMongoMockClient()
    db = mock_client["soc_ai_scheduler_test"]
    monkeypatch.setattr(scheduler_module, "raw_alerts", db["raw_alerts"])
    monkeypatch.setattr(scheduler_module, "incidents", db["incidents"])
    monkeypatch.setattr(scheduler_module, "system_heartbeats", db["system_heartbeats"])
    monkeypatch.setattr(ai_usage, "ai_usage_collection", db["ai_usage"])
    monkeypatch.setattr(notifications, "notifications_collection", db["notifications"])
    monkeypatch.setattr(pipeline_settings, "system_settings", db["system_settings"])
    monkeypatch.setattr(campaign_correlation, "incidents", db["incidents"])
    scheduler_module._budget_notified = False
    scheduler_module.set_auto_investigate_enabled(True)
    scheduler_module.set_alert_ingestion_enabled(True)
    scheduler_module.set_enrichment_enabled(True)
    scheduler_module.set_campaign_correlation_enabled(True)
    alerting._consecutive_failures.clear()
    alerting._active_alerts.clear()
    yield db
    scheduler_module.set_auto_investigate_enabled(True)
    scheduler_module.set_alert_ingestion_enabled(True)
    scheduler_module.set_enrichment_enabled(True)
    scheduler_module.set_campaign_correlation_enabled(True)
    alerting._consecutive_failures.clear()
    alerting._active_alerts.clear()


# ---- alert-ingestion pause (pauses pulling new alerts from Wazuh) ----

def test_correlate_campaigns_skips_when_disabled(scheduler_db, monkeypatch):
    scheduler_module.set_campaign_correlation_enabled(False)

    async def fake_correlate(*args, **kwargs):
        raise AssertionError("campaign_correlation.correlate_campaigns should not be called while paused")

    monkeypatch.setattr(campaign_correlation, "correlate_campaigns", fake_correlate)

    asyncio.run(scheduler_module.correlate_campaigns())  # must not raise


def test_correlate_campaigns_broadcasts_when_incidents_are_tagged(scheduler_db, monkeypatch):
    broadcasts = []

    async def fake_correlate(*args, **kwargs):
        return 2

    async def fake_broadcast(payload):
        broadcasts.append(payload)

    monkeypatch.setattr(campaign_correlation, "correlate_campaigns", fake_correlate)
    monkeypatch.setattr(scheduler_module.ws_manager, "broadcast", fake_broadcast)

    asyncio.run(scheduler_module.correlate_campaigns())

    assert broadcasts == [{"type": "incidents_changed"}]


def test_correlate_campaigns_survives_a_failure_for_retry_next_tick(scheduler_db, monkeypatch):
    async def boom(*args, **kwargs):
        raise RuntimeError("mongo hiccup")

    monkeypatch.setattr(campaign_correlation, "correlate_campaigns", boom)

    asyncio.run(scheduler_module.correlate_campaigns())  # must not raise


def test_poll_wazuh_skips_fetch_when_ingestion_paused(scheduler_db, monkeypatch):
    scheduler_module.set_alert_ingestion_enabled(False)

    async def fake_fetch_recent_alerts(minutes):
        raise AssertionError("fetch_recent_alerts should not be called while paused")

    monkeypatch.setattr(scheduler_module, "fetch_recent_alerts", fake_fetch_recent_alerts)

    asyncio.run(scheduler_module.poll_wazuh())  # must not raise


def test_poll_wazuh_still_fetches_when_ingestion_enabled(scheduler_db, monkeypatch):
    async def fake_fetch_recent_alerts(minutes):
        return [{"_id": "a1", "timestamp": "2026-01-01T00:00:00+00:00", "data": {"srcip": "10.0.0.5"}}]

    monkeypatch.setattr(scheduler_module, "fetch_recent_alerts", fake_fetch_recent_alerts)

    asyncio.run(scheduler_module.poll_wazuh())

    stored = asyncio.run(scheduler_db["raw_alerts"].find_one({"_id": "a1"}))
    assert stored is not None


def test_auto_investigate_picks_oldest_uninvestigated_case_and_marks_it(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-old", first_seen=1)))
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-new", first_seen=2)))

    captured = {}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None, org_context=None):
        captured["incident_id"] = incident["_id"]
        return {"raw": "ok", "severity": "high"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    assert captured["incident_id"] == "case-old"
    updated = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-old"}))
    assert updated["investigation"] == {"raw": "ok", "severity": "high"}
    untouched = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-new"}))
    assert "investigation" not in untouched


def test_auto_investigate_picks_higher_priority_case_even_if_newer(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-old-low-priority", first_seen=1, priority=0)))
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-new-high-priority", first_seen=99, priority=5)))

    captured = {}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None, org_context=None):
        captured["incident_id"] = incident["_id"]
        return {"raw": "ok"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    assert captured["incident_id"] == "case-new-high-priority"


def test_auto_investigate_ignores_already_investigated_cases(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(
        _incident("case-done", first_seen=1, investigation={"raw": "already done"})
    ))

    called = False

    async def fake_investigate_incident(*args, **kwargs):
        nonlocal called
        called = True
        return {"raw": "should not run"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    assert called is False


def test_auto_investigate_respects_disabled_toggle(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-1", first_seen=1)))
    scheduler_module.set_auto_investigate_enabled(False)

    called = False

    async def fake_investigate_incident(*args, **kwargs):
        nonlocal called
        called = True
        return {"raw": "should not run"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    assert called is False
    untouched = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-1"}))
    assert "investigation" not in untouched


def test_auto_investigate_skips_when_over_the_monthly_budget_cap(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-1", first_seen=1)))
    asyncio.run(pipeline_settings.set_monthly_budget_cap(1.0))
    asyncio.run(ai_usage.record("investigate", "m", 1_000_000, 0))  # costs well over $1

    called = False

    async def fake_investigate_incident(*args, **kwargs):
        nonlocal called
        called = True
        return {"raw": "should not run"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    assert called is False
    untouched = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-1"}))
    assert "investigation" not in untouched


def test_auto_investigate_notifies_once_when_budget_cap_is_crossed(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-1", first_seen=1)))
    asyncio.run(pipeline_settings.set_monthly_budget_cap(1.0))
    asyncio.run(ai_usage.record("investigate", "m", 1_000_000, 0))

    asyncio.run(scheduler_module.auto_investigate_cases())
    asyncio.run(scheduler_module.auto_investigate_cases())  # same tick-over-cap state again

    async def _collect():
        return [n async for n in scheduler_db["notifications"].find({"type": "budget_cap_reached"})]

    notified = asyncio.run(_collect())
    assert len(notified) == 1  # must not re-notify every tick while still over cap


def test_auto_investigate_still_runs_when_under_the_budget_cap(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-1", first_seen=1)))
    asyncio.run(pipeline_settings.set_monthly_budget_cap(1000.0))

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None, org_context=None):
        return {"raw": "ok", "severity": "high"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    updated = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-1"}))
    assert updated["investigation"] == {"raw": "ok", "severity": "high"}


def test_auto_investigate_leaves_case_unmarked_on_failure_for_retry(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-1", first_seen=1)))

    async def failing_investigate_incident(*args, **kwargs):
        raise RuntimeError("Bedrock is down")

    monkeypatch.setattr(scheduler_module, "investigate_incident", failing_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    untouched = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-1"}))
    assert "investigation" not in untouched


def test_auto_investigate_records_failure_for_debug_diagnostics(scheduler_db, monkeypatch):
    debug_state._recent_errors.clear()
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-1", first_seen=1)))

    async def failing_investigate_incident(*args, **kwargs):
        raise RuntimeError("Bedrock is down")

    monkeypatch.setattr(scheduler_module, "investigate_incident", failing_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    errors = debug_state.recent_errors()
    assert errors[0]["source"] == "auto_investigate_cases"
    assert "case-1" in errors[0]["detail"]
    assert "Bedrock is down" in errors[0]["detail"]


def test_auto_investigate_passes_stored_asset_without_a_live_lookup(scheduler_db, monkeypatch):
    # Asset info is stored on the case at creation time now (correlator.py / promote_alert) —
    # auto_investigate_cases just reads it off the document, no S3 call in this hot path at all.
    asyncio.run(scheduler_db["incidents"].insert_one(
        _incident("case-1", first_seen=1, asset={"hostname": "db-02", "raw": {"env": "prod"}})
    ))

    captured = {}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None, org_context=None):
        captured["asset"] = asset
        return {"raw": "ok"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    assert captured["asset"]["hostname"] == "db-02"


def test_auto_investigate_passes_stored_unique_values_without_a_live_lookup(scheduler_db, monkeypatch):
    # Aggregated once at correlation time (correlator.py's merge_unique_values) and stored
    # directly on the case — auto_investigate_cases just reads it off the document, no extra
    # raw_alerts lookup in this hot path.
    asyncio.run(scheduler_db["incidents"].insert_one(
        _incident("case-1", first_seen=1, unique_values={"full_log": ["line one", "line two"]})
    ))

    captured = {}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None, org_context=None):
        captured["unique_values"] = unique_values
        return {"raw": "ok"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    assert captured["unique_values"] == {"full_log": ["line one", "line two"]}


def test_auto_investigate_passes_stored_threat_intel_without_a_live_lookup(scheduler_db, monkeypatch):
    # Threat intel is computed once by enrich_new_cases (see app/case_enrichment.py), at
    # correlation time — auto_investigate_cases just reads it off the document now, no live
    # lookup_all call in this hot path at all.
    asyncio.run(scheduler_db["incidents"].insert_one(
        _incident("case-1", first_seen=1, threat_intel={"indicator": "198.51.100.7", "indicator_type": "ip", "sources": {}})
    ))

    captured = {}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None, org_context=None):
        captured["threat_intel"] = threat_intel
        return {"raw": "ok"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    assert captured["threat_intel"]["indicator"] == "198.51.100.7"


def test_auto_investigate_passes_stored_org_context_without_a_live_lookup(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(
        _incident("case-1", first_seen=1, org_context={"instance_name": "web-01", "client_name": "Acme"})
    ))

    captured = {}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None, org_context=None):
        captured["org_context"] = org_context
        return {"raw": "ok"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    assert captured["org_context"] == {"instance_name": "web-01", "client_name": "Acme"}


def test_auto_investigate_ignores_cases_not_yet_enriched(scheduler_db, monkeypatch):
    doc = _incident("case-1", first_seen=1)
    del doc["enrichment"]
    asyncio.run(scheduler_db["incidents"].insert_one(doc))

    called = False

    async def fake_investigate_incident(*args, **kwargs):
        nonlocal called
        called = True
        return {"raw": "should not run"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    assert called is False


def test_auto_investigate_does_nothing_when_no_pending_cases(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(
        _incident("case-done", first_seen=1, investigation={"raw": "already done"})
    ))

    called = False

    async def fake_investigate_incident(*args, **kwargs):
        nonlocal called
        called = True
        return {"raw": "should not run"}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    assert called is False


def test_auto_investigate_records_ai_usage_on_success(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-1", first_seen=1)))

    async def fake_investigate_incident(*args, **kwargs):
        return {"raw": "ok", "model_used": "phi4-mini:latest", "prompt_tokens": 200, "completion_tokens": 50, "parse_ok": True}

    monkeypatch.setattr(scheduler_module, "investigate_incident", fake_investigate_incident)

    asyncio.run(scheduler_module.auto_investigate_cases())

    usage = asyncio.run(ai_usage.summary())
    assert usage["calls"] == 1
    assert usage["prompt_tokens"] == 200
    assert usage["parse_failures"] == 0


# ---- enrich_new_cases (threat intel + org-docs context, before the case reaches the AI queue) ----

def _uninvestigated(incident_id="case-1", **overrides):
    # enrich_new_cases picks cases missing "enrichment" — _incident()'s default already has one,
    # so these tests build their own doc without it instead of overriding a key back to absent.
    doc = _incident(incident_id, **overrides)
    doc.pop("enrichment", None)
    return doc


def test_enrich_picks_oldest_unenriched_case_and_marks_it(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_uninvestigated("case-old", first_seen=1)))
    asyncio.run(scheduler_db["incidents"].insert_one(_uninvestigated("case-new", first_seen=2)))

    captured = {}

    async def fake_enrich_case(case):
        captured["incident_id"] = case["_id"]
        return {"threat_intel": {"indicator": "1.2.3.4"}, "org_context": {"instance_name": None, "client_name": None}}

    monkeypatch.setattr(scheduler_module.case_enrichment, "enrich_case", fake_enrich_case)

    asyncio.run(scheduler_module.enrich_new_cases())

    assert captured["incident_id"] == "case-old"
    updated = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-old"}))
    assert updated["threat_intel"] == {"indicator": "1.2.3.4"}
    assert updated["org_context"] == {"instance_name": None, "client_name": None}
    assert "enriched_at" in updated["enrichment"]
    untouched = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-new"}))
    assert "enrichment" not in untouched


def test_enrich_picks_higher_priority_case_even_if_newer(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_uninvestigated("case-old-low-priority", first_seen=1, priority=0)))
    asyncio.run(scheduler_db["incidents"].insert_one(_uninvestigated("case-new-high-priority", first_seen=99, priority=5)))

    captured = {}

    async def fake_enrich_case(case):
        captured["incident_id"] = case["_id"]
        return {"threat_intel": None, "org_context": {"instance_name": None, "client_name": None}}

    monkeypatch.setattr(scheduler_module.case_enrichment, "enrich_case", fake_enrich_case)

    asyncio.run(scheduler_module.enrich_new_cases())

    assert captured["incident_id"] == "case-new-high-priority"


def test_enrich_ignores_already_enriched_cases(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-done", first_seen=1)))  # default already enriched

    called = False

    async def fake_enrich_case(*args, **kwargs):
        nonlocal called
        called = True
        return {"threat_intel": None, "org_context": None}

    monkeypatch.setattr(scheduler_module.case_enrichment, "enrich_case", fake_enrich_case)

    asyncio.run(scheduler_module.enrich_new_cases())

    assert called is False


def test_enrich_respects_disabled_toggle(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_uninvestigated("case-1", first_seen=1)))
    scheduler_module.set_enrichment_enabled(False)

    called = False

    async def fake_enrich_case(*args, **kwargs):
        nonlocal called
        called = True
        return {"threat_intel": None, "org_context": None}

    monkeypatch.setattr(scheduler_module.case_enrichment, "enrich_case", fake_enrich_case)

    asyncio.run(scheduler_module.enrich_new_cases())

    assert called is False
    untouched = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-1"}))
    assert "enrichment" not in untouched


def test_enrich_leaves_case_unmarked_on_failure_for_retry(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_uninvestigated("case-1", first_seen=1)))

    async def failing_enrich_case(case):
        raise RuntimeError("threat intel APIs unreachable")

    monkeypatch.setattr(scheduler_module.case_enrichment, "enrich_case", failing_enrich_case)

    asyncio.run(scheduler_module.enrich_new_cases())

    untouched = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-1"}))
    assert "enrichment" not in untouched


def test_enrich_records_failure_for_debug_diagnostics(scheduler_db, monkeypatch):
    debug_state._recent_errors.clear()
    asyncio.run(scheduler_db["incidents"].insert_one(_uninvestigated("case-1", first_seen=1)))

    async def failing_enrich_case(case):
        raise RuntimeError("threat intel APIs unreachable")

    monkeypatch.setattr(scheduler_module.case_enrichment, "enrich_case", failing_enrich_case)

    asyncio.run(scheduler_module.enrich_new_cases())

    errors = debug_state.recent_errors()
    assert errors[0]["source"] == "enrich_new_cases"
    assert "case-1" in errors[0]["detail"]


def test_enrich_does_nothing_when_no_pending_cases(scheduler_db, monkeypatch):
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-done", first_seen=1)))  # already enriched

    called = False

    async def fake_enrich_case(*args, **kwargs):
        nonlocal called
        called = True
        return {"threat_intel": None, "org_context": None}

    monkeypatch.setattr(scheduler_module.case_enrichment, "enrich_case", fake_enrich_case)

    asyncio.run(scheduler_module.enrich_new_cases())

    assert called is False


# ---- check_correlator_health ----

def test_correlator_health_alerts_when_stale(scheduler_db):
    asyncio.run(scheduler_db["system_heartbeats"].insert_one({
        "_id": "correlator", "last_run": time.time() - 999, "alerts_processed_total": 10,
    }))

    # An alert only activates after ALERT_FAILURE_THRESHOLD consecutive failed checks — a single
    # stale reading is one tick, not (yet) a sustained problem.
    for _ in range(3):
        asyncio.run(scheduler_module.check_correlator_health())

    active = alerting.active_alerts()
    assert len(active) == 1
    assert active[0]["source"] == "correlator"


def test_correlator_health_alerts_on_recorded_error(scheduler_db):
    asyncio.run(scheduler_db["system_heartbeats"].insert_one({
        "_id": "correlator", "last_run": time.time(), "last_error": "Lost connection to MongoDB",
    }))

    for _ in range(3):
        asyncio.run(scheduler_module.check_correlator_health())

    active = alerting.active_alerts()
    assert len(active) == 1
    assert "Lost connection" in active[0]["message"]


def test_correlator_health_clears_alert_once_healthy_again(scheduler_db):
    asyncio.run(scheduler_db["system_heartbeats"].insert_one({"_id": "correlator", "last_run": time.time() - 999}))
    for _ in range(3):
        asyncio.run(scheduler_module.check_correlator_health())
    assert len(alerting.active_alerts()) == 1

    asyncio.run(scheduler_db["system_heartbeats"].update_one({"_id": "correlator"}, {"$set": {"last_run": time.time()}}))
    asyncio.run(scheduler_module.check_correlator_health())

    assert alerting.active_alerts() == []


def test_correlator_health_does_nothing_when_no_heartbeat_yet(scheduler_db):
    asyncio.run(scheduler_module.check_correlator_health())
    assert alerting.active_alerts() == []


# ---- check_case_aging ----

def test_case_aging_notifies_assigned_analyst_once(scheduler_db, monkeypatch):
    monkeypatch.setattr(scheduler_module, "CASE_AGING_HOURS", 1)
    old_case = _incident("case-1", first_seen=time.time() - 7200, assigned_to="eve")
    asyncio.run(scheduler_db["incidents"].insert_one(old_case))

    asyncio.run(scheduler_module.check_case_aging())

    notes = asyncio.run(notifications.list_for_user("eve", is_admin=False))
    assert len(notes) == 1
    assert notes[0]["type"] == "case_aging"

    updated = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-1"}))
    assert updated["aging_notified"] is True

    # Running again must not double-notify the same case.
    asyncio.run(scheduler_module.check_case_aging())
    notes_again = asyncio.run(notifications.list_for_user("eve", is_admin=False))
    assert len(notes_again) == 1


def test_case_aging_notifies_admins_when_unassigned(scheduler_db, monkeypatch):
    monkeypatch.setattr(scheduler_module, "CASE_AGING_HOURS", 1)
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-1", first_seen=time.time() - 7200)))

    asyncio.run(scheduler_module.check_case_aging())

    admin_notes = asyncio.run(notifications.list_for_user("admin", is_admin=True))
    assert len(admin_notes) == 1


def test_case_aging_ignores_cases_within_threshold(scheduler_db, monkeypatch):
    monkeypatch.setattr(scheduler_module, "CASE_AGING_HOURS", 48)
    asyncio.run(scheduler_db["incidents"].insert_one(_incident("case-1", first_seen=time.time() - 3600)))

    asyncio.run(scheduler_module.check_case_aging())

    updated = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-1"}))
    assert "aging_notified" not in updated


def test_case_aging_ignores_closed_cases(scheduler_db, monkeypatch):
    monkeypatch.setattr(scheduler_module, "CASE_AGING_HOURS", 1)
    asyncio.run(scheduler_db["incidents"].insert_one(
        _incident("case-1", first_seen=time.time() - 7200, case_status="closed")
    ))

    asyncio.run(scheduler_module.check_case_aging())

    updated = asyncio.run(scheduler_db["incidents"].find_one({"_id": "case-1"}))
    assert "aging_notified" not in updated

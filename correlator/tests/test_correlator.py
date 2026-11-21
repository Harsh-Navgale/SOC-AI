import os
import sys

os.environ.setdefault("MONGO_URI", "mongodb://localhost:27017")

import mongomock
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import correlator  # noqa: E402


@pytest.fixture(autouse=True)
def mock_mongo(monkeypatch):
    mock_client = mongomock.MongoClient()
    db = mock_client["soc_ai_test"]
    monkeypatch.setattr(correlator, "raw_alerts", db["raw_alerts"])
    monkeypatch.setattr(correlator, "incidents", db["incidents"])
    monkeypatch.setattr(correlator, "exclusion_rules", db["exclusion_rules"])
    monkeypatch.setattr(correlator, "heartbeats", db["system_heartbeats"])
    monkeypatch.setattr(correlator, "asset_inventory_cache", db["asset_inventory_cache"])
    monkeypatch.setattr(correlator, "system_settings", db["system_settings"])
    return db


def make_alert(_id="a1", srcip="10.0.0.5", level=5, mitre_ids=None, mitre_tactics=None, description="SSH authentication failure", timestamp=None, groups=None):
    # `srcip` sets BOTH agent.ip (what source_ip actually resolves to now) and data.srcip (kept
    # around so unique_values-related tests still have a client-address field to assert on) —
    # same value in both keeps every existing test below (written when data.srcip drove
    # grouping) still exercising the same case-grouping scenarios under the new rule.
    alert = {
        "_id": _id,
        "correlated": False,
        "data": {"srcip": srcip},
        "agent": {"ip": srcip},
        "rule": {
            "level": level,
            "description": description,
            "mitre": {"id": mitre_ids or [], "tactic": mitre_tactics or []},
            "groups": groups or [],
        },
    }
    if timestamp is not None:
        alert["timestamp"] = timestamp
    return alert


def test_extract_source_ip_uses_agent_ip():
    alert = {"agent": {"ip": "9.9.9.9"}}
    assert correlator.extract_source_ip(alert) == "9.9.9.9"


def test_extract_source_ip_ignores_data_srcip_even_when_present():
    # Grouping is always by the Wazuh agent's own IP now — a web client's address in
    # data.srcip (e.g. behind an Nginx 500) must never override it.
    alert = {"data": {"srcip": "1.2.3.4"}, "agent": {"ip": "9.9.9.9"}}
    assert correlator.extract_source_ip(alert) == "9.9.9.9"


def test_extract_source_ip_defaults_to_unknown():
    assert correlator.extract_source_ip({}) == "unknown"


def test_extract_source_ip_defaults_to_unknown_when_only_data_srcip_present():
    assert correlator.extract_source_ip({"data": {"srcip": "1.2.3.4"}}) == "unknown"


def test_process_alert_creates_new_incident(mock_mongo):
    alert = make_alert(mitre_ids=["T1110"], mitre_tactics=["credential-access"])
    mock_mongo["raw_alerts"].insert_one(alert)

    correlator.process_alert(alert)

    incident = mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"})
    assert incident is not None
    assert incident["alert_count"] == 1
    assert incident["severity"] == "low"
    assert incident["mitre_ids"] == ["T1110"]
    assert incident["is_vulnerability_alert"] is False

    stored_alert = mock_mongo["raw_alerts"].find_one({"_id": "a1"})
    assert stored_alert["correlated"] is True


# ---- Vulnerability Detection findings tagged distinctly from behavioral rule alerts ----

def test_is_vulnerability_alert_matches_substring_case_insensitive():
    assert correlator.is_vulnerability_alert({"rule": {"groups": ["Vulnerability-Detector"]}}) is True
    assert correlator.is_vulnerability_alert({"rule": {"groups": ["authentication_failed"]}}) is False
    assert correlator.is_vulnerability_alert({"rule": {}}) is False
    assert correlator.is_vulnerability_alert({}) is False


def test_process_alert_tags_vulnerability_findings_on_the_incident(mock_mongo):
    alert = make_alert(groups=["vulnerability-detector"], description="CVE-2026-12345 affects openssl")
    mock_mongo["raw_alerts"].insert_one(alert)

    correlator.process_alert(alert)

    incident = mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"})
    assert incident["is_vulnerability_alert"] is True


def test_process_alert_groups_same_source_ip_within_window(mock_mongo):
    for i in range(correlator.THRESHOLD):
        alert = make_alert(_id=f"a{i}")
        mock_mongo["raw_alerts"].insert_one(alert)
        correlator.process_alert(alert)

    incident = mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"})
    assert incident["alert_count"] == correlator.THRESHOLD
    assert incident["severity"] == "high"


# ---- grouping by (source_ip, rule), not source_ip alone ----

def test_rule_key_prefers_rule_id_over_description():
    alert = {"rule": {"id": "31151", "description": "Multiple web server 400 error codes"}}
    assert correlator.rule_key(alert) == "31151"


def test_rule_key_falls_back_to_description_when_no_id():
    alert = {"rule": {"description": "Multiple web server 400 error codes"}}
    assert correlator.rule_key(alert) == "Multiple web server 400 error codes"


def test_two_different_rules_on_the_same_ip_create_two_separate_cases(mock_mongo):
    a1 = make_alert("a1", srcip="10.0.0.5", description="Nginx 503 status code")
    a1["rule"]["id"] = "1001"
    a2 = make_alert("a2", srcip="10.0.0.5", description="SSH brute force")
    a2["rule"]["id"] = "1002"
    mock_mongo["raw_alerts"].insert_one(a1)
    mock_mongo["raw_alerts"].insert_one(a2)
    correlator.process_alert(a1)
    correlator.process_alert(a2)

    incidents = list(mock_mongo["incidents"].find({"source_ip": "10.0.0.5"}))
    assert len(incidents) == 2
    descriptions = {i["rule_description"] for i in incidents}
    assert descriptions == {"Nginx 503 status code", "SSH brute force"}


def test_repeated_alerts_for_the_same_ip_and_rule_still_merge_into_one_case(mock_mongo):
    for i in range(3):
        a = make_alert(f"a{i}", srcip="10.0.0.5", description="SSH brute force")
        a["rule"]["id"] = "1002"
        mock_mongo["raw_alerts"].insert_one(a)
        correlator.process_alert(a)

    incidents = list(mock_mongo["incidents"].find({"source_ip": "10.0.0.5"}))
    assert len(incidents) == 1
    assert incidents[0]["alert_count"] == 3


# ---- exclusion rules ----

def test_matches_criterion_contains_is_case_insensitive():
    alert = make_alert(description="Health check probe from monitoring")
    assert correlator._matches_criterion(alert, {"field": "rule.description", "operator": "contains", "value": "HEALTH CHECK"})
    assert not correlator._matches_criterion(alert, {"field": "rule.description", "operator": "contains", "value": "brute force"})


def test_matches_criterion_equals_requires_exact_match():
    alert = make_alert(srcip="10.1.2.3")
    assert correlator._matches_criterion(alert, {"field": "source_ip", "operator": "equals", "value": "10.1.2.3"})
    assert not correlator._matches_criterion(alert, {"field": "source_ip", "operator": "equals", "value": "10.1.2"})


def test_matches_criterion_against_list_field():
    alert = make_alert(mitre_tactics=["Reconnaissance", "Discovery"])
    assert correlator._matches_criterion(alert, {"field": "mitre.tactic", "operator": "contains", "value": "recon"})
    assert not correlator._matches_criterion(alert, {"field": "mitre.tactic", "operator": "contains", "value": "impact"})


def test_find_matching_exclusion_requires_all_criteria_in_a_rule():
    alert = make_alert(srcip="10.1.2.3", description="Health check")
    rules = [{
        "description": "monitoring noise",
        "criteria": [
            {"field": "source_ip", "operator": "equals", "value": "10.1.2.3"},
            {"field": "rule.description", "operator": "contains", "value": "brute force"},  # doesn't match
        ],
    }]
    assert correlator.find_matching_exclusion(alert, rules) is None


def test_find_matching_exclusion_returns_first_full_match():
    alert = make_alert(description="Health check probe")
    rules = [{"description": "ignore health checks", "criteria": [{"field": "rule.description", "operator": "contains", "value": "health check"}]}]
    assert correlator.find_matching_exclusion(alert, rules) == "ignore health checks"


def test_run_once_marks_excluded_alerts_without_creating_an_incident(mock_mongo):
    mock_mongo["exclusion_rules"].insert_one({
        "_id": "r1", "active": True, "description": "ignore health checks",
        "criteria": [{"field": "rule.description", "operator": "contains", "value": "health check"}],
    })
    excluded_alert = make_alert("a1", srcip="10.9.9.9", description="Health check probe")
    normal_alert = make_alert("a2", srcip="10.0.0.5", description="SSH authentication failure")
    mock_mongo["raw_alerts"].insert_one(excluded_alert)
    mock_mongo["raw_alerts"].insert_one(normal_alert)

    processed = correlator.run_once()
    assert processed == 2

    stored_excluded = mock_mongo["raw_alerts"].find_one({"_id": "a1"})
    assert stored_excluded["correlated"] is True
    assert stored_excluded["excluded"] is True
    assert stored_excluded["excluded_by_rule"] == "ignore health checks"
    assert mock_mongo["incidents"].find_one({"source_ip": excluded_alert["data"]["srcip"]}) is None

    stored_normal = mock_mongo["raw_alerts"].find_one({"_id": "a2"})
    assert stored_normal.get("excluded") is not True
    assert mock_mongo["incidents"].find_one({"source_ip": normal_alert["data"]["srcip"]}) is not None


def test_run_once_ignores_inactive_exclusion_rules(mock_mongo):
    mock_mongo["exclusion_rules"].insert_one({
        "_id": "r1", "active": False, "description": "ignore health checks",
        "criteria": [{"field": "rule.description", "operator": "contains", "value": "health check"}],
    })
    alert = make_alert("a1", description="Health check probe")
    mock_mongo["raw_alerts"].insert_one(alert)

    correlator.run_once()

    stored = mock_mongo["raw_alerts"].find_one({"_id": "a1"})
    assert stored.get("excluded") is not True
    assert mock_mongo["incidents"].find_one({"source_ip": alert["data"]["srcip"]}) is not None


# ---- alert-time-based windowing (vs. wall-clock processing time) ----

def test_alert_time_uses_the_alerts_own_timestamp():
    from datetime import datetime, timezone
    alert = make_alert(timestamp="2026-04-29T15:07:28.120+0530")
    fallback = datetime.now(timezone.utc)
    result = correlator._alert_time(alert, fallback)
    assert result.year == 2026 and result.month == 4 and result.day == 29
    assert result != fallback


def test_alert_time_falls_back_when_timestamp_missing():
    from datetime import datetime, timezone
    fallback = datetime(2026, 1, 1, tzinfo=timezone.utc)
    alert = make_alert()  # no timestamp
    assert correlator._alert_time(alert, fallback) == fallback


def test_alert_time_falls_back_on_unparseable_timestamp():
    from datetime import datetime, timezone
    fallback = datetime(2026, 1, 1, tzinfo=timezone.utc)
    alert = make_alert(timestamp="not-a-real-timestamp")
    assert correlator._alert_time(alert, fallback) == fallback


def test_historical_alerts_close_together_merge_using_their_own_time_not_upload_time(mock_mongo):
    # Two alerts genuinely 3 minutes apart back in April, uploaded/processed together today.
    a1 = make_alert("a1", timestamp="2026-04-29T15:07:00.000+0000")
    a2 = make_alert("a2", timestamp="2026-04-29T15:10:00.000+0000")
    mock_mongo["raw_alerts"].insert_one(a1)
    mock_mongo["raw_alerts"].insert_one(a2)
    correlator.process_alert(a1)
    correlator.process_alert(a2)

    incidents = list(mock_mongo["incidents"].find({"source_ip": "10.0.0.5"}))
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["alert_count"] == 2
    # first/last seen reflect the alerts' OWN historical time, not today's processing time.
    assert incident["first_seen_iso"].startswith("2026-04-29")
    assert incident["last_seen_iso"].startswith("2026-04-29")


def test_historical_alerts_months_apart_do_not_merge_even_when_uploaded_together(mock_mongo):
    # Same source IP, but the two real-world incidents are months apart — uploading both in one
    # batch (so both get *processed* within the same second) must not merge them into one case.
    a1 = make_alert("a1", timestamp="2026-04-29T15:07:00.000+0000")
    a2 = make_alert("a2", timestamp="2026-07-15T09:00:00.000+0000")
    mock_mongo["raw_alerts"].insert_one(a1)
    mock_mongo["raw_alerts"].insert_one(a2)
    correlator.process_alert(a1)
    correlator.process_alert(a2)

    incidents = list(mock_mongo["incidents"].find({"source_ip": "10.0.0.5"}))
    assert len(incidents) == 2


def test_out_of_order_historical_alerts_never_move_last_seen_backward(mock_mongo):
    # The later alert (in real time) is processed FIRST, then an earlier one arrives second.
    later = make_alert("a1", timestamp="2026-04-29T15:10:00.000+0000")
    earlier = make_alert("a2", timestamp="2026-04-29T15:07:00.000+0000")
    mock_mongo["raw_alerts"].insert_one(later)
    mock_mongo["raw_alerts"].insert_one(earlier)
    correlator.process_alert(later)
    correlator.process_alert(earlier)

    incident = mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"})
    assert incident["alert_count"] == 2
    assert incident["last_seen_iso"].startswith("2026-04-29T15:10")


def test_historical_alerts_months_apart_do_not_merge_regardless_of_processing_order(mock_mongo):
    # Same scenario as the forward-order test above, but processed in reverse (the later,
    # July alert arrives first) — a one-sided ">=" window check would let the July incident
    # wrongly swallow the April alert, since "July's last_seen >= April - window" is trivially
    # true. The window must be symmetric so processing order never matters.
    july = make_alert("july", timestamp="2026-07-15T09:00:00.000+0000")
    april = make_alert("april", timestamp="2026-04-29T15:07:00.000+0000")
    mock_mongo["raw_alerts"].insert_one(july)
    mock_mongo["raw_alerts"].insert_one(april)
    correlator.process_alert(july)
    correlator.process_alert(april)

    incidents = list(mock_mongo["incidents"].find({"source_ip": "10.0.0.5"}))
    assert len(incidents) == 2


def test_out_of_order_historical_alerts_never_move_first_seen_forward(mock_mongo):
    # The later alert is processed first (creating the incident), then an earlier one folds
    # in — first_seen must move back to the earlier time, not stay at the later one.
    later = make_alert("a1", timestamp="2026-04-29T15:10:00.000+0000")
    earlier = make_alert("a2", timestamp="2026-04-29T15:07:00.000+0000")
    mock_mongo["raw_alerts"].insert_one(later)
    mock_mongo["raw_alerts"].insert_one(earlier)
    correlator.process_alert(later)
    correlator.process_alert(earlier)

    incident = mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"})
    assert incident["alert_count"] == 2
    assert incident["first_seen_iso"].startswith("2026-04-29T15:07")


# ---- asset enrichment from the backend's S3 inventory cache ----

def test_process_alert_attaches_cached_asset_on_new_incident(mock_mongo):
    mock_mongo["asset_inventory_cache"].insert_one({
        "_id": "10.0.0.5", "hostname": "db-02", "raw": {"env": "prod"},
    })
    alert = make_alert()
    mock_mongo["raw_alerts"].insert_one(alert)

    correlator.process_alert(alert)

    incident = mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"})
    assert incident["asset"] == {"hostname": "db-02", "raw": {"env": "prod"}}


def test_process_alert_sets_asset_none_when_ip_not_cached(mock_mongo):
    alert = make_alert()
    mock_mongo["raw_alerts"].insert_one(alert)

    correlator.process_alert(alert)

    incident = mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"})
    assert incident["asset"] is None


def test_process_alert_refreshes_asset_on_fold_in(mock_mongo):
    a1 = make_alert("a1")
    mock_mongo["raw_alerts"].insert_one(a1)
    correlator.process_alert(a1)

    incident = mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"})
    assert incident["asset"] is None

    # Cache gets populated after the case already exists — the next alert folding into the
    # same case should pick up the now-cached asset, not stay stuck at the earlier None.
    mock_mongo["asset_inventory_cache"].insert_one({
        "_id": "10.0.0.5", "hostname": "db-02", "raw": {},
    })
    a2 = make_alert("a2")
    mock_mongo["raw_alerts"].insert_one(a2)
    correlator.process_alert(a2)

    incident = mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"})
    assert incident["asset"]["hostname"] == "db-02"


# ---- unique_values: every distinct value seen across all alerts folded into a case ----

def test_flatten_alert_values_extracts_nested_scalars_by_dotted_path():
    alert = {
        "_id": "a1",
        "correlated": False,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "data": {"srcip": "10.0.0.5", "srcport": 51820, "srcuser": "root"},
        "agent": {"id": "001", "name": "web01"},
        "rule": {"level": 7, "description": "SSH brute force"},
        "full_log": "Jan 1 00:00:00 sshd: Failed password for root",
    }

    values = correlator.flatten_alert_values(alert)

    assert values["data.srcip"] == {"10.0.0.5"}
    assert values["data.srcport"] == {"51820"}
    assert values["data.srcuser"] == {"root"}
    assert values["agent.name"] == {"web01"}
    assert values["rule.description"] == {"SSH brute force"}
    assert values["full_log"] == {"Jan 1 00:00:00 sshd: Failed password for root"}


def test_flatten_alert_values_excludes_per_alert_identifier_fields():
    alert = {"_id": "a1", "correlated": False, "timestamp": "2026-01-01T00:00:00+00:00", "data": {"srcip": "10.0.0.5"}}
    values = correlator.flatten_alert_values(alert)
    assert "_id" not in values
    assert "correlated" not in values
    assert "timestamp" not in values


def test_flatten_alert_values_walks_lists_of_scalars_and_dicts():
    alert = {"rule": {"groups": ["authentication_failed", "syslog"]}, "related": [{"id": "1"}, {"id": "2"}]}
    values = correlator.flatten_alert_values(alert)
    assert values["rule.groups"] == {"authentication_failed", "syslog"}
    assert values["related.id"] == {"1", "2"}


def test_flatten_alert_values_skips_none_and_empty_string():
    alert = {"data": {"dstuser": None, "url": ""}}
    values = correlator.flatten_alert_values(alert)
    assert values == {}


def test_merge_unique_values_accumulates_across_calls_without_duplicating():
    merged = correlator.merge_unique_values(None, {"data.srcport": {"1"}})
    merged = correlator.merge_unique_values(merged, {"data.srcport": {"2"}})
    merged = correlator.merge_unique_values(merged, {"data.srcport": {"1"}})  # repeat, not a dup
    assert merged["data.srcport"] == ["1", "2"]


def test_merge_unique_values_caps_general_fields_at_fifty():
    values = {"data.srcport": {str(i) for i in range(60)}}
    merged = correlator.merge_unique_values(None, values)
    assert len(merged["data.srcport"]) == 50


def test_merge_unique_values_caps_full_log_tighter_at_ten():
    values = {"full_log": {f"log line {i}" for i in range(20)}}
    merged = correlator.merge_unique_values(None, values)
    assert len(merged["full_log"]) == 10


def test_process_alert_stores_unique_values_on_new_incident(mock_mongo):
    alert = make_alert(srcip="10.0.0.5")
    alert["data"]["srcport"] = 51820
    mock_mongo["raw_alerts"].insert_one(alert)

    correlator.process_alert(alert)

    incident = mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"})
    assert incident["unique_values"]["data.srcport"] == ["51820"]


def test_process_alert_merges_unique_values_across_folded_alerts(mock_mongo):
    a1 = make_alert("a1", srcip="10.0.0.5")
    a1["data"]["srcport"] = 51820
    a2 = make_alert("a2", srcip="10.0.0.5")
    a2["data"]["srcport"] = 51821
    mock_mongo["raw_alerts"].insert_one(a1)
    mock_mongo["raw_alerts"].insert_one(a2)

    correlator.process_alert(a1)
    correlator.process_alert(a2)

    incident = mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"})
    assert incident["unique_values"]["data.srcport"] == ["51820", "51821"]


# ---- case-correlation pause (set by the backend via /api/settings/case-correlation) ----

def test_run_once_skips_processing_when_correlation_paused(mock_mongo):
    mock_mongo["system_settings"].insert_one({"_id": "case_correlation", "paused": True})
    alert = make_alert()
    mock_mongo["raw_alerts"].insert_one(alert)

    processed = correlator.run_once()

    assert processed == 0
    stored = mock_mongo["raw_alerts"].find_one({"_id": "a1"})
    assert stored["correlated"] is False
    assert mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"}) is None


def test_run_once_processes_normally_when_not_paused(mock_mongo):
    mock_mongo["system_settings"].insert_one({"_id": "case_correlation", "paused": False})
    alert = make_alert()
    mock_mongo["raw_alerts"].insert_one(alert)

    processed = correlator.run_once()

    assert processed == 1
    assert mock_mongo["incidents"].find_one({"source_ip": "10.0.0.5"}) is not None


def test_run_once_processes_normally_with_no_setting_document_at_all(mock_mongo):
    # Default state before any admin has ever touched the toggle — no document exists yet.
    alert = make_alert()
    mock_mongo["raw_alerts"].insert_one(alert)

    processed = correlator.run_once()

    assert processed == 1


def test_write_heartbeat_records_last_error(mock_mongo):
    correlator.write_heartbeat(0, error="ServerSelectionTimeoutError: boom")

    hb = mock_mongo["system_heartbeats"].find_one({"_id": "correlator"})
    assert hb["last_error"] == "ServerSelectionTimeoutError: boom"
    assert "last_error_at" in hb


def test_write_heartbeat_clears_last_error_on_success(mock_mongo):
    correlator.write_heartbeat(0, error="boom")
    correlator.write_heartbeat(5)

    hb = mock_mongo["system_heartbeats"].find_one({"_id": "correlator"})
    assert "last_error" not in hb
    assert "last_error_at" not in hb
    assert hb["alerts_processed_total"] == 5

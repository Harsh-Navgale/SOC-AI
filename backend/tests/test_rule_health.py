import asyncio

import pytest

from app import rule_health


async def _list_notifications(mock_db):
    return [n async for n in mock_db["notifications"].find()]


def test_get_rule_health_summary_aggregates_confirmed_dispositions_by_rule(mock_db):
    asyncio.run(mock_db["incidents"].insert_many([
        {"_id": "1", "rule_key": "r1", "rule_description": "Multiple failed logins",
         "case_status": "closed", "disposition": "false_positive",
         "investigation": {"rule_health": "likely_miscalibrated"}},
        {"_id": "2", "rule_key": "r1", "rule_description": "Multiple failed logins",
         "case_status": "closed", "disposition": "true_positive",
         "investigation": {"rule_health": "appears_sound"}},
        {"_id": "3", "rule_key": "r2", "rule_description": "Port scan detected",
         "case_status": "open"},  # not closed yet — must not be counted
        {"_id": "4", "rule_key": "r3", "rule_description": "Unrelated rule",
         "case_status": "closed"},  # closed but no confirmed disposition — must not be counted
        {"_id": "5", "rule_key": "r1", "rule_description": "Multiple failed logins",
         "case_status": "closed", "disposition": "benign_positive",
         "investigation": {"verdict": "benign_positive"}},  # pre-dates the rule_health field entirely
    ]))

    result = asyncio.run(rule_health.get_rule_health_summary())

    assert len(result) == 1
    row = result[0]
    assert row["_id"] == "r1"
    assert row["rule_description"] == "Multiple failed logins"
    assert row["confirmed_total"] == 3
    assert row["confirmed_false_positive"] == 1
    assert row["confirmed_true_positive"] == 1
    assert row["confirmed_benign_positive"] == 1
    assert row["confirmed_fp_rate"] == pytest.approx(1 / 3)
    # The AI's own unconfirmed opinion stays in separately-named fields, never mixed into the
    # confirmed_* counts above — and doc "5" (an investigation that pre-dates this field, so
    # `investigation.rule_health` is genuinely missing, not null) must NOT be counted as "has an
    # opinion" just because MongoDB's $ne treats missing the same as null.
    assert row["ai_flagged_miscalibrated"] == 1
    assert row["ai_rule_health_total"] == 2


def test_get_rule_health_summary_excludes_vulnerability_detection_findings(mock_db):
    asyncio.run(mock_db["incidents"].insert_many([
        {"_id": "1", "rule_key": "100", "rule_description": "CVE-2026-1 affects openssl",
         "case_status": "closed", "disposition": "false_positive", "is_vulnerability_alert": True},
        {"_id": "2", "rule_key": "r1", "rule_description": "Multiple failed logins",
         "case_status": "closed", "disposition": "false_positive", "is_vulnerability_alert": False},
    ]))

    result = asyncio.run(rule_health.get_rule_health_summary())

    assert len(result) == 1
    assert result[0]["_id"] == "r1"


def test_get_rule_health_summary_is_empty_with_no_confirmed_closures(mock_db):
    asyncio.run(mock_db["incidents"].insert_one(
        {"_id": "1", "rule_key": "r1", "case_status": "open"},
    ))

    assert asyncio.run(rule_health.get_rule_health_summary()) == []


def test_check_fp_threshold_does_nothing_below_the_threshold(mock_db):
    asyncio.run(mock_db["incidents"].insert_many([
        {"_id": "1", "rule_key": "r1", "case_status": "closed", "disposition": "false_positive"},
        {"_id": "2", "rule_key": "r1", "case_status": "closed", "disposition": "false_positive"},
    ]))

    notified = asyncio.run(rule_health.check_fp_threshold("r1", "Multiple failed logins", "1"))

    assert notified is False
    assert asyncio.run(mock_db["notifications"].count_documents({})) == 0


def test_check_fp_threshold_notifies_once_the_threshold_is_crossed(mock_db):
    asyncio.run(mock_db["incidents"].insert_many([
        {"_id": str(i), "rule_key": "r1", "case_status": "closed", "disposition": "false_positive"}
        for i in range(3)
    ]))

    notified = asyncio.run(rule_health.check_fp_threshold("r1", "Multiple failed logins", "0"))

    assert notified is True
    created = asyncio.run(_list_notifications(mock_db))
    assert len(created) == 1
    assert created[0]["type"] == "rule_fp_threshold"
    assert created[0]["user"] is None
    assert "Multiple failed logins" in created[0]["message"]


def test_check_fp_threshold_does_not_renotify_once_already_flagged(mock_db):
    asyncio.run(mock_db["incidents"].insert_many([
        {"_id": str(i), "rule_key": "r1", "case_status": "closed", "disposition": "false_positive"}
        for i in range(5)
    ]))

    first = asyncio.run(rule_health.check_fp_threshold("r1", "Multiple failed logins", "0"))
    second = asyncio.run(rule_health.check_fp_threshold("r1", "Multiple failed logins", "0"))

    assert first is True
    assert second is False
    assert asyncio.run(mock_db["notifications"].count_documents({})) == 1


def test_check_fp_threshold_is_a_noop_without_a_rule_key(mock_db):
    notified = asyncio.run(rule_health.check_fp_threshold(None, "desc", "1"))

    assert notified is False
    assert asyncio.run(mock_db["notifications"].count_documents({})) == 0

import asyncio
import time

from mongomock_motor import AsyncMongoMockClient

from app import campaign_correlation


def _db(monkeypatch):
    mock_client = AsyncMongoMockClient()
    db = mock_client["soc_ai_campaign_correlation_test"]
    monkeypatch.setattr(campaign_correlation, "incidents", db["incidents"])
    return db["incidents"]


def _incident(incident_id, source_ip, rule_key, mitre_tactics=None, first_seen=None, last_seen=None, case_status="open"):
    now = time.time()
    return {
        "_id": incident_id, "source_ip": source_ip, "rule_key": rule_key,
        "mitre_tactics": mitre_tactics or [], "case_status": case_status,
        "first_seen": first_seen if first_seen is not None else now,
        "last_seen": last_seen if last_seen is not None else now,
    }


def test_groups_incidents_sharing_a_rule_key_across_different_ips(monkeypatch):
    db = _db(monkeypatch)
    asyncio.run(db.insert_one(_incident("inc-1", "10.0.0.1", "5712")))
    asyncio.run(db.insert_one(_incident("inc-2", "10.0.0.2", "5712")))

    updated = asyncio.run(campaign_correlation.correlate_campaigns())

    assert updated == 2
    doc1 = asyncio.run(db.find_one({"_id": "inc-1"}))
    doc2 = asyncio.run(db.find_one({"_id": "inc-2"}))
    assert doc1["campaign_id"] == doc2["campaign_id"]


def test_does_not_group_incidents_from_the_same_source_ip(monkeypatch):
    db = _db(monkeypatch)
    asyncio.run(db.insert_one(_incident("inc-1", "10.0.0.1", "5712")))
    asyncio.run(db.insert_one(_incident("inc-2", "10.0.0.1", "5712")))  # same IP — already one correlator incident

    updated = asyncio.run(campaign_correlation.correlate_campaigns())

    assert updated == 0


def test_does_not_group_unrelated_incidents(monkeypatch):
    db = _db(monkeypatch)
    asyncio.run(db.insert_one(_incident("inc-1", "10.0.0.1", "5712")))
    asyncio.run(db.insert_one(_incident("inc-2", "10.0.0.2", "9999")))  # different rule, no shared tactic

    updated = asyncio.run(campaign_correlation.correlate_campaigns())

    assert updated == 0
    doc1 = asyncio.run(db.find_one({"_id": "inc-1"}))
    assert "campaign_id" not in doc1


def test_groups_incidents_sharing_a_mitre_tactic_even_with_different_rules(monkeypatch):
    db = _db(monkeypatch)
    asyncio.run(db.insert_one(_incident("inc-1", "10.0.0.1", "100100", mitre_tactics=["reconnaissance"])))
    asyncio.run(db.insert_one(_incident("inc-2", "10.0.0.2", "100200", mitre_tactics=["reconnaissance", "initial-access"])))

    updated = asyncio.run(campaign_correlation.correlate_campaigns())

    assert updated == 2


def test_does_not_group_incidents_outside_the_time_window(monkeypatch):
    db = _db(monkeypatch)
    now = time.time()
    asyncio.run(db.insert_one(_incident("inc-1", "10.0.0.1", "5712", first_seen=now, last_seen=now)))
    asyncio.run(db.insert_one(_incident("inc-2", "10.0.0.2", "5712", first_seen=now - 7200, last_seen=now - 7200)))  # 2h earlier

    updated = asyncio.run(campaign_correlation.correlate_campaigns(window_seconds=3600))

    assert updated == 0


def test_transitive_grouping_across_three_incidents(monkeypatch):
    # inc-1 shares a rule with inc-2; inc-2 shares a (different) rule with inc-3; inc-1 and
    # inc-3 share nothing directly — all three must still end up in one campaign.
    db = _db(monkeypatch)
    asyncio.run(db.insert_one(_incident("inc-1", "10.0.0.1", "5712")))
    asyncio.run(db.insert_one(_incident("inc-2", "10.0.0.2", "5712", mitre_tactics=["lateral-movement"])))
    asyncio.run(db.insert_one(_incident("inc-3", "10.0.0.3", "9999", mitre_tactics=["lateral-movement"])))

    asyncio.run(campaign_correlation.correlate_campaigns())

    docs = {d["_id"]: d for d in [asyncio.run(db.find_one({"_id": i})) for i in ("inc-1", "inc-2", "inc-3")]}
    assert docs["inc-1"]["campaign_id"] == docs["inc-2"]["campaign_id"] == docs["inc-3"]["campaign_id"]


def test_ignores_closed_incidents(monkeypatch):
    db = _db(monkeypatch)
    asyncio.run(db.insert_one(_incident("inc-1", "10.0.0.1", "5712")))
    asyncio.run(db.insert_one(_incident("inc-2", "10.0.0.2", "5712", case_status="closed")))

    updated = asyncio.run(campaign_correlation.correlate_campaigns())

    assert updated == 0


def test_rerunning_is_idempotent(monkeypatch):
    db = _db(monkeypatch)
    asyncio.run(db.insert_one(_incident("inc-1", "10.0.0.1", "5712")))
    asyncio.run(db.insert_one(_incident("inc-2", "10.0.0.2", "5712")))

    first = asyncio.run(campaign_correlation.correlate_campaigns())
    second = asyncio.run(campaign_correlation.correlate_campaigns())

    assert first == 2
    assert second == 0  # already tagged — nothing new to update

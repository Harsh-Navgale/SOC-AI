import asyncio

from mongomock_motor import AsyncMongoMockClient

from app import eval_harness


def _db(monkeypatch):
    mock_client = AsyncMongoMockClient()
    db = mock_client["soc_ai_eval_harness_test"]
    monkeypatch.setattr(eval_harness, "incidents", db["incidents"])
    monkeypatch.setattr(eval_harness, "eval_reports", db["eval_reports"])
    return db


def _closed_incident(incident_id, disposition, **overrides):
    doc = {
        "_id": incident_id, "source_ip": "1.2.3.4", "rule_description": "test rule",
        "alert_count": 1, "max_level": 5, "mitre_tactics": [],
        "case_status": "closed", "disposition": disposition,
    }
    doc.update(overrides)
    return doc


def test_run_eval_excludes_the_incidents_own_precedent(monkeypatch):
    db = _db(monkeypatch)
    asyncio.run(db["incidents"].insert_one(_closed_incident("case-1", "false_positive")))
    captured = {}

    async def fake_investigate(incident, **kwargs):
        captured["exclude_precedent_source"] = kwargs.get("exclude_precedent_source")
        return {"verdict": "false_positive"}

    monkeypatch.setattr(eval_harness, "investigate_incident", fake_investigate)

    asyncio.run(eval_harness.run_eval(1))

    assert captured["exclude_precedent_source"] == "case-case-1"


def test_run_eval_only_samples_closed_incidents_with_a_disposition(monkeypatch):
    db = _db(monkeypatch)
    asyncio.run(db["incidents"].insert_one(_closed_incident("case-1", "false_positive")))
    asyncio.run(db["incidents"].insert_one({**_closed_incident("case-2", "false_positive"), "case_status": "open"}))
    asyncio.run(db["incidents"].insert_one({
        "_id": "case-3", "source_ip": "1.2.3.4", "rule_description": "x", "alert_count": 1,
        "max_level": 5, "mitre_tactics": [], "case_status": "closed",  # no disposition at all
    }))
    called_ids = []

    async def fake_investigate(incident, **kwargs):
        called_ids.append(incident["_id"])
        return {"verdict": "false_positive"}

    monkeypatch.setattr(eval_harness, "investigate_incident", fake_investigate)

    asyncio.run(eval_harness.run_eval(10))

    assert called_ids == ["case-1"]


def test_run_eval_builds_the_confusion_matrix_and_agreement_rate(monkeypatch):
    db = _db(monkeypatch)
    asyncio.run(db["incidents"].insert_one(_closed_incident("case-1", "false_positive")))
    asyncio.run(db["incidents"].insert_one(_closed_incident("case-2", "true_positive")))

    verdicts = {"case-1": "false_positive", "case-2": "benign_positive"}  # one agrees, one doesn't

    async def fake_investigate(incident, **kwargs):
        return {"verdict": verdicts[incident["_id"]]}

    monkeypatch.setattr(eval_harness, "investigate_incident", fake_investigate)

    asyncio.run(eval_harness.run_eval(2))

    report = asyncio.run(eval_harness.get_latest_report())
    assert report["status"] == "done"
    assert report["sample_size_scored"] == 2
    assert report["agreement_rate"] == 0.5
    assert report["confusion_matrix"]["false_positive"]["false_positive"] == 1
    assert report["confusion_matrix"]["true_positive"]["benign_positive"] == 1


def test_run_eval_counts_a_failed_investigation_as_an_error_not_a_crash(monkeypatch):
    db = _db(monkeypatch)
    asyncio.run(db["incidents"].insert_one(_closed_incident("case-1", "false_positive")))
    asyncio.run(db["incidents"].insert_one(_closed_incident("case-2", "true_positive")))

    async def fake_investigate(incident, **kwargs):
        if incident["_id"] == "case-1":
            raise RuntimeError("AI unavailable")
        return {"verdict": "true_positive"}

    monkeypatch.setattr(eval_harness, "investigate_incident", fake_investigate)

    asyncio.run(eval_harness.run_eval(2))

    report = asyncio.run(eval_harness.get_latest_report())
    assert report["status"] == "done"
    assert report["errors"] == 1
    assert report["sample_size_scored"] == 1
    assert report["agreement_rate"] == 1.0


def test_run_eval_treats_an_unparsed_verdict_as_disagreement_not_a_crash(monkeypatch):
    db = _db(monkeypatch)
    asyncio.run(db["incidents"].insert_one(_closed_incident("case-1", "false_positive")))

    async def fake_investigate(incident, **kwargs):
        return {"verdict": None}  # the model didn't follow the format

    monkeypatch.setattr(eval_harness, "investigate_incident", fake_investigate)

    asyncio.run(eval_harness.run_eval(1))

    report = asyncio.run(eval_harness.get_latest_report())
    assert report["agreement_rate"] == 0.0
    assert report["confusion_matrix"]["false_positive"]["unparsed"] == 1


def test_get_latest_report_returns_none_when_no_run_has_ever_happened(monkeypatch):
    _db(monkeypatch)
    assert asyncio.run(eval_harness.get_latest_report()) is None

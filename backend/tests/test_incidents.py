import asyncio


def _login(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    return resp.json()["access_token"]


def _seed_incident(mock_db, incident_id="inc-1", **overrides):
    doc = {
        "_id": incident_id,
        "source_ip": "10.0.0.5",
        "case_status": "open",
        "assigned_to": None,
        "notes": [],
        "severity": "low",
        "alert_count": 1,
        "max_level": 5,
        "mitre_ids": [],
        "mitre_tactics": [],
        "rule_description": "test rule",
        "last_seen": 0,
    }
    doc.update(overrides)
    asyncio.run(mock_db["incidents"].insert_one(doc))


def test_update_incident_status(client, mock_db):
    _seed_incident(mock_db)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.patch("/api/incidents/inc-1", json={"case_status": "investigating"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["case_status"] == "investigating"


def test_list_and_get_incident_include_risk_score(client, mock_db):
    _seed_incident(mock_db, "inc-1", severity="high", alert_count=10, max_level=12)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    listed = client.get("/api/incidents", headers=headers).json()
    assert listed["total"] == 1
    assert listed["items"][0]["risk"]["label"] in ("low", "medium", "high", "critical")
    assert isinstance(listed["items"][0]["risk"]["score"], int)

    detail = client.get("/api/incidents/inc-1", headers=headers).json()
    assert detail["risk"]["score"] == listed["items"][0]["risk"]["score"]

    patched = client.patch("/api/incidents/inc-1", json={"case_status": "investigating"}, headers=headers).json()
    assert "risk" in patched


def test_update_incident_not_found(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.patch("/api/incidents/does-not-exist", json={"case_status": "investigating"}, headers=headers)
    assert resp.status_code == 404


def test_add_note(client, mock_db):
    _seed_incident(mock_db)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/incidents/inc-1/notes", json={"text": "looks like a scanner"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["author"] == "admin"

    detail = client.get("/api/incidents/inc-1", headers=headers)
    assert len(detail.json()["notes"]) == 1


def test_close_incident_embeds_resolution(client, mock_db, monkeypatch):
    _seed_incident(mock_db)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    embedded = {}

    async def fake_embed_case_resolution(incident, resolution, disposition):
        embedded["incident_id"] = incident["_id"]
        embedded["resolution"] = resolution
        embedded["disposition"] = disposition

    monkeypatch.setattr("app.main.embed_case_resolution", fake_embed_case_resolution)

    resp = client.post(
        "/api/incidents/inc-1/close",
        json={"resolution": "confirmed false positive, blocked at firewall anyway", "disposition": "false_positive"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["knowledge_embedded"] is True
    assert embedded["incident_id"] == "inc-1"
    assert embedded["disposition"] == "false_positive"

    detail = client.get("/api/incidents/inc-1", headers=headers)
    assert detail.json()["case_status"] == "closed"


def test_list_incidents_filters_by_severity(client, mock_db):
    _seed_incident(mock_db, "inc-1", severity="high", source_ip="10.0.0.5")
    _seed_incident(mock_db, "inc-2", severity="low", source_ip="10.0.0.6")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/incidents?severity=high", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    ids = [inc["_id"] for inc in body["items"]]
    assert ids == ["inc-1"]


def test_list_incidents_filters_by_case_status(client, mock_db):
    _seed_incident(mock_db, "inc-1", case_status="open")
    _seed_incident(mock_db, "inc-2", case_status="closed")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/incidents?case_status=closed", headers=headers)
    assert resp.status_code == 200
    ids = [inc["_id"] for inc in resp.json()["items"]]
    assert ids == ["inc-2"]


def test_list_incidents_search_matches_source_ip_or_rule(client, mock_db):
    _seed_incident(mock_db, "inc-1", source_ip="203.0.113.9", rule_description="SSH brute force")
    _seed_incident(mock_db, "inc-2", source_ip="10.0.0.6", rule_description="Port scan detected")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    by_ip = client.get("/api/incidents?search=203.0.113", headers=headers)
    assert [inc["_id"] for inc in by_ip.json()["items"]] == ["inc-1"]

    by_rule = client.get("/api/incidents?search=brute", headers=headers)
    assert [inc["_id"] for inc in by_rule.json()["items"]] == ["inc-1"]


def test_list_incidents_search_is_case_insensitive_and_combines_with_filters(client, mock_db):
    _seed_incident(mock_db, "inc-1", severity="high", source_ip="10.0.0.5", rule_description="Malware detected")
    _seed_incident(mock_db, "inc-2", severity="low", source_ip="10.0.0.5", rule_description="Malware detected")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/incidents?search=MALWARE&severity=high", headers=headers)
    assert [inc["_id"] for inc in resp.json()["items"]] == ["inc-1"]


def test_list_incidents_pagination(client, mock_db):
    for i in range(5):
        _seed_incident(mock_db, f"inc-{i}", last_seen=i)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    page1 = client.get("/api/incidents?limit=2&skip=0", headers=headers).json()
    assert page1["total"] == 5
    assert len(page1["items"]) == 2
    assert page1["items"][0]["_id"] == "inc-4"  # sorted by last_seen desc

    page2 = client.get("/api/incidents?limit=2&skip=2", headers=headers).json()
    assert len(page2["items"]) == 2
    assert {i["_id"] for i in page1["items"]}.isdisjoint({i["_id"] for i in page2["items"]})


def test_related_incidents_matches_same_source_ip(client, mock_db):
    _seed_incident(mock_db, "inc-1", source_ip="10.0.0.5", case_status="open")
    _seed_incident(mock_db, "inc-2", source_ip="10.0.0.5", case_status="closed", resolution="false positive")
    _seed_incident(mock_db, "inc-3", source_ip="10.0.0.9", case_status="open")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/incidents/inc-1/related", headers=headers)
    assert resp.status_code == 200
    ids = [inc["_id"] for inc in resp.json()]
    assert ids == ["inc-2"]
    assert resp.json()[0]["resolution"] == "false positive"


def test_related_incidents_not_found(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/incidents/does-not-exist/related", headers=headers)
    assert resp.status_code == 404


def test_investigate_passes_threat_intel_to_report(client, mock_db, monkeypatch):
    _seed_incident(mock_db, "inc-1", source_ip="203.0.113.9")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    captured = {}

    async def fake_lookup_all(indicator):
        captured["indicator"] = indicator
        return {"indicator": indicator, "indicator_type": "ip", "sources": {}}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None):
        captured["threat_intel"] = threat_intel
        captured["asset"] = asset
        captured["risk"] = risk
        return {"raw": "ok", "severity": "high", "confidence": "high", "impact": "x",
                "priority": "high", "summary": "x", "actions": [], "generated_at": "now"}

    monkeypatch.setattr("app.main.threat_intel.lookup_all", fake_lookup_all)
    monkeypatch.setattr("app.main.investigate_incident", fake_investigate_incident)

    resp = client.post("/api/incidents/inc-1/investigate", headers=headers)
    assert resp.status_code == 200
    assert captured["indicator"] == "203.0.113.9"
    assert captured["threat_intel"]["indicator"] == "203.0.113.9"


def test_investigate_checks_the_single_external_srcip_not_the_agent_ip(client, mock_db, monkeypatch):
    # source_ip is the Wazuh agent's own IP (correlator.py groups by agent.ip only) — threat
    # intel should check the actual external caller captured in unique_values instead.
    _seed_incident(mock_db, "inc-1", source_ip="10.29.12.215", unique_values={"data.srcip": ["198.51.100.7"]})
    headers = {"Authorization": f"Bearer {_login(client)}"}

    captured = {}

    async def fake_lookup_all(indicator):
        captured["indicator"] = indicator
        return {"indicator": indicator, "indicator_type": "ip", "sources": {}}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None):
        return {"raw": "ok", "severity": "high", "confidence": "high", "impact": "x",
                "priority": "high", "summary": "x", "actions": [], "generated_at": "now"}

    monkeypatch.setattr("app.main.threat_intel.lookup_all", fake_lookup_all)
    monkeypatch.setattr("app.main.investigate_incident", fake_investigate_incident)

    resp = client.post("/api/incidents/inc-1/investigate", headers=headers)
    assert resp.status_code == 200
    assert captured["indicator"] == "198.51.100.7"


def test_get_incident_exposes_threat_intel_ip(client, mock_db):
    _seed_incident(mock_db, "inc-1", source_ip="10.29.12.215", unique_values={"data.srcip": ["198.51.100.7"]})
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/incidents/inc-1", headers=headers)
    assert resp.json()["threat_intel_ip"] == "198.51.100.7"


def test_get_incident_threat_intel_ip_falls_back_to_source_ip(client, mock_db):
    _seed_incident(mock_db, "inc-1", source_ip="10.29.12.215")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/incidents/inc-1", headers=headers)
    assert resp.json()["threat_intel_ip"] == "10.29.12.215"


def test_investigate_survives_threat_intel_failure(client, mock_db, monkeypatch):
    _seed_incident(mock_db, "inc-1", source_ip="203.0.113.9")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    async def failing_lookup_all(indicator):
        raise RuntimeError("boom")

    captured = {}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None):
        captured["threat_intel"] = threat_intel
        captured["asset"] = asset
        captured["risk"] = risk
        return {"raw": "ok", "severity": "high", "confidence": "high", "impact": "x",
                "priority": "high", "summary": "x", "actions": [], "generated_at": "now"}

    monkeypatch.setattr("app.main.threat_intel.lookup_all", failing_lookup_all)
    monkeypatch.setattr("app.main.investigate_incident", fake_investigate_incident)

    resp = client.post("/api/incidents/inc-1/investigate", headers=headers)
    assert resp.status_code == 200
    assert captured["threat_intel"] is None


def test_investigate_passes_risk_score_and_stored_asset_to_report(client, mock_db, monkeypatch):
    # Asset info is stored on the incident at creation time (correlator.py / promote_alert, from
    # the S3 inventory cache) — investigate() just reads it, no live S3 call anymore.
    _seed_incident(
        mock_db, "inc-1", source_ip="203.0.113.9", severity="high", alert_count=10, max_level=12,
        asset={"hostname": "web-01", "raw": {"hostname": "web-01", "env": "prod"}},
    )
    headers = {"Authorization": f"Bearer {_login(client)}"}

    async def fake_lookup_all(indicator):
        return {"indicator": indicator, "indicator_type": "ip", "sources": {}}

    captured = {}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None):
        captured["asset"] = asset
        captured["risk"] = risk
        return {"raw": "ok", "severity": "high", "confidence": "high", "impact": "x",
                "priority": "high", "summary": "x", "actions": [], "generated_at": "now"}

    monkeypatch.setattr("app.main.threat_intel.lookup_all", fake_lookup_all)
    monkeypatch.setattr("app.main.investigate_incident", fake_investigate_incident)

    resp = client.post("/api/incidents/inc-1/investigate", headers=headers)
    assert resp.status_code == 200
    assert captured["asset"]["hostname"] == "web-01"
    assert captured["risk"]["score"] > 0


def test_investigate_survives_incident_with_no_stored_asset(client, mock_db, monkeypatch):
    # No AWS/S3 configured (or the incident predates this feature) — no `asset` field at all.
    # Investigation must still run fine, just without asset context.
    _seed_incident(mock_db, "inc-1", source_ip="203.0.113.9")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    async def fake_lookup_all(indicator):
        return {"indicator": indicator, "indicator_type": "ip", "sources": {}}

    captured = {}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None):
        captured["asset"] = asset
        return {"raw": "ok", "severity": "high", "confidence": "high", "impact": "x",
                "priority": "high", "summary": "x", "actions": [], "generated_at": "now"}

    monkeypatch.setattr("app.main.threat_intel.lookup_all", fake_lookup_all)
    monkeypatch.setattr("app.main.investigate_incident", fake_investigate_incident)

    resp = client.post("/api/incidents/inc-1/investigate", headers=headers)
    assert resp.status_code == 200
    assert captured["asset"] is None


def test_get_investigation_queue_orders_by_priority_then_first_seen(client, mock_db):
    _seed_incident(mock_db, "case-old", first_seen=1, priority=0)
    _seed_incident(mock_db, "case-newer-default-priority", first_seen=2, priority=0)
    _seed_incident(mock_db, "case-boosted", first_seen=3, priority=5)
    _seed_incident(mock_db, "case-reviewed", first_seen=0, investigation={"raw": "done"})
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/incidents/queue", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3
    assert [i["_id"] for i in body["items"]] == ["case-boosted", "case-old", "case-newer-default-priority"]


def test_update_incident_priority_reorders_the_queue(client, mock_db):
    _seed_incident(mock_db, "case-a", first_seen=1, priority=0)
    _seed_incident(mock_db, "case-b", first_seen=2, priority=0)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.patch("/api/incidents/case-b", json={"priority": 10}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["priority"] == 10

    queue = client.get("/api/incidents/queue", headers=headers).json()
    assert [i["_id"] for i in queue["items"]] == ["case-b", "case-a"]


def test_requeue_incident_moves_it_back_into_the_pending_queue(client, mock_db):
    _seed_incident(mock_db, "inc-1", investigation={"raw": "old report", "severity": "high"})
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/incidents/inc-1/requeue", headers=headers)
    assert resp.status_code == 200
    assert "investigation" not in resp.json()

    queue = client.get("/api/incidents/queue", headers=headers).json()
    assert [i["_id"] for i in queue["items"]] == ["inc-1"]

    entries = client.get("/api/audit-log", headers=headers).json()
    match = next(e for e in entries if e["action"] == "incident.requeue")
    assert match["target"] == "inc-1"


def test_requeue_incident_not_found(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/incidents/does-not-exist/requeue", headers=headers)
    assert resp.status_code == 404


def test_list_incidents_filters_by_reviewed(client, mock_db):
    _seed_incident(mock_db, "inc-case", source_ip="10.0.0.5")
    _seed_incident(mock_db, "inc-incident", source_ip="10.0.0.6", investigation={"raw": "done"})
    headers = {"Authorization": f"Bearer {_login(client)}"}

    cases = client.get("/api/incidents?reviewed=false", headers=headers).json()
    assert [inc["_id"] for inc in cases["items"]] == ["inc-case"]

    reviewed = client.get("/api/incidents?reviewed=true", headers=headers).json()
    assert [inc["_id"] for inc in reviewed["items"]] == ["inc-incident"]

    all_incidents = client.get("/api/incidents", headers=headers).json()
    assert all_incidents["total"] == 2


def test_get_incident_includes_distinct_log_lines_from_stored_unique_values(client, mock_db):
    _seed_incident(mock_db, "inc-1", unique_values={"full_log": ["old log line", "newest log line"]})
    headers = {"Authorization": f"Bearer {_login(client)}"}

    detail = client.get("/api/incidents/inc-1", headers=headers)
    assert detail.json()["full_logs"] == ["old log line", "newest log line"]


def test_get_incident_defaults_full_logs_to_empty_list_with_no_unique_values(client, mock_db):
    _seed_incident(mock_db, "inc-1")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    detail = client.get("/api/incidents/inc-1", headers=headers)
    assert detail.json()["full_logs"] == []


def test_investigate_passes_stored_unique_values_to_report(client, mock_db, monkeypatch):
    _seed_incident(mock_db, "inc-1", source_ip="203.0.113.9", unique_values={"full_log": ["GET /admin HTTP/1.1"]})
    headers = {"Authorization": f"Bearer {_login(client)}"}

    async def fake_lookup_all(indicator):
        return {"indicator": indicator, "indicator_type": "ip", "sources": {}}

    captured = {}

    async def fake_investigate_incident(incident, threat_intel=None, asset=None, risk=None, unique_values=None):
        captured["unique_values"] = unique_values
        return {"raw": "ok", "severity": "high", "confidence": "high", "impact": "x",
                "priority": "high", "summary": "x", "actions": [], "generated_at": "now"}

    monkeypatch.setattr("app.main.threat_intel.lookup_all", fake_lookup_all)
    monkeypatch.setattr("app.main.investigate_incident", fake_investigate_incident)

    resp = client.post("/api/incidents/inc-1/investigate", headers=headers)
    assert resp.status_code == 200
    assert captured["unique_values"] == {"full_log": ["GET /admin HTTP/1.1"]}


def test_delete_incident(client, mock_db):
    _seed_incident(mock_db, "inc-1")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.delete("/api/incidents/inc-1", headers=headers)
    assert resp.status_code == 200

    detail = client.get("/api/incidents/inc-1", headers=headers)
    assert detail.status_code == 404


def test_delete_incident_not_found(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.delete("/api/incidents/does-not-exist", headers=headers)
    assert resp.status_code == 404


def test_delete_incident_requires_admin(client, mock_db):
    from app.auth import hash_password
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    _seed_incident(mock_db, "inc-1")
    token = client.post("/api/auth/login", json={"username": "eve", "password": "eve-pw"}).json()["access_token"]

    resp = client.delete("/api/incidents/inc-1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_delete_incidents_bulk(client, mock_db):
    _seed_incident(mock_db, "inc-1")
    _seed_incident(mock_db, "inc-2")
    _seed_incident(mock_db, "inc-3")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/incidents/delete-bulk", json={"ids": ["inc-1", "inc-2"]}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 2

    remaining = client.get("/api/incidents", headers=headers).json()
    assert remaining["total"] == 1
    assert remaining["items"][0]["_id"] == "inc-3"


def test_delete_incident_is_audited(client, mock_db):
    _seed_incident(mock_db, "inc-1")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    client.delete("/api/incidents/inc-1", headers=headers)

    entries = client.get("/api/audit-log", headers=headers).json()
    assert any(e["action"] == "incident.delete" and e["target"] == "inc-1" for e in entries)


# ---- confirmed disposition on close (required, not optional) ----

def test_close_incident_requires_disposition(client, mock_db):
    _seed_incident(mock_db)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/incidents/inc-1/close", json={"resolution": "handled"}, headers=headers)
    assert resp.status_code == 422


def test_close_incident_rejects_an_unrecognized_disposition(client, mock_db):
    _seed_incident(mock_db)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post(
        "/api/incidents/inc-1/close",
        json={"resolution": "handled", "disposition": "not_a_real_value"},
        headers=headers,
    )
    assert resp.status_code == 422


def test_close_incident_accepts_all_valid_dispositions(client, mock_db, monkeypatch):
    async def fake_embed(incident, resolution, disposition):
        return None

    monkeypatch.setattr("app.main.embed_case_resolution", fake_embed)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    for i, disposition in enumerate(["true_positive", "false_positive", "benign_positive"]):
        incident_id = f"inc-disp-{i}"
        _seed_incident(mock_db, incident_id)
        resp = client.post(
            f"/api/incidents/{incident_id}/close",
            json={"resolution": "handled", "disposition": disposition},
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        detail = client.get(f"/api/incidents/{incident_id}", headers=headers).json()
        assert detail["disposition"] == disposition


def test_update_incident_cannot_close_via_patch(client, mock_db):
    """Closing must go through POST .../close, which enforces a confirmed disposition — the
    generic PATCH endpoint would otherwise let a case close with neither a resolution nor a
    disposition, defeating that guarantee."""
    _seed_incident(mock_db)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.patch("/api/incidents/inc-1", json={"case_status": "closed"}, headers=headers)
    assert resp.status_code == 400

    detail = client.get("/api/incidents/inc-1", headers=headers).json()
    assert detail["case_status"] == "open"

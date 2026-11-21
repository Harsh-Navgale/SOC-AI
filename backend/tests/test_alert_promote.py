import asyncio
import time


def _login(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    return resp.json()["access_token"]


def _seed_alert(mock_db, alert_id="a1", level=12, description="sshd: brute force", srcip=None,
                 agent_ip=None, correlated=False, mitre_ids=None, mitre_tactics=None,
                 timestamp="2026-01-01T00:00:00+00:00", full_log=None):
    rule = {"id": "5710", "level": level, "description": description}
    if mitre_ids or mitre_tactics:
        rule["mitre"] = {"id": mitre_ids or [], "tactic": mitre_tactics or []}
    # source_ip now always resolves from agent.ip (_extract_source_ip ignores data.srcip
    # entirely) — an explicit agent_ip wins when a test needs the two to diverge; otherwise
    # `srcip` (most call sites below) drives agent.ip too, so those tests still exercise the
    # same case-grouping scenarios they did before the resolution rule changed.
    resolved_agent_ip = agent_ip or srcip or "10.0.0.15"
    doc = {
        "_id": alert_id,
        "timestamp": timestamp,
        "correlated": correlated,
        "agent": {"id": "001", "name": "web-01", "ip": resolved_agent_ip},
        "rule": rule,
    }
    if srcip:
        doc["data"] = {"srcip": srcip}
    if full_log:
        doc["full_log"] = full_log
    asyncio.run(mock_db["raw_alerts"].insert_one(doc))


def test_promote_creates_new_incident(client, mock_db):
    _seed_alert(mock_db, "a1", level=12, srcip="203.0.113.9")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["source_ip"] == "203.0.113.9"
    assert body["case_status"] == "open"
    assert body["severity"] == "low"  # matches correlator: severity starts low regardless of rule level
    assert body["alert_count"] == 1
    assert body["max_level"] == 12
    assert body["alert_ids"] == ["a1"]
    assert "risk" in body

    alert = asyncio.run(mock_db["raw_alerts"].find_one({"_id": "a1"}))
    assert alert["correlated"] is True


def test_promote_uses_agent_ip_when_no_data_srcip(client, mock_db):
    _seed_alert(mock_db, "a1", agent_ip="10.0.0.42")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    assert resp.json()["source_ip"] == "10.0.0.42"


def test_promote_ignores_data_srcip_even_when_present(client, mock_db):
    # Grouping is always by the Wazuh agent's own IP — a web client's address in data.srcip
    # (e.g. behind an Nginx 500) must never override it.
    _seed_alert(mock_db, "a1", srcip="203.0.113.9", agent_ip="10.0.0.42")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    assert resp.json()["source_ip"] == "10.0.0.42"


def test_promote_folds_into_existing_open_incident_for_same_ip_and_rule(client, mock_db):
    now = 1767225600.0  # matches _seed_alert's default 2026-01-01T00:00:00+00:00 timestamp
    asyncio.run(mock_db["incidents"].insert_one({
        "_id": "inc-1", "source_ip": "203.0.113.9", "rule_key": "5710", "case_status": "open", "assigned_to": None,
        "notes": [], "severity": "low", "alert_ids": ["old-1"], "alert_count": 1, "max_level": 5,
        "mitre_ids": [], "mitre_tactics": [], "first_seen": now, "first_seen_iso": "x",
        "last_seen": now, "last_seen_iso": "x", "rule_description": "old rule",
    }))
    _seed_alert(mock_db, "a1", level=8, srcip="203.0.113.9")  # default rule id "5710" matches
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["_id"] == "inc-1"
    assert body["alert_count"] == 2
    assert body["max_level"] == 8
    assert "a1" in body["alert_ids"]

    total = client.get("/api/incidents", headers=headers).json()["total"]
    assert total == 1  # no duplicate incident created


def test_promote_creates_separate_case_for_a_different_rule_on_the_same_ip(client, mock_db):
    now = 1767225600.0  # matches _seed_alert's default 2026-01-01T00:00:00+00:00 timestamp
    asyncio.run(mock_db["incidents"].insert_one({
        "_id": "inc-1", "source_ip": "203.0.113.9", "rule_key": "9999", "case_status": "open", "assigned_to": None,
        "notes": [], "severity": "low", "alert_ids": ["old-1"], "alert_count": 1, "max_level": 5,
        "mitre_ids": [], "mitre_tactics": [], "first_seen": now, "first_seen_iso": "x",
        "last_seen": now, "last_seen_iso": "x", "rule_description": "Nginx 503 status code",
    }))
    # Default rule id "5710" (from _seed_alert) differs from the existing case's "9999" — must
    # create its own case rather than folding into a case for an unrelated rule.
    _seed_alert(mock_db, "a1", level=10, srcip="203.0.113.9", description="SSH brute force")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    body = resp.json()
    assert body["_id"] != "inc-1"
    assert body["rule_description"] == "SSH brute force"

    total = client.get("/api/incidents", headers=headers).json()["total"]
    assert total == 2


def test_promote_bumps_severity_to_high_at_threshold(client, mock_db):
    now = 1767225600.0  # matches _seed_alert's default 2026-01-01T00:00:00+00:00 timestamp
    asyncio.run(mock_db["incidents"].insert_one({
        "_id": "inc-1", "source_ip": "203.0.113.9", "rule_key": "5710", "case_status": "open", "assigned_to": None,
        "notes": [], "severity": "low", "alert_ids": ["1", "2", "3", "4"], "alert_count": 4, "max_level": 5,
        "mitre_ids": [], "mitre_tactics": [], "first_seen": now, "first_seen_iso": "x",
        "last_seen": now, "last_seen_iso": "x", "rule_description": "old rule",
    }))
    _seed_alert(mock_db, "a1", level=8, srcip="203.0.113.9")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    assert resp.json()["severity"] == "high"  # 4 + 1 = 5 == CORRELATION_THRESHOLD default


def test_promote_rejects_already_correlated_alert(client, mock_db):
    _seed_alert(mock_db, "a1", correlated=True)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    assert resp.status_code == 409


def test_promote_allows_overriding_an_excluded_alert(client, mock_db):
    _seed_alert(mock_db, "a1", srcip="203.0.113.9", correlated=True)
    asyncio.run(mock_db["raw_alerts"].update_one({"_id": "a1"}, {"$set": {"excluded": True, "excluded_by_rule": "ignore health checks"}}))
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["source_ip"] == "203.0.113.9"

    # The override clears the excluded marker — it's genuinely in a case now, not still "excluded".
    stored = asyncio.run(mock_db["raw_alerts"].find_one({"_id": "a1"}))
    assert "excluded" not in stored
    assert "excluded_by_rule" not in stored


def test_promote_alert_not_found(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/alerts/does-not-exist/promote", headers=headers)
    assert resp.status_code == 404


def test_promote_is_audited(client, mock_db):
    _seed_alert(mock_db, "a1", srcip="203.0.113.9")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    client.post("/api/alerts/a1/promote", headers=headers)

    entries = client.get("/api/audit-log", headers=headers).json()
    match = next(e for e in entries if e["action"] == "alert.promote")
    assert match["target"] == "a1"
    assert "incident_id" in match["details"]


def test_promote_copies_mitre_fields(client, mock_db):
    _seed_alert(mock_db, "a1", srcip="203.0.113.9", mitre_ids=["T1110"], mitre_tactics=["Credential Access"])
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    body = resp.json()
    assert body["mitre_ids"] == ["T1110"]
    assert body["mitre_tactics"] == ["Credential Access"]


def test_promote_stores_unique_values_from_the_alert(client, mock_db):
    _seed_alert(mock_db, "a1", srcip="203.0.113.9", full_log="Failed password for root from 203.0.113.9")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    body = resp.json()
    assert body["unique_values"]["full_log"] == ["Failed password for root from 203.0.113.9"]
    assert body["unique_values"]["data.srcip"] == ["203.0.113.9"]


def test_promote_merges_unique_values_into_an_existing_case(client, mock_db):
    now = 1767225600.0  # matches _seed_alert's default 2026-01-01T00:00:00+00:00 timestamp
    asyncio.run(mock_db["incidents"].insert_one({
        "_id": "inc-1", "source_ip": "203.0.113.9", "rule_key": "5710", "case_status": "open", "assigned_to": None,
        "notes": [], "severity": "low", "alert_ids": ["old-1"], "alert_count": 1, "max_level": 5,
        "mitre_ids": [], "mitre_tactics": [], "first_seen": now, "first_seen_iso": "x",
        "last_seen": now, "last_seen_iso": "x", "rule_description": "old rule",
        "unique_values": {"full_log": ["first log line"]},
    }))
    _seed_alert(mock_db, "a1", srcip="203.0.113.9", full_log="second log line")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    body = resp.json()
    assert body["unique_values"]["full_log"] == ["first log line", "second log line"]


def test_promote_uses_alerts_own_timestamp_not_processing_time(client, mock_db):
    _seed_alert(mock_db, "a1", srcip="203.0.113.9", timestamp="2026-04-29T15:07:00.000+0000")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    body = resp.json()
    assert body["first_seen_iso"].startswith("2026-04-29")
    assert body["last_seen_iso"].startswith("2026-04-29")


def test_promote_does_not_merge_incidents_months_apart_regardless_of_order(client, mock_db):
    now = time.time()
    # An existing incident whose last real activity was in July.
    asyncio.run(mock_db["incidents"].insert_one({
        "_id": "inc-1", "source_ip": "203.0.113.9", "case_status": "open", "assigned_to": None,
        "notes": [], "severity": "low", "alert_ids": ["old-1"], "alert_count": 1, "max_level": 5,
        "mitre_ids": [], "mitre_tactics": [], "first_seen": now, "first_seen_iso": "2026-07-15T09:00:00+00:00",
        "last_seen": 1784106000.0, "last_seen_iso": "2026-07-15T09:00:00+00:00", "rule_description": "old rule",
    }))
    # Promoting an April alert for the same IP must NOT fold into the July incident.
    _seed_alert(mock_db, "a1", srcip="203.0.113.9", timestamp="2026-04-29T15:07:00.000+0000")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/alerts/a1/promote", headers=headers)
    body = resp.json()
    assert body["_id"] != "inc-1"
    assert body["first_seen_iso"].startswith("2026-04-29")

    total = client.get("/api/incidents", headers=headers).json()["total"]
    assert total == 2

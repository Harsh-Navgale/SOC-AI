import asyncio

from app import exclusion_rules as exclusion_rules_module


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


# ---- AI structuring ----

def test_structure_criteria_uses_ai_output_when_valid(monkeypatch):
    async def fake_generate(prompt, model=None):
        return '{"criteria": [{"field": "rule.description", "operator": "contains", "value": "health check"}]}'
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)

    criteria = asyncio.run(exclusion_rules_module.structure_criteria("ignore health check alerts"))
    assert criteria == [{"field": "rule.description", "operator": "contains", "value": "health check"}]


def test_structure_criteria_handles_multiple_conditions(monkeypatch):
    async def fake_generate(prompt, model=None):
        return '''{"criteria": [
            {"field": "source_ip", "operator": "equals", "value": "10.1.2.3"},
            {"field": "rule.description", "operator": "contains", "value": "scan"}
        ]}'''
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)

    criteria = asyncio.run(exclusion_rules_module.structure_criteria("ignore scans from 10.1.2.3"))
    assert len(criteria) == 2
    assert {"field": "source_ip", "operator": "equals", "value": "10.1.2.3"} in criteria


def test_structure_criteria_tolerates_prose_wrapped_around_json(monkeypatch):
    async def fake_generate(prompt, model=None):
        return 'Sure, here is the JSON:\n{"criteria": [{"field": "agent.name", "operator": "contains", "value": "scanner-01"}]}\nHope that helps!'
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)

    criteria = asyncio.run(exclusion_rules_module.structure_criteria("ignore scanner-01"))
    assert criteria == [{"field": "agent.name", "operator": "contains", "value": "scanner-01"}]


def test_structure_criteria_drops_placeholder_none_values(monkeypatch):
    # A small model asked to fill in every allowed field sometimes emits the literal text
    # "None"/"n/a" for fields the analyst never mentioned, instead of omitting them. Keeping
    # one would AND in a condition that can never match (e.g. source_ip equals "None"),
    # silently making the whole rule impossible to ever trigger.
    async def fake_generate(prompt, model=None):
        return '''{"criteria": [
            {"field": "source_ip", "operator": "equals", "value": "None"},
            {"field": "rule.description", "operator": "contains", "value": "health check probe"},
            {"field": "mitre.tactic", "operator": "equals", "value": "n/a"},
            {"field": "agent.name", "operator": "contains", "value": "unknown"},
            {"field": "agent.ip", "operator": "equals", "value": ""}
        ]}'''
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)

    criteria = asyncio.run(exclusion_rules_module.structure_criteria("ignore health check probes"))
    assert criteria == [{"field": "rule.description", "operator": "contains", "value": "health check probe"}]


def test_structure_criteria_falls_back_on_invalid_json(monkeypatch):
    async def fake_generate(prompt, model=None):
        return "not json at all"
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)

    criteria = asyncio.run(exclusion_rules_module.structure_criteria("ignore weird noisy alerts"))
    assert criteria == [{"field": "rule.description", "operator": "contains", "value": "ignore weird noisy alerts"}]


def test_structure_criteria_falls_back_on_disallowed_field(monkeypatch):
    async def fake_generate(prompt, model=None):
        return '{"criteria": [{"field": "something.made.up", "operator": "contains", "value": "x"}]}'
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)

    criteria = asyncio.run(exclusion_rules_module.structure_criteria("some description"))
    assert criteria == [{"field": "rule.description", "operator": "contains", "value": "some description"}]


def test_structure_criteria_falls_back_when_the_ai_call_fails(monkeypatch):
    async def failing_generate(prompt, model=None):
        raise RuntimeError("Bedrock unreachable")
    monkeypatch.setattr(exclusion_rules_module, "_generate", failing_generate)

    criteria = asyncio.run(exclusion_rules_module.structure_criteria("ignore this"))
    assert criteria == [{"field": "rule.description", "operator": "contains", "value": "ignore this"}]


# ---- structured (non-AI) creation ----

def test_create_rule_from_rule_id_skips_ai(mock_db, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("AI must not be called when a structured field is given")
    monkeypatch.setattr(exclusion_rules_module, "_generate", boom)

    doc = asyncio.run(exclusion_rules_module.create_rule(None, "admin", rule_id="5710"))
    assert doc["criteria"] == [{"field": "rule.id", "operator": "equals", "value": "5710"}]
    assert doc["ai_structured"] is False
    assert "rule.id" in doc["description"]  # auto-generated label since none was given


def test_create_rule_combines_all_three_structured_fields(mock_db, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("AI must not be called when a structured field is given")
    monkeypatch.setattr(exclusion_rules_module, "_generate", boom)

    doc = asyncio.run(exclusion_rules_module.create_rule(
        None, "admin", rule_id="100", rule_description="health check", ip="10.1.2.3", ip_field="agent.ip",
    ))
    assert doc["criteria"] == [
        {"field": "rule.id", "operator": "equals", "value": "100"},
        {"field": "rule.description", "operator": "contains", "value": "health check"},
        {"field": "agent.ip", "operator": "equals", "value": "10.1.2.3"},
    ]


def test_create_rule_structured_field_uses_a_given_label_instead_of_auto_generating_one(mock_db, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("AI must not be called when a structured field is given")
    monkeypatch.setattr(exclusion_rules_module, "_generate", boom)

    doc = asyncio.run(exclusion_rules_module.create_rule("Known scanner", "admin", ip="10.1.2.3"))
    assert doc["description"] == "Known scanner"


def test_create_rule_ip_field_defaults_to_source_ip(mock_db, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("AI must not be called when a structured field is given")
    monkeypatch.setattr(exclusion_rules_module, "_generate", boom)

    doc = asyncio.run(exclusion_rules_module.create_rule(None, "admin", ip="10.1.2.3"))
    assert doc["criteria"] == [{"field": "source_ip", "operator": "equals", "value": "10.1.2.3"}]


# ---- endpoints ----

def test_create_exclusion_rule_endpoint_with_structured_fields(client, mock_db, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("AI must not be called when a structured field is given")
    monkeypatch.setattr(exclusion_rules_module, "_generate", boom)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/exclusion-rules", json={"rule_id": "5710"}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["criteria"] == [{"field": "rule.id", "operator": "equals", "value": "5710"}]
    assert body["ai_structured"] is False


def test_create_exclusion_rule_rejects_when_nothing_at_all_is_given(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/exclusion-rules", json={}, headers=headers)
    assert resp.status_code == 422




def test_create_exclusion_rule_endpoint(client, mock_db, monkeypatch):
    async def fake_generate(prompt, model=None):
        return '{"criteria": [{"field": "rule.description", "operator": "contains", "value": "health check"}]}'
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post("/api/exclusion-rules", json={"description": "ignore health check noise"}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["description"] == "ignore health check noise"
    assert body["criteria"] == [{"field": "rule.description", "operator": "contains", "value": "health check"}]
    assert body["active"] is True
    assert body["created_by"] == "admin"


def test_create_exclusion_rule_requires_admin(client, mock_db):
    from app.auth import hash_password
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/exclusion-rules", json={"description": "x"}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_create_exclusion_rule_rejects_blank_description(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/exclusion-rules", json={"description": "   "}, headers=headers)
    assert resp.status_code == 422


def test_list_exclusion_rules(client, mock_db, monkeypatch):
    async def fake_generate(prompt, model=None):
        return '{"criteria": [{"field": "rule.description", "operator": "contains", "value": "x"}]}'
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    client.post("/api/exclusion-rules", json={"description": "rule one"}, headers=headers)
    client.post("/api/exclusion-rules", json={"description": "rule two"}, headers=headers)

    resp = client.get("/api/exclusion-rules", headers=headers)
    assert resp.status_code == 200
    descriptions = {r["description"] for r in resp.json()}
    assert descriptions == {"rule one", "rule two"}


def test_toggle_exclusion_rule_active(client, mock_db, monkeypatch):
    async def fake_generate(prompt, model=None):
        return '{"criteria": [{"field": "rule.description", "operator": "contains", "value": "x"}]}'
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    created = client.post("/api/exclusion-rules", json={"description": "rule one"}, headers=headers).json()

    resp = client.patch(f"/api/exclusion-rules/{created['_id']}", json={"active": False}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["active"] is False


def test_update_exclusion_rule_description_re_structures_criteria(client, mock_db, monkeypatch):
    call_count = {"n": 0}

    async def fake_generate(prompt, model=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return '{"criteria": [{"field": "rule.description", "operator": "contains", "value": "old"}]}'
        return '{"criteria": [{"field": "rule.description", "operator": "contains", "value": "new"}]}'
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    created = client.post("/api/exclusion-rules", json={"description": "old description"}, headers=headers).json()
    resp = client.patch(f"/api/exclusion-rules/{created['_id']}", json={"description": "new description"}, headers=headers)
    assert resp.json()["criteria"] == [{"field": "rule.description", "operator": "contains", "value": "new"}]


def test_delete_exclusion_rule(client, mock_db, monkeypatch):
    async def fake_generate(prompt, model=None):
        return '{"criteria": [{"field": "rule.description", "operator": "contains", "value": "x"}]}'
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    created = client.post("/api/exclusion-rules", json={"description": "rule one"}, headers=headers).json()
    resp = client.delete(f"/api/exclusion-rules/{created['_id']}", headers=headers)
    assert resp.status_code == 200

    listing = client.get("/api/exclusion-rules", headers=headers).json()
    assert listing == []


def test_delete_exclusion_rule_not_found(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.delete("/api/exclusion-rules/does-not-exist", headers=headers)
    assert resp.status_code == 404


def test_exclusion_rule_create_is_audited(client, mock_db, monkeypatch):
    async def fake_generate(prompt, model=None):
        return '{"criteria": [{"field": "rule.description", "operator": "contains", "value": "x"}]}'
    monkeypatch.setattr(exclusion_rules_module, "_generate", fake_generate)
    headers = {"Authorization": f"Bearer {_login(client)}"}

    client.post("/api/exclusion-rules", json={"description": "rule one"}, headers=headers)

    entries = client.get("/api/audit-log", headers=headers).json()
    assert any(e["action"] == "exclusion_rule.create" for e in entries)

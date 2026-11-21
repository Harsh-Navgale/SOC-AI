import asyncio

from app import scheduler as scheduler_module, pipeline_settings
from app.auth import hash_password


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


# ---- alert ingestion (pause pulling new alerts from Wazuh) ----

def test_alert_ingestion_setting_defaults_to_enabled(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/alert-ingestion", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True


def test_admin_can_toggle_alert_ingestion_setting(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    try:
        resp = client.post("/api/settings/alert-ingestion", json={"enabled": False}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        assert scheduler_module.alert_ingestion_enabled is False

        assert client.get("/api/settings/alert-ingestion", headers=headers).json()["enabled"] is False
    finally:
        scheduler_module.set_alert_ingestion_enabled(True)


def test_non_admin_cannot_toggle_alert_ingestion_setting(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/settings/alert-ingestion", json={"enabled": False}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# ---- case correlation (pause the correlator grouping alerts into cases) ----

def test_case_correlation_setting_defaults_to_enabled(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/case-correlation", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True


def test_admin_can_toggle_case_correlation_setting(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/settings/case-correlation", json={"enabled": False}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False
    assert asyncio.run(pipeline_settings.is_correlation_paused()) is True

    assert client.get("/api/settings/case-correlation", headers=headers).json()["enabled"] is False

    resp = client.post("/api/settings/case-correlation", json={"enabled": True}, headers=headers)
    assert resp.json()["enabled"] is True


def test_non_admin_cannot_toggle_case_correlation_setting(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/settings/case-correlation", json={"enabled": False}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# ---- case enrichment (threat intel + org-docs context, between correlation and AI investigation) ----

def test_case_enrichment_setting_defaults_to_enabled(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/case-enrichment", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True


def test_admin_can_toggle_case_enrichment_setting(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    try:
        resp = client.post("/api/settings/case-enrichment", json={"enabled": False}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        assert scheduler_module.enrichment_enabled is False

        assert client.get("/api/settings/case-enrichment", headers=headers).json()["enabled"] is False
    finally:
        scheduler_module.set_enrichment_enabled(True)


def test_non_admin_cannot_toggle_case_enrichment_setting(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/settings/case-enrichment", json={"enabled": False}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# ---- campaign correlation (cross-incident grouping, backend-only job) ----

def test_campaign_correlation_setting_defaults_to_enabled(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/campaign-correlation", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True


def test_admin_can_toggle_campaign_correlation_setting(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    try:
        resp = client.post("/api/settings/campaign-correlation", json={"enabled": False}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        assert scheduler_module.campaign_correlation_enabled is False

        assert client.get("/api/settings/campaign-correlation", headers=headers).json()["enabled"] is False
    finally:
        scheduler_module.set_campaign_correlation_enabled(True)


def test_non_admin_cannot_toggle_campaign_correlation_setting(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/settings/campaign-correlation", json={"enabled": False}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_auto_investigate_setting_defaults_to_enabled(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/auto-investigate", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True


def test_admin_can_toggle_auto_investigate_setting(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    try:
        resp = client.post("/api/settings/auto-investigate", json={"enabled": False}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        assert scheduler_module.auto_investigate_enabled is False

        assert client.get("/api/settings/auto-investigate", headers=headers).json()["enabled"] is False
    finally:
        scheduler_module.set_auto_investigate_enabled(True)


def test_non_admin_cannot_toggle_auto_investigate_setting(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/settings/auto-investigate", json={"enabled": False}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# ---- multi-agent investigation (staged rule-health + verdict agents instead of one prompt) ----

def test_multi_agent_investigation_setting_defaults_to_disabled(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/multi-agent-investigation", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


def test_admin_can_toggle_multi_agent_investigation_setting(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/settings/multi-agent-investigation", json={"enabled": True}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True
    assert asyncio.run(pipeline_settings.is_multi_agent_investigation_enabled()) is True

    assert client.get("/api/settings/multi-agent-investigation", headers=headers).json()["enabled"] is True

    resp = client.post("/api/settings/multi-agent-investigation", json={"enabled": False}, headers=headers)
    assert resp.json()["enabled"] is False


def test_non_admin_cannot_toggle_multi_agent_investigation_setting(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/settings/multi-agent-investigation", json={"enabled": True}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# ---- structured output (Bedrock tool-use for investigate_incident, Claude-on-Bedrock only) ----

def test_structured_output_setting_defaults_to_disabled(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/structured-output", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


def test_admin_can_toggle_structured_output_setting(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/settings/structured-output", json={"enabled": True}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True
    assert asyncio.run(pipeline_settings.is_structured_output_enabled()) is True

    assert client.get("/api/settings/structured-output", headers=headers).json()["enabled"] is True

    resp = client.post("/api/settings/structured-output", json={"enabled": False}, headers=headers)
    assert resp.json()["enabled"] is False


def test_non_admin_cannot_toggle_structured_output_setting(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/settings/structured-output", json={"enabled": True}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# ---- cheap AI model (routes mechanically-simple cases away from the default model) ----

def test_cheap_ai_model_setting_defaults_to_none(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/cheap-ai-model", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["model_id"] is None


def test_admin_can_set_cheap_ai_model(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/settings/cheap-ai-model", json={"model_id": "bedrock:amazon.nova-micro-v1:0"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["model_id"] == "bedrock:amazon.nova-micro-v1:0"
    assert asyncio.run(pipeline_settings.get_cheap_ai_model()) == "bedrock:amazon.nova-micro-v1:0"


def test_non_admin_cannot_set_cheap_ai_model(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/settings/cheap-ai-model", json={"model_id": "m"}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# ---- monthly AI budget cap ----

def test_monthly_budget_cap_setting_defaults_to_none(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/monthly-budget-cap", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["amount"] is None


def test_admin_can_set_monthly_budget_cap(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/settings/monthly-budget-cap", json={"amount": 25.5}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["amount"] == 25.5
    assert asyncio.run(pipeline_settings.get_monthly_budget_cap()) == 25.5


def test_non_admin_cannot_set_monthly_budget_cap(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")

    resp = client.post("/api/settings/monthly-budget-cap", json={"amount": 10}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403

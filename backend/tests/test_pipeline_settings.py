import asyncio

from mongomock_motor import AsyncMongoMockClient

from app import pipeline_settings


def _db(monkeypatch):
    mock_client = AsyncMongoMockClient()
    db = mock_client["soc_ai_pipeline_settings_test"]
    monkeypatch.setattr(pipeline_settings, "system_settings", db["system_settings"])
    return db


def test_correlation_defaults_to_not_paused(monkeypatch):
    _db(monkeypatch)
    assert asyncio.run(pipeline_settings.is_correlation_paused()) is False


def test_set_correlation_paused_persists(monkeypatch):
    _db(monkeypatch)
    asyncio.run(pipeline_settings.set_correlation_paused(True))
    assert asyncio.run(pipeline_settings.is_correlation_paused()) is True

    asyncio.run(pipeline_settings.set_correlation_paused(False))
    assert asyncio.run(pipeline_settings.is_correlation_paused()) is False


def test_multi_agent_investigation_defaults_to_disabled(monkeypatch):
    _db(monkeypatch)
    assert asyncio.run(pipeline_settings.is_multi_agent_investigation_enabled()) is False


def test_set_multi_agent_investigation_enabled_persists(monkeypatch):
    _db(monkeypatch)
    asyncio.run(pipeline_settings.set_multi_agent_investigation_enabled(True))
    assert asyncio.run(pipeline_settings.is_multi_agent_investigation_enabled()) is True

    asyncio.run(pipeline_settings.set_multi_agent_investigation_enabled(False))
    assert asyncio.run(pipeline_settings.is_multi_agent_investigation_enabled()) is False


def test_structured_output_defaults_to_disabled(monkeypatch):
    _db(monkeypatch)
    assert asyncio.run(pipeline_settings.is_structured_output_enabled()) is False


def test_set_structured_output_enabled_persists(monkeypatch):
    _db(monkeypatch)
    asyncio.run(pipeline_settings.set_structured_output_enabled(True))
    assert asyncio.run(pipeline_settings.is_structured_output_enabled()) is True

    asyncio.run(pipeline_settings.set_structured_output_enabled(False))
    assert asyncio.run(pipeline_settings.is_structured_output_enabled()) is False


def test_monthly_budget_cap_defaults_to_none(monkeypatch):
    _db(monkeypatch)
    assert asyncio.run(pipeline_settings.get_monthly_budget_cap()) is None


def test_set_monthly_budget_cap_persists(monkeypatch):
    _db(monkeypatch)
    asyncio.run(pipeline_settings.set_monthly_budget_cap(50.0))
    assert asyncio.run(pipeline_settings.get_monthly_budget_cap()) == 50.0

    asyncio.run(pipeline_settings.set_monthly_budget_cap(None))
    assert asyncio.run(pipeline_settings.get_monthly_budget_cap()) is None


def test_cheap_ai_model_defaults_to_none(monkeypatch):
    _db(monkeypatch)
    assert asyncio.run(pipeline_settings.get_cheap_ai_model()) is None


def test_set_cheap_ai_model_persists(monkeypatch):
    _db(monkeypatch)
    asyncio.run(pipeline_settings.set_cheap_ai_model("bedrock:amazon.nova-micro-v1:0"))
    assert asyncio.run(pipeline_settings.get_cheap_ai_model()) == "bedrock:amazon.nova-micro-v1:0"

    asyncio.run(pipeline_settings.set_cheap_ai_model(None))
    assert asyncio.run(pipeline_settings.get_cheap_ai_model()) is None

import asyncio
from datetime import datetime, timezone

from mongomock_motor import AsyncMongoMockClient

from app import ai_usage


def _db(monkeypatch):
    mock_client = AsyncMongoMockClient()
    db = mock_client["soc_ai_usage_test"]
    monkeypatch.setattr(ai_usage, "ai_usage_collection", db["ai_usage"])
    return db["ai_usage"]


def test_estimate_cost_matches_configured_rates(monkeypatch):
    monkeypatch.setattr(ai_usage, "AI_COST_PER_1M_INPUT", 1.0)
    monkeypatch.setattr(ai_usage, "AI_COST_PER_1M_OUTPUT", 5.0)

    cost = ai_usage.estimate_cost(prompt_tokens=1_000_000, completion_tokens=200_000)

    assert cost == 1.0 + 1.0  # 1M in @ $1/M + 200K out @ $5/M = $1 + $1


def test_estimate_cost_uses_real_bedrock_rate_for_a_known_model(monkeypatch):
    # Deliberately different from the configured global default, so this only passes if the
    # Bedrock-specific rate was actually used, not the fallback.
    monkeypatch.setattr(ai_usage, "AI_COST_PER_1M_INPUT", 999.0)
    monkeypatch.setattr(ai_usage, "AI_COST_PER_1M_OUTPUT", 999.0)

    cost = ai_usage.estimate_cost(
        prompt_tokens=1_000_000, completion_tokens=1_000_000,
        model="bedrock:anthropic.claude-haiku-4-5-20251001-v1:0",
    )

    assert cost == 1.0 + 5.0  # Haiku 4.5's real $1/$5 per 1M, not the 999.0 fallback


def test_estimate_cost_falls_back_to_global_default_for_unrecognized_bedrock_model(monkeypatch):
    monkeypatch.setattr(ai_usage, "AI_COST_PER_1M_INPUT", 2.0)
    monkeypatch.setattr(ai_usage, "AI_COST_PER_1M_OUTPUT", 10.0)

    cost = ai_usage.estimate_cost(
        prompt_tokens=1_000_000, completion_tokens=1_000_000, model="bedrock:some.unknown-model-v1:0",
    )

    assert cost == 2.0 + 10.0


def test_estimate_cost_ignores_bedrock_pricing_for_an_unprefixed_model_id(monkeypatch):
    monkeypatch.setattr(ai_usage, "AI_COST_PER_1M_INPUT", 2.0)
    monkeypatch.setattr(ai_usage, "AI_COST_PER_1M_OUTPUT", 10.0)

    cost = ai_usage.estimate_cost(prompt_tokens=1_000_000, completion_tokens=1_000_000, model="some-model")

    assert cost == 2.0 + 10.0


def test_summary_aggregates_totals_across_calls(monkeypatch):
    _db(monkeypatch)
    asyncio.run(ai_usage.record("investigate", "phi4-mini", 500, 150, parse_ok=True))
    asyncio.run(ai_usage.record("investigate", "phi4-mini", 700, 200, parse_ok=False))
    asyncio.run(ai_usage.record("ask_ai", "phi4-mini", 300, 100))

    summary = asyncio.run(ai_usage.summary())

    assert summary["calls"] == 3
    assert summary["prompt_tokens"] == 1500
    assert summary["completion_tokens"] == 450
    assert summary["estimated_cost"] > 0


def test_parse_failure_rate_only_counts_investigation_calls(monkeypatch):
    _db(monkeypatch)
    asyncio.run(ai_usage.record("investigate", "m", 100, 50, parse_ok=True))
    asyncio.run(ai_usage.record("investigate", "m", 100, 50, parse_ok=False))
    asyncio.run(ai_usage.record("ask_ai", "m", 100, 50))  # parse_ok stays None — not counted

    summary = asyncio.run(ai_usage.summary())

    assert summary["parse_total"] == 2
    assert summary["parse_failures"] == 1
    assert summary["parse_failure_rate"] == 0.5


def test_summary_with_no_data_returns_zeros_and_null_rate(monkeypatch):
    _db(monkeypatch)
    summary = asyncio.run(ai_usage.summary())

    assert summary["calls"] == 0
    assert summary["parse_failure_rate"] is None


def test_month_to_date_cost_sums_only_this_months_calls(monkeypatch):
    collection = _db(monkeypatch)
    asyncio.run(collection.insert_one({
        "source": "investigate", "model": "m", "prompt_tokens": 0, "completion_tokens": 0,
        "estimated_cost": 100.0, "parse_ok": None, "created_at": "2020-01-01T00:00:00+00:00",
    }))
    asyncio.run(collection.insert_one({
        "source": "investigate", "model": "m", "prompt_tokens": 0, "completion_tokens": 0,
        "estimated_cost": 2.5, "parse_ok": None,
        "created_at": datetime.now(timezone.utc).replace(day=1).isoformat(),
    }))

    cost = asyncio.run(ai_usage.month_to_date_cost())

    assert cost == 2.5  # the 2020 record must not be included


def test_month_to_date_cost_is_zero_with_no_data(monkeypatch):
    _db(monkeypatch)
    assert asyncio.run(ai_usage.month_to_date_cost()) == 0.0


def test_summary_includes_month_to_date_cost(monkeypatch):
    _db(monkeypatch)
    asyncio.run(ai_usage.record("investigate", "m", 1_000_000, 0))

    summary = asyncio.run(ai_usage.summary())

    assert summary["month_to_date_cost"] > 0

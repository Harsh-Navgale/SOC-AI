"""Per-call AI token/cost tracking, surfaced on the Debug tab. For a Bedrock model this app has
a known rate for (bedrock_client.py's BEDROCK_PRICING), cost uses that model's actual $/1M
rates. For a Bedrock model without a listed rate, cost falls back to the configured
AI_COST_PER_1M_INPUT/OUTPUT (defaulting to Claude Haiku 4.5's pricing) as a best-effort estimate.
"""
from datetime import datetime, timezone

from app.db import ai_usage as ai_usage_collection
from app.config import AI_COST_PER_1M_INPUT, AI_COST_PER_1M_OUTPUT
from app import bedrock_client


def estimate_cost(
    prompt_tokens: int, completion_tokens: int, model: str | None = None,
    cache_read_tokens: int = 0, cache_write_tokens: int = 0,
) -> float:
    """cache_read_tokens/cache_write_tokens come from Bedrock's Converse API usage object when a
    call actually used prompt caching (see bedrock_client.py's _supports_prompt_caching) — 0 for
    every other call, same cost as before caching existed. Priced relative to whichever
    input_rate was just resolved: a cache write runs ~1.25x ordinary input, a cache read ~0.1x
    — Anthropic's documented ratios for Claude, applied here as a best-effort estimate like the
    rest of this module (not pulled live from AWS billing)."""
    input_rate, output_rate = AI_COST_PER_1M_INPUT, AI_COST_PER_1M_OUTPUT
    if model and model.startswith("bedrock:"):
        rates = bedrock_client.price_for(model[len("bedrock:"):])
        if rates:
            input_rate, output_rate = rates
    return round(
        prompt_tokens / 1_000_000 * input_rate
        + completion_tokens / 1_000_000 * output_rate
        + cache_write_tokens / 1_000_000 * input_rate * 1.25
        + cache_read_tokens / 1_000_000 * input_rate * 0.1,
        6,
    )


async def record(
    source: str, model: str, prompt_tokens: int, completion_tokens: int, parse_ok: bool | None = None,
    cache_read_tokens: int = 0, cache_write_tokens: int = 0,
):
    await ai_usage_collection.insert_one({
        "source": source,  # "investigate" | "ask_ai"
        "model": model,
        "prompt_tokens": prompt_tokens or 0,
        "completion_tokens": completion_tokens or 0,
        "estimated_cost": estimate_cost(
            prompt_tokens or 0, completion_tokens or 0, model,
            cache_read_tokens=cache_read_tokens or 0, cache_write_tokens=cache_write_tokens or 0,
        ),
        "parse_ok": parse_ok,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })


async def month_to_date_cost() -> float:
    """Sum of estimated_cost for calls recorded since the start of the current calendar month.
    created_at is stored as an ISO 8601 string (see record() above), which sorts/compares
    lexically the same as the datetimes it represents, so a plain string $gte works without
    parsing every document back into a datetime."""
    month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    pipeline = [
        {"$match": {"created_at": {"$gte": month_start.isoformat()}}},
        {"$group": {"_id": None, "estimated_cost": {"$sum": "$estimated_cost"}}},
    ]
    totals = [doc async for doc in ai_usage_collection.aggregate(pipeline)]
    return round(totals[0]["estimated_cost"], 4) if totals else 0.0


async def summary() -> dict:
    """All-time totals for the Debug tab, plus a parse-failure rate for investigation reports
    specifically (parse_ok is only ever set for that source — ask_ai has no such notion)."""
    pipeline = [
        {"$group": {
            "_id": None,
            "calls": {"$sum": 1},
            "prompt_tokens": {"$sum": "$prompt_tokens"},
            "completion_tokens": {"$sum": "$completion_tokens"},
            "estimated_cost": {"$sum": "$estimated_cost"},
        }}
    ]
    totals = [doc async for doc in ai_usage_collection.aggregate(pipeline)]
    totals = totals[0] if totals else {}

    parse_total = await ai_usage_collection.count_documents({"parse_ok": {"$ne": None}})
    parse_failures = await ai_usage_collection.count_documents({"parse_ok": False})

    return {
        "calls": totals.get("calls", 0),
        "prompt_tokens": totals.get("prompt_tokens", 0),
        "completion_tokens": totals.get("completion_tokens", 0),
        "estimated_cost": round(totals.get("estimated_cost", 0.0), 4),
        "parse_failures": parse_failures,
        "parse_total": parse_total,
        "parse_failure_rate": round(parse_failures / parse_total, 4) if parse_total else None,
        "month_to_date_cost": await month_to_date_cost(),
    }

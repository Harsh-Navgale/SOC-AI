"""Persisted pause switch for the case-correlation stage of the pipeline (raw alert -> case
-> AI investigation -> incident). Unlike the AI-investigation pause (an in-memory flag on the
backend, fine since only the backend's own scheduler reads it) and the alert-ingestion pause
(same — it only gates the backend's own Wazuh-polling job), the correlator is a separate
container/process with no shared memory with the backend, so its pause has to live somewhere
both sides can see it. Mongo is that shared place.
"""
from app.db import system_settings

_STAGE_ID = "case_correlation"


async def is_correlation_paused() -> bool:
    doc = await system_settings.find_one({"_id": _STAGE_ID})
    return bool(doc and doc.get("paused"))


async def set_correlation_paused(paused: bool) -> None:
    await system_settings.update_one({"_id": _STAGE_ID}, {"$set": {"paused": paused}}, upsert=True)


# The admin-configured default AI model (a Bedrock model id, conventionally prefixed
# "bedrock:" — see rag.py's _generate()) that every background job uses when nobody's present
# to pick one per call. Same shared-Mongo reasoning as the pause switch above, even though this
# isn't a pause: it's read by rag.py, which the backend and any future additional backend
# instance would both need to see consistently.
_DEFAULT_MODEL_ID = "default_ai_model"


async def get_default_ai_model() -> str | None:
    doc = await system_settings.find_one({"_id": _DEFAULT_MODEL_ID})
    return doc.get("model_id") if doc else None


async def set_default_ai_model(model_id: str) -> None:
    await system_settings.update_one({"_id": _DEFAULT_MODEL_ID}, {"$set": {"model_id": model_id}}, upsert=True)


# The admin-configured second choice _generate() crosses over to when the default model is
# unavailable outright (Bedrock not connected/credentials expired, or that specific
# model/region having an outage) — not when the model itself just produces a bad answer.
# Explicit and admin-set, same as DEFAULT_BEDROCK_CHAT_MODEL, rather than auto-picked: picking
# an unvetted model automatically on failure would risk silently invoking one with real,
# unexpected per-token cost.
_FALLBACK_MODEL_ID = "fallback_ai_model"


async def get_fallback_ai_model() -> str | None:
    doc = await system_settings.find_one({"_id": _FALLBACK_MODEL_ID})
    return doc.get("model_id") if doc else None


async def set_fallback_ai_model(model_id: str) -> None:
    await system_settings.update_one({"_id": _FALLBACK_MODEL_ID}, {"$set": {"model_id": model_id}}, upsert=True)


# Same idea, for embeddings (RAG retrieval into ChromaDB) — a Bedrock model id, conventionally
# "bedrock:"-prefixed, same convention as the chat-model setting above. Unlike the
# chat model, this one isn't safe to change casually once org_knowledge holds real vectors —
# see bedrock_client.py's embed() docstring — but nothing here enforces that; it's on whoever
# changes this setting to know the collection is empty first, or to accept re-embedding it.
_DEFAULT_EMBEDDING_MODEL_ID = "default_embedding_model"


async def get_default_embedding_model() -> str | None:
    doc = await system_settings.find_one({"_id": _DEFAULT_EMBEDDING_MODEL_ID})
    return doc.get("model_id") if doc else None


async def set_default_embedding_model(model_id: str) -> None:
    await system_settings.update_one({"_id": _DEFAULT_EMBEDDING_MODEL_ID}, {"$set": {"model_id": model_id}}, upsert=True)


# Routes investigate_incident() (rag.py) through app/investigation_pipeline.py's staged
# rule-health + verdict agents instead of its own single prompt. Off by default — it roughly
# doubles AI-generation cost/latency per incident (two model calls instead of one), so an admin
# opts in deliberately rather than it silently changing behavior (and cost) on upgrade.
_MULTI_AGENT_INVESTIGATION_ID = "multi_agent_investigation"


async def is_multi_agent_investigation_enabled() -> bool:
    doc = await system_settings.find_one({"_id": _MULTI_AGENT_INVESTIGATION_ID})
    return bool(doc and doc.get("enabled"))


async def set_multi_agent_investigation_enabled(enabled: bool) -> None:
    await system_settings.update_one({"_id": _MULTI_AGENT_INVESTIGATION_ID}, {"$set": {"enabled": enabled}}, upsert=True)


# Monthly ceiling (USD) on AI-generation spend (ai_usage.month_to_date_cost()), checked by
# scheduler.py's auto_investigate_cases before each tick. None means no cap — the default,
# since this is an opt-in safety valve, not a default-on restriction nobody asked for.
_MONTHLY_BUDGET_CAP_ID = "monthly_budget_cap_usd"


async def get_monthly_budget_cap() -> float | None:
    doc = await system_settings.find_one({"_id": _MONTHLY_BUDGET_CAP_ID})
    return doc.get("amount") if doc else None


async def set_monthly_budget_cap(amount: float | None) -> None:
    await system_settings.update_one({"_id": _MONTHLY_BUDGET_CAP_ID}, {"$set": {"amount": amount}}, upsert=True)


# The model investigate_incident() routes a mechanically-simple case to instead of the admin
# default (rag.py: a vulnerability/CVE-match alert, or one with a close confirmed-disposition
# precedent for its rule) — None means no routing, every case uses the default model, same as
# before this existed.
_CHEAP_AI_MODEL_ID = "cheap_ai_model"


async def get_cheap_ai_model() -> str | None:
    doc = await system_settings.find_one({"_id": _CHEAP_AI_MODEL_ID})
    return doc.get("model_id") if doc else None


async def set_cheap_ai_model(model_id: str | None) -> None:
    await system_settings.update_one({"_id": _CHEAP_AI_MODEL_ID}, {"$set": {"model_id": model_id}}, upsert=True)


# Routes investigate_incident()'s single-prompt path (rag.py) through Bedrock's schema-constrained
# tool-use instead of freeform-text + regex parsing, when the resolved model is Claude-on-Bedrock.
# Off by default — this touches the already-tested core investigation prompt, so an admin opts in
# deliberately and is expected to validate with the eval harness before relying on it.
_STRUCTURED_OUTPUT_ID = "structured_output"


async def is_structured_output_enabled() -> bool:
    doc = await system_settings.find_one({"_id": _STRUCTURED_OUTPUT_ID})
    return bool(doc and doc.get("enabled"))


async def set_structured_output_enabled(enabled: bool) -> None:
    await system_settings.update_one({"_id": _STRUCTURED_OUTPUT_ID}, {"$set": {"enabled": enabled}}, upsert=True)

"""Enriches a freshly-correlated case with threat intel and org-docs instance/client context —
once, right after correlation and before the case reaches the AI investigation queue (see
app/scheduler.py's enrich_new_cases job, which is what actually enforces that ordering).

This deliberately lives in the backend, not in correlator/correlator.py: that service is kept to
plain MongoDB with zero network/AI dependencies by design (its lookup_asset() reads a cache the
backend pre-populates instead of calling AWS live) — threat intel and org-docs RAG both need live
network/AI calls, which don't belong in that fast, dependency-free poll loop.
"""
import json
import logging
import time

from app.db import db
from app import threat_intel
from app.rag import embed_text, _generate, _retrieve_context

logger = logging.getLogger("soc.case_enrichment")

org_context_cache = db["org_context_cache"]
incidents = db["incidents"]
# An instance/client mapping for a given host doesn't change cycle to cycle, so this avoids
# re-running the RAG + AI extraction on every enrichment pass for a long-running case.
_ORG_CONTEXT_CACHE_TTL_SECONDS = 24 * 60 * 60

EXTRACTION_PROMPT = """You extract the instance name and client name for a specific host from
organizational documentation excerpts, if present.

Host identifiers to match against: {identifiers}

Organizational knowledge excerpts:
{context}

Respond with ONLY a JSON object in exactly this shape, no other text:
{{"instance_name": "<name or null>", "client_name": "<name or null>"}}

Use null (not the string "none"/"n/a"/"unknown") for either field if the excerpts don't clearly
identify it for this specific host.
"""


def _normalize_ip(ip: str) -> str:
    return ip.strip().lower()


def _extract_json_object(text: str) -> dict:
    # Kept as its own copy rather than importing exclusion_rules.py's version of this — this
    # codebase doesn't share small private helpers across modules (see asset_cache.py's
    # _normalize_ip for the same reasoning), and it's a one-line rule to keep in sync if it ever
    # needs to change.
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found in model output")
    return json.loads(text[start:end + 1])


def _case_identifiers(case: dict) -> list[str]:
    """Everything about this case that might identify it in an org doc — the host's own IP plus
    every distinct agent hostname seen across its folded-in alerts (correlator.py's
    merge_unique_values already aggregated this at correlation time, no extra lookup needed)."""
    identifiers = []
    source_ip = case.get("source_ip")
    if source_ip and source_ip != "unknown":
        identifiers.append(source_ip)
    identifiers.extend((case.get("unique_values") or {}).get("agent.name") or [])
    return identifiers


async def _lookup_org_context(case: dict) -> dict:
    identifiers = _case_identifiers(case)
    if not identifiers:
        return {"instance_name": None, "client_name": None}

    query = "instance " + " ".join(identifiers)
    try:
        embedding = await embed_text(query)
        context, _, _, _ = _retrieve_context(embedding, n_results=3)
    except Exception:
        logger.warning("Could not retrieve org knowledge for case enrichment; skipping instance/client lookup", exc_info=True)
        return {"instance_name": None, "client_name": None}

    if not context.strip():
        return {"instance_name": None, "client_name": None}

    try:
        gen = await _generate(EXTRACTION_PROMPT.format(identifiers=", ".join(identifiers), context=context))
        parsed = _extract_json_object(gen["text"])
        instance_name = parsed.get("instance_name")
        client_name = parsed.get("client_name")
        return {
            "instance_name": instance_name if isinstance(instance_name, str) and instance_name.strip() else None,
            "client_name": client_name if isinstance(client_name, str) and client_name.strip() else None,
        }
    except Exception:
        logger.warning("Could not extract instance/client name from org docs for case enrichment", exc_info=True)
        return {"instance_name": None, "client_name": None}


async def get_org_context(case: dict) -> dict:
    """Cached (24h) by source_ip. A "nothing found" result is cached too — a host with no
    matching org doc isn't re-queried (and re-billed in AI-generation time) every cycle either."""
    source_ip = case.get("source_ip")
    cache_key = _normalize_ip(source_ip) if source_ip else None

    if cache_key:
        cached = await org_context_cache.find_one({"_id": cache_key})
        if cached and time.time() - cached.get("cached_at", 0) < _ORG_CONTEXT_CACHE_TTL_SECONDS:
            return {"instance_name": cached.get("instance_name"), "client_name": cached.get("client_name")}

    result = await _lookup_org_context(case)

    if cache_key:
        await org_context_cache.update_one(
            {"_id": cache_key},
            {"$set": {**result, "cached_at": time.time()}},
            upsert=True,
        )
    return result


async def backfill_legacy_cases() -> int:
    """One-time migration for the deploy where case enrichment first ships: every case that
    already existed is missing "enrichment" entirely, which would otherwise queue it (one per
    enrich_new_cases tick, see app/scheduler.py) ahead of genuinely new cases — and, worse, burn
    through threat-intel's rate-limited quota (VirusTotal: 4/min) re-checking alerts nobody's
    actively reviewing anymore. Marks them as skipped instead of enriching for real; the incident
    detail/list views already render a missing threat_intel/org_context as "no data", so this is
    a no-op for their display, same as before this feature existed. Idempotent — only ever
    targets cases still missing "enrichment", so running it again on an already-migrated
    database (the normal case, every restart after the first) does nothing.
    """
    result = await incidents.update_many(
        {"enrichment": {"$exists": False}},
        {"$set": {"enrichment": {"skipped": True, "reason": "existed before case enrichment was introduced"}}},
    )
    if result.modified_count:
        logger.info("Backfilled %d pre-existing case(s) as enrichment-skipped", result.modified_count)
    return result.modified_count


async def enrich_case(case: dict) -> dict:
    """Computes both enrichment signals for a case, once. Threat intel reuses the exact same
    resolve_target_ip + lookup_all logic that used to run inline inside auto_investigate_cases —
    this only moves *when* it runs, not the logic itself (lookup_all's own 10-minute cache keeps
    re-enrichment on a long-running case cheap)."""
    ti_result = None
    target = threat_intel.resolve_target_ip(case)
    if target:
        try:
            ti_result = await threat_intel.lookup_all(target)
        except Exception:
            logger.info("Threat intel lookup unavailable while enriching case %s", case.get("_id"))

    org_context = await get_org_context(case)

    return {"threat_intel": ti_result, "org_context": org_context}

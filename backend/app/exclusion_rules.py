"""Alert exclusion rules — an analyst describes, in plain language, alerts that should never
become incidents (a known noisy health check, a scanner IP that's actually authorized, etc).
The AI runs ONCE, at rule-save time, to translate that description into a small structured
filter (field/operator/value). From then on the correlator checks every incoming alert against
that structured filter directly — a fast dict-field comparison, not a live model call — since
a live call per alert would bottleneck ingestion (and rack up real per-token Bedrock cost) at
any real volume. If the model's output can't be parsed into something usable, this falls back to a plain
substring match against the rule description itself, so a rule is never silently a no-op.
"""
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.db import db
from app.rag import _generate

logger = logging.getLogger("soc.exclusion_rules")

exclusion_rules = db["exclusion_rules"]

# Kept intentionally small — a field/operator vocabulary a 3-4B CPU model can reliably pick
# from, matched by both the correlator (Python) and this structuring prompt.
ALLOWED_FIELDS = ["rule.description", "rule.id", "agent.name", "agent.ip", "source_ip", "mitre.tactic"]
ALLOWED_OPERATORS = ["contains", "equals"]

STRUCTURING_PROMPT = """You turn a security analyst's plain-language description of alerts to
ignore into a strict JSON filter.

Allowed fields: {fields}
Allowed operators: {operators}
- "source_ip" is the alert's source IP address.
- "mitre.tactic" matches against the alert's MITRE ATT&CK tactic(s).
- Use "contains" for partial/substring matches, "equals" for an exact match.

Analyst's description:
{description}

Respond with ONLY a JSON object in exactly this shape, no other text:
{{"criteria": [{{"field": "<one of the allowed fields>", "operator": "<contains|equals>", "value": "<text to match>"}}]}}

Only include a criterion for a condition the analyst actually mentioned — do NOT list every
allowed field with a placeholder like "none"/"n/a"/"unknown" for the ones they didn't mention.
A criterion with a made-up placeholder value would never match anything and silently make the
whole rule useless. All conditions you do include must match together (AND) for an alert to be
excluded. If the description doesn't clearly map to any allowed field, do your best with
"rule.description" using the analyst's own key phrase as the value.
"""


def _extract_json_object(text: str) -> dict:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found in model output")
    return json.loads(text[start:end + 1])


def _fallback_criteria(description: str) -> list[dict]:
    return [{"field": "rule.description", "operator": "contains", "value": description.strip()}]


async def structure_criteria(description: str) -> list[dict]:
    prompt = STRUCTURING_PROMPT.format(
        fields=", ".join(ALLOWED_FIELDS), operators=", ".join(ALLOWED_OPERATORS), description=description.strip(),
    )
    try:
        raw = await _generate(prompt)
        parsed = _extract_json_object(raw)
        cleaned = []
        for c in parsed.get("criteria", []):
            if not isinstance(c, dict) or c.get("field") not in ALLOWED_FIELDS:
                continue
            value = str(c.get("value", "")).strip()
            # A small model asked to fill in every field it was shown often does exactly that —
            # emitting the literal text "none"/"n/a"/"null" for fields the analyst never
            # mentioned, rather than omitting them. Those aren't real values: keeping one would
            # AND in a condition that can never match (e.g. source_ip equals "None"), silently
            # making the whole rule impossible to ever trigger.
            if not value or value.lower() in ("none", "n/a", "na", "null", "unknown", "-"):
                continue
            cleaned.append({
                "field": c["field"],
                "operator": c["operator"] if c.get("operator") in ALLOWED_OPERATORS else "contains",
                "value": value,
            })
        if cleaned:
            return cleaned
        logger.warning("AI exclusion structuring produced no usable criteria; falling back to keyword match")
    except Exception:
        logger.warning("Could not AI-structure exclusion rule; falling back to keyword match", exc_info=True)
    return _fallback_criteria(description)


def _describe_criteria(criteria: list[dict]) -> str:
    """Builds a human-readable label for a rule created from structured fields directly, so the
    list view always has something to show even when no free-text description was given."""
    return " AND ".join(f'{c["field"]} {c["operator"]} "{c["value"]}"' for c in criteria)


async def create_rule(
    description: Optional[str], created_by: str, *,
    rule_id: Optional[str] = None, rule_description: Optional[str] = None,
    ip: Optional[str] = None, ip_field: str = "source_ip",
) -> dict:
    """Structured mode (any of rule_id/rule_description/ip given) builds criteria directly and
    skips the AI call entirely — exact control for an analyst who already knows which field they
    want to match, rather than trusting a plain-language description to be interpreted correctly.
    Falls back to the AI-structuring path only when none of those are given, i.e. description
    alone (unchanged from before this mode existed).
    """
    manual_criteria = []
    if rule_id and rule_id.strip():
        manual_criteria.append({"field": "rule.id", "operator": "equals", "value": rule_id.strip()})
    if rule_description and rule_description.strip():
        manual_criteria.append({"field": "rule.description", "operator": "contains", "value": rule_description.strip()})
    if ip and ip.strip():
        manual_criteria.append({"field": ip_field, "operator": "equals", "value": ip.strip()})

    if manual_criteria:
        criteria = manual_criteria
        ai_structured = False
        label = (description or "").strip() or _describe_criteria(criteria)
    else:
        label = (description or "").strip()
        criteria = await structure_criteria(label)
        ai_structured = criteria != _fallback_criteria(label)

    doc = {
        "_id": str(uuid.uuid4()),
        "description": label,
        "criteria": criteria,
        "active": True,
        "ai_structured": ai_structured,
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await exclusion_rules.insert_one(doc)
    return doc

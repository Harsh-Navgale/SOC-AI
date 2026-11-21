"""Option-B multi-agent investigation: splits rag.py's investigate_incident() single prompt
into a deterministic digest step plus two focused AI calls, each passing its output to the
next, instead of one prompt doing everything at once:

    1. _build_digest()        - no LLM call; formats every enrichment source the single-prompt
                                 path already used (threat intel, risk, asset, org context,
                                 unique values, precedents) into the same text blocks, gathered
                                 once so both agents below read the identical inputs.
    2. _run_rule_health_stage - one focused call judging only the triggering RULE, given the
                                 digest's precedents and alert-field patterns.
    3. _run_verdict_stage     - the final verdict/report call, informed by stage 2's rule-health
                                 opinion instead of judging it inline.

Toggled by pipeline_settings.is_multi_agent_investigation_enabled(); rag.py.investigate_incident()
picks this path or its own single-prompt path based on that setting. The returned dict has the
same keys either way, plus an additive "pipeline_stages" list for debugging.
"""
import logging

from app.ai_usage import estimate_cost
from app.rag import (
    _generate,
    _wrap_untrusted,
    _UNTRUSTED_DATA_NOTICE,
    _incident_summary,
    _asset_summary,
    _risk_summary,
    _org_context_summary,
    _unique_values_summary,
    _threat_intel_summary,
    _parse_investigation,
)

logger = logging.getLogger("soc.investigation_pipeline")


def _build_digest(threat_intel, asset, risk, unique_values, org_context, precedent_blocks, generic_blocks) -> dict:
    return {
        "unique_values_text": _unique_values_summary(unique_values),
        "threat_intel_text": _threat_intel_summary(threat_intel),
        "asset_text": _asset_summary(asset),
        "org_context_text": _org_context_summary(org_context),
        "risk_text": _risk_summary(risk),
        "precedents_text": "\n\n".join(precedent_blocks) or "(none found)",
        "generic_knowledge_text": "\n\n".join(generic_blocks) or "(none found)",
    }


async def _run_rule_health_stage(incident: dict, digest: dict, model: str | None = None) -> dict:
    prompt = f"""You are a SOC analyst assistant assessing whether a Wazuh detection RULE is well
calibrated — separate from judging any specific alert.
{_UNTRUSTED_DATA_NOTICE}

Rule: {incident.get('rule_description')}

Distinct alert-field values seen across this case:
{_wrap_untrusted("alert-field-values", digest["unique_values_text"])}

Confirmed-disposition precedents for this same rule (human-confirmed ground truth — weigh a
close match heavily, but it's evidence about those past cases, not this one):
{_wrap_untrusted("confirmed-case-precedents", digest["precedents_text"])}

Does this rule look poorly calibrated (fires on benign/expected behavior, duplicates a more
useful rule, threshold too sensitive)? This is a secondary, unconfirmed opinion meant to flag
tuning candidates — it is not a finding about any specific alert, and no human has verified it.

Respond in EXACTLY this format, one field per line:
Rule health: <likely_miscalibrated|appears_sound|insufficient_data>
Rule health reasoning: <one sentence>
"""
    gen = await _generate(prompt, model=model)
    parsed = _parse_investigation(gen["text"])
    return {
        "rule_health": parsed["rule_health"],
        "rule_health_reasoning": parsed["rule_health_reasoning"],
        "raw": gen["text"].strip(),
        "prompt": prompt,
        "model_used": gen["model_used"],
        "prompt_tokens": gen["prompt_tokens"],
        "completion_tokens": gen["completion_tokens"],
    }


async def _run_verdict_stage(
    incident: dict, digest: dict, rule_health: dict | None, model: str | None = None
) -> tuple[dict, dict, str]:
    rule_health_line = (
        f"Rule-health assessment from a separate specialized check (treat as context, it is not "
        f"your own finding): {rule_health['rule_health'] or 'insufficient_data'} — "
        f"{rule_health['rule_health_reasoning'] or '(no reasoning given)'}"
        if rule_health else "Rule-health assessment: not applicable for this alert type."
    )

    prompt = f"""You are a SOC analyst assistant producing a structured investigation report for a security incident.
{_UNTRUSTED_DATA_NOTICE}

Incident details:
{_incident_summary(incident)}

Distinct values observed across every alert folded into this case (ground your analysis in
this, not just the rule's generic description):
{_wrap_untrusted("alert-field-values", digest["unique_values_text"])}

Threat intelligence for {incident.get('source_ip')}:
{_wrap_untrusted("threat-intel", digest["threat_intel_text"])}

Known asset info for this IP (from the S3 inventory):
{digest["asset_text"]}

Known instance/client info (from org docs):
{_wrap_untrusted("org-context", digest["org_context_text"])}

Computed risk score for this incident:
{digest["risk_text"]}

Similar past confirmed-disposition cases (human-confirmed ground truth for a specific past case —
weigh a close match heavily, but it is evidence about that past case, not a guarantee this one is
identical):
{_wrap_untrusted("confirmed-case-precedents", digest["precedents_text"])}

Relevant organizational knowledge/playbooks (generic guidance, not case-specific precedent):
{_wrap_untrusted("org-knowledge", digest["generic_knowledge_text"])}

{rule_health_line}

Weigh the threat intelligence heavily: a source IP with real malicious findings (VirusTotal
detections, high AbuseIPDB confidence, URLhaus/ThreatFox hits) should raise your severity and
confidence, while a clean or unavailable result should not by itself be treated as reassuring.
If the asset info identifies a known, named host, treat this as a real asset in our environment
and weigh potential business impact accordingly. If the instance/client info identifies a
specific client, factor that into Impact and Owning team. If a confirmed-disposition precedent
above closely matches this case's rule and pattern, say so explicitly in Probable cause or
Summary — but still form your own Verdict from this case's own evidence; do not copy a
precedent's disposition without justification.

Decide whether this is a real attack, noise, or expected internal behavior (Verdict), and
whether it originated from outside our network or from something internal like a
misconfiguration, routine internal traffic, or an insider (Origin). Escalate is a hard yes/no:
say yes only if this needs a human paged right now, independent of the Severity/Priority scale.

Respond in EXACTLY this format, one field per line:
Severity: <low|medium|high|critical>
Confidence: <low|medium|high>
Verdict: <true_positive|false_positive|benign_positive|needs_review>
Origin: <external|internal|unknown>
Escalate: <yes|no>
Category: <brute_force|malware|recon|exfiltration|misconfiguration|policy_violation|other>
Owning team: <Network/Perimeter Security|Identity & Access|Endpoint/EDR|Application/Dev|Cloud/Infra|IT Helpdesk|No action needed>
Impact: <one sentence>
Priority: <low|medium|high|urgent>
Probable cause: <one to two sentences on what likely caused this>
Summary: <two to three sentences>
Recommended actions:
- <action 1>
- <action 2>
- <action 3>
"""
    gen = await _generate(prompt, model=model)
    parsed = _parse_investigation(gen["text"])
    return parsed, gen, prompt


async def run(
    incident: dict, threat_intel: dict | None, asset: dict | None, risk: dict | None,
    unique_values: dict | None, org_context: dict | None,
    precedent_blocks: list[str], generic_blocks: list[str],
    model: str | None = None,
) -> dict:
    is_vuln = bool(incident.get("is_vulnerability_alert"))
    digest = _build_digest(threat_intel, asset, risk, unique_values, org_context, precedent_blocks, generic_blocks)

    rule_health_result = None if is_vuln else await _run_rule_health_stage(incident, digest, model=model)
    verdict_parsed, verdict_gen, verdict_prompt = await _run_verdict_stage(incident, digest, rule_health_result, model=model)

    parsed = dict(verdict_parsed)
    parsed["rule_health"] = rule_health_result["rule_health"] if rule_health_result else None
    parsed["rule_health_reasoning"] = rule_health_result["rule_health_reasoning"] if rule_health_result else None

    # Costed per stage, not as one combined token count against only the verdict stage's
    # model — _generate()'s cross-provider fallback means the two stages can legitimately
    # resolve to different models/providers with different $/token rates, and pricing the
    # combined total at only one of them would silently misreport AI spend.
    stages = []
    total_cost = estimate_cost(verdict_gen["prompt_tokens"], verdict_gen["completion_tokens"], verdict_gen["model_used"])
    prompt_tokens = verdict_gen["prompt_tokens"]
    completion_tokens = verdict_gen["completion_tokens"]
    if rule_health_result:
        stages.append({
            "stage": "rule_health", "raw": rule_health_result["raw"], "prompt": rule_health_result["prompt"],
            "model_used": rule_health_result["model_used"],
            "prompt_tokens": rule_health_result["prompt_tokens"], "completion_tokens": rule_health_result["completion_tokens"],
        })
        prompt_tokens += rule_health_result["prompt_tokens"]
        completion_tokens += rule_health_result["completion_tokens"]
        total_cost += estimate_cost(
            rule_health_result["prompt_tokens"], rule_health_result["completion_tokens"], rule_health_result["model_used"]
        )
    stages.append({
        "stage": "verdict", "raw": verdict_gen["text"].strip(), "prompt": verdict_prompt,
        "model_used": verdict_gen["model_used"],
        "prompt_tokens": verdict_gen["prompt_tokens"], "completion_tokens": verdict_gen["completion_tokens"],
    })

    parse_ok = bool(parsed.get("severity") and parsed.get("summary"))
    # Separate from parse_ok (which only tracks the verdict stage's severity/summary): a rule
    # health line that comes back unparsed collapses to the same `rule_health: None` a model
    # legitimately saying "insufficient_data" would never produce (that's a normal enum value,
    # not a parse failure) — this flag makes the two distinguishable instead of silently equal.
    rule_health_parse_ok = None if rule_health_result is None else parsed.get("rule_health") is not None
    return {
        "raw": verdict_gen["text"].strip(),
        **parsed,
        "prompt": "\n\n---\n\n".join(f"[{s['stage']}]\n{s['prompt']}" for s in stages),
        "model_used": verdict_gen["model_used"],
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "estimated_cost": total_cost,
        "parse_ok": parse_ok,
        "rule_health_parse_ok": rule_health_parse_ok,
        "pipeline_stages": stages,
    }

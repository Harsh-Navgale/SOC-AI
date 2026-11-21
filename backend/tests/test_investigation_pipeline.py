import asyncio

from app import investigation_pipeline


INCIDENT = {"_id": "inc-1", "source_ip": "1.2.3.4", "rule_description": "Listened ports changed", "alert_count": 1, "max_level": 5, "mitre_tactics": []}
VULN_INCIDENT = {**INCIDENT, "is_vulnerability_alert": True}


# ---- _build_digest: deterministic, no LLM call ----

def test_build_digest_formats_precedents_and_generic_blocks_separately():
    digest = investigation_pipeline._build_digest(
        None, None, None, None, None,
        precedent_blocks=["[Confirmed false_positive precedent] old case"],
        generic_blocks=["generic playbook text"],
    )
    assert digest["precedents_text"] == "[Confirmed false_positive precedent] old case"
    assert digest["generic_knowledge_text"] == "generic playbook text"


def test_build_digest_defaults_empty_blocks_to_none_found():
    digest = investigation_pipeline._build_digest(None, None, None, None, None, [], [])
    assert digest["precedents_text"] == "(none found)"
    assert digest["generic_knowledge_text"] == "(none found)"


# ---- _run_rule_health_stage ----

def test_rule_health_stage_parses_the_two_expected_fields(monkeypatch):
    async def fake_generate(prompt, model=None):
        return {
            "text": "Rule health: likely_miscalibrated\nRule health reasoning: fires on routine maintenance\n",
            "model_used": "m", "prompt_tokens": 10, "completion_tokens": 5,
        }

    monkeypatch.setattr(investigation_pipeline, "_generate", fake_generate)
    digest = investigation_pipeline._build_digest(None, None, None, None, None, [], [])

    result = asyncio.run(investigation_pipeline._run_rule_health_stage(INCIDENT, digest))

    assert result["rule_health"] == "likely_miscalibrated"
    assert result["rule_health_reasoning"] == "fires on routine maintenance"
    assert result["prompt_tokens"] == 10 and result["completion_tokens"] == 5


def test_rule_health_stage_prompt_includes_the_precedents_block(monkeypatch):
    captured = {}

    async def fake_generate(prompt, model=None):
        captured["prompt"] = prompt
        return {"text": "Rule health: appears_sound\nRule health reasoning: fine\n", "model_used": "m", "prompt_tokens": 1, "completion_tokens": 1}

    monkeypatch.setattr(investigation_pipeline, "_generate", fake_generate)
    digest = investigation_pipeline._build_digest(None, None, None, None, None, ["[Confirmed true_positive precedent] prior case"], [])

    asyncio.run(investigation_pipeline._run_rule_health_stage(INCIDENT, digest))

    assert "[Confirmed true_positive precedent] prior case" in captured["prompt"]
    assert "Wazuh detection RULE" in captured["prompt"]


# ---- _run_verdict_stage ----

def test_verdict_stage_includes_rule_health_context_when_given(monkeypatch):
    captured = {}

    async def fake_generate(prompt, model=None):
        captured["prompt"] = prompt
        return {"text": "Severity: high\nSummary: bad\nRecommended actions:\n- x\n", "model_used": "m", "prompt_tokens": 1, "completion_tokens": 1}

    monkeypatch.setattr(investigation_pipeline, "_generate", fake_generate)
    digest = investigation_pipeline._build_digest(None, None, None, None, None, [], [])
    rule_health = {"rule_health": "likely_miscalibrated", "rule_health_reasoning": "too sensitive"}

    asyncio.run(investigation_pipeline._run_verdict_stage(INCIDENT, digest, rule_health))

    assert "likely_miscalibrated — too sensitive" in captured["prompt"]
    assert "Rule health:" not in captured["prompt"]  # the verdict stage doesn't ask for this field itself


def test_verdict_stage_notes_rule_health_not_applicable_when_none(monkeypatch):
    captured = {}

    async def fake_generate(prompt, model=None):
        captured["prompt"] = prompt
        return {"text": "Severity: high\nSummary: bad\nRecommended actions:\n- x\n", "model_used": "m", "prompt_tokens": 1, "completion_tokens": 1}

    monkeypatch.setattr(investigation_pipeline, "_generate", fake_generate)
    digest = investigation_pipeline._build_digest(None, None, None, None, None, [], [])

    asyncio.run(investigation_pipeline._run_verdict_stage(INCIDENT, digest, None))

    assert "not applicable for this alert type" in captured["prompt"]


# ---- run(): full orchestration ----

def test_run_calls_both_stages_and_merges_rule_health_into_the_final_result(monkeypatch):
    calls = []

    async def fake_generate(prompt, model=None):
        calls.append(prompt)
        if "Wazuh detection RULE is well" in prompt:
            return {"text": "Rule health: appears_sound\nRule health reasoning: fine\n", "model_used": "m", "prompt_tokens": 10, "completion_tokens": 5}
        return {"text": "Severity: high\nSummary: bad\nRecommended actions:\n- x\n", "model_used": "m", "prompt_tokens": 20, "completion_tokens": 8}

    monkeypatch.setattr(investigation_pipeline, "_generate", fake_generate)

    result = asyncio.run(investigation_pipeline.run(INCIDENT, None, None, None, None, None, [], []))

    assert len(calls) == 2  # rule-health stage + verdict stage
    assert result["rule_health"] == "appears_sound"
    assert result["severity"] == "high"
    assert result["prompt_tokens"] == 30 and result["completion_tokens"] == 13
    assert [s["stage"] for s in result["pipeline_stages"]] == ["rule_health", "verdict"]


def test_run_skips_the_rule_health_stage_for_vulnerability_alerts(monkeypatch):
    calls = []

    async def fake_generate(prompt, model=None):
        calls.append(prompt)
        return {"text": "Severity: high\nSummary: bad\nRecommended actions:\n- x\n", "model_used": "m", "prompt_tokens": 20, "completion_tokens": 8}

    monkeypatch.setattr(investigation_pipeline, "_generate", fake_generate)

    result = asyncio.run(investigation_pipeline.run(VULN_INCIDENT, None, None, None, None, None, [], []))

    assert len(calls) == 1  # only the verdict stage ran
    assert result["rule_health"] is None
    assert result["rule_health_reasoning"] is None
    assert [s["stage"] for s in result["pipeline_stages"]] == ["verdict"]


def test_run_marks_parse_ok_false_when_the_model_ignores_the_format(monkeypatch):
    async def fake_generate(prompt, model=None):
        return {"text": "not the expected format at all", "model_used": "m", "prompt_tokens": 1, "completion_tokens": 1}

    monkeypatch.setattr(investigation_pipeline, "_generate", fake_generate)

    result = asyncio.run(investigation_pipeline.run(VULN_INCIDENT, None, None, None, None, None, [], []))

    assert result["parse_ok"] is False


def test_run_threads_an_explicit_model_override_into_both_stages(monkeypatch):
    seen_models = []

    async def fake_generate(prompt, model=None):
        seen_models.append(model)
        if "Wazuh detection RULE is well" in prompt:
            return {"text": "Rule health: appears_sound\nRule health reasoning: fine\n", "model_used": model or "m", "prompt_tokens": 1, "completion_tokens": 1}
        return {"text": "Severity: low\nSummary: ok\nRecommended actions:\n- x\n", "model_used": model or "m", "prompt_tokens": 1, "completion_tokens": 1}

    monkeypatch.setattr(investigation_pipeline, "_generate", fake_generate)

    asyncio.run(investigation_pipeline.run(INCIDENT, None, None, None, None, None, [], [], model="bedrock:amazon.nova-micro-v1:0"))

    assert seen_models == ["bedrock:amazon.nova-micro-v1:0", "bedrock:amazon.nova-micro-v1:0"]

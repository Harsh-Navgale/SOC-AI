import asyncio

from app import case_enrichment
from app import threat_intel as threat_intel_module


# ---- _case_identifiers ----

def test_case_identifiers_includes_source_ip():
    assert case_enrichment._case_identifiers({"source_ip": "10.1.2.3"}) == ["10.1.2.3"]


def test_case_identifiers_excludes_unknown_source_ip():
    assert case_enrichment._case_identifiers({"source_ip": "unknown"}) == []


def test_case_identifiers_includes_agent_names_from_unique_values():
    case = {"source_ip": "10.1.2.3", "unique_values": {"agent.name": ["web-01", "web-02"]}}
    assert case_enrichment._case_identifiers(case) == ["10.1.2.3", "web-01", "web-02"]


def test_case_identifiers_empty_case_returns_empty_list():
    assert case_enrichment._case_identifiers({}) == []


# ---- org-context lookup (RAG + one-shot AI extraction) ----

def test_lookup_org_context_returns_nulls_and_skips_rag_when_no_identifiers(monkeypatch):
    async def boom_embed(text):
        raise AssertionError("embed_text must not be called with no identifiers to search for")

    monkeypatch.setattr(case_enrichment, "embed_text", boom_embed)

    result = asyncio.run(case_enrichment._lookup_org_context({}))
    assert result == {"instance_name": None, "client_name": None}


def test_lookup_org_context_extracts_instance_and_client_from_retrieved_context(monkeypatch):
    async def fake_embed_text(text):
        return [0.1]

    def fake_retrieve_context(embedding, n_results=3):
        return "Instance ip-10-1-2-3 belongs to client Acme Corp.", ["org_docs/instances.md"], ["..."], []

    async def fake_generate(prompt, model=None):
        return {"text": '{"instance_name": "ip-10-1-2-3", "client_name": "Acme Corp"}', "model_used": "m", "prompt_tokens": 1, "completion_tokens": 1}

    monkeypatch.setattr(case_enrichment, "embed_text", fake_embed_text)
    monkeypatch.setattr(case_enrichment, "_retrieve_context", fake_retrieve_context)
    monkeypatch.setattr(case_enrichment, "_generate", fake_generate)

    result = asyncio.run(case_enrichment._lookup_org_context({"source_ip": "10.1.2.3"}))
    assert result == {"instance_name": "ip-10-1-2-3", "client_name": "Acme Corp"}


def test_lookup_org_context_returns_nulls_when_retrieved_context_is_empty(monkeypatch):
    async def fake_embed_text(text):
        return [0.1]

    def fake_retrieve_context(embedding, n_results=3):
        return "", [], [], []

    async def boom_generate(prompt, model=None):
        raise AssertionError("must not ask the model to extract from empty context")

    monkeypatch.setattr(case_enrichment, "embed_text", fake_embed_text)
    monkeypatch.setattr(case_enrichment, "_retrieve_context", fake_retrieve_context)
    monkeypatch.setattr(case_enrichment, "_generate", boom_generate)

    result = asyncio.run(case_enrichment._lookup_org_context({"source_ip": "10.1.2.3"}))
    assert result == {"instance_name": None, "client_name": None}


def test_lookup_org_context_falls_back_to_nulls_on_unparseable_model_output(monkeypatch):
    async def fake_embed_text(text):
        return [0.1]

    def fake_retrieve_context(embedding, n_results=3):
        return "some org doc text", [], [], []

    async def fake_generate(prompt, model=None):
        return {"text": "not json at all", "model_used": "m", "prompt_tokens": 1, "completion_tokens": 1}

    monkeypatch.setattr(case_enrichment, "embed_text", fake_embed_text)
    monkeypatch.setattr(case_enrichment, "_retrieve_context", fake_retrieve_context)
    monkeypatch.setattr(case_enrichment, "_generate", fake_generate)

    result = asyncio.run(case_enrichment._lookup_org_context({"source_ip": "10.1.2.3"}))
    assert result == {"instance_name": None, "client_name": None}


def test_lookup_org_context_treats_placeholder_strings_as_null(monkeypatch):
    async def fake_embed_text(text):
        return [0.1]

    def fake_retrieve_context(embedding, n_results=3):
        return "some org doc text", [], [], []

    async def fake_generate(prompt, model=None):
        return {"text": '{"instance_name": null, "client_name": "Acme Corp"}', "model_used": "m", "prompt_tokens": 1, "completion_tokens": 1}

    monkeypatch.setattr(case_enrichment, "embed_text", fake_embed_text)
    monkeypatch.setattr(case_enrichment, "_retrieve_context", fake_retrieve_context)
    monkeypatch.setattr(case_enrichment, "_generate", fake_generate)

    result = asyncio.run(case_enrichment._lookup_org_context({"source_ip": "10.1.2.3"}))
    assert result == {"instance_name": None, "client_name": "Acme Corp"}


# ---- get_org_context caching ----

def test_get_org_context_caches_by_source_ip(mock_db, monkeypatch):
    call_count = {"n": 0}

    async def fake_embed_text(text):
        call_count["n"] += 1
        return [0.1]

    def fake_retrieve_context(embedding, n_results=3):
        return "Instance web-01 belongs to client Acme.", [], [], []

    async def fake_generate(prompt, model=None):
        return {"text": '{"instance_name": "web-01", "client_name": "Acme"}', "model_used": "m", "prompt_tokens": 1, "completion_tokens": 1}

    monkeypatch.setattr(case_enrichment, "embed_text", fake_embed_text)
    monkeypatch.setattr(case_enrichment, "_retrieve_context", fake_retrieve_context)
    monkeypatch.setattr(case_enrichment, "_generate", fake_generate)

    case = {"source_ip": "10.1.2.3"}
    first = asyncio.run(case_enrichment.get_org_context(case))
    second = asyncio.run(case_enrichment.get_org_context(case))

    assert first == {"instance_name": "web-01", "client_name": "Acme"}
    assert second == first
    assert call_count["n"] == 1  # second call was a cache hit, no re-embedding


def test_get_org_context_caches_a_not_found_result_too(mock_db, monkeypatch):
    call_count = {"n": 0}

    async def fake_embed_text(text):
        call_count["n"] += 1
        return [0.1]

    def fake_retrieve_context(embedding, n_results=3):
        return "", [], [], []

    monkeypatch.setattr(case_enrichment, "embed_text", fake_embed_text)
    monkeypatch.setattr(case_enrichment, "_retrieve_context", fake_retrieve_context)

    case = {"source_ip": "10.1.2.3"}
    asyncio.run(case_enrichment.get_org_context(case))
    asyncio.run(case_enrichment.get_org_context(case))

    assert call_count["n"] == 1


def test_get_org_context_different_ips_do_not_share_a_cache_entry(mock_db, monkeypatch):
    async def fake_embed_text(text):
        return [0.1]

    def fake_retrieve_context(embedding, n_results=3):
        return "", [], [], []

    monkeypatch.setattr(case_enrichment, "embed_text", fake_embed_text)
    monkeypatch.setattr(case_enrichment, "_retrieve_context", fake_retrieve_context)

    asyncio.run(case_enrichment.get_org_context({"source_ip": "10.1.2.3"}))
    asyncio.run(case_enrichment.get_org_context({"source_ip": "10.1.2.4"}))

    count = asyncio.run(case_enrichment.org_context_cache.count_documents({}))
    assert count == 2


# ---- backfill_legacy_cases (one-time migration for a deploy where this feature is new) ----

def test_backfill_marks_pre_existing_cases_as_enrichment_skipped(mock_db):
    asyncio.run(mock_db["incidents"].insert_one({"_id": "legacy-1", "source_ip": "10.1.2.3"}))
    asyncio.run(mock_db["incidents"].insert_one({"_id": "legacy-2", "source_ip": "10.1.2.4"}))

    modified = asyncio.run(case_enrichment.backfill_legacy_cases())

    assert modified == 2
    doc = asyncio.run(mock_db["incidents"].find_one({"_id": "legacy-1"}))
    assert doc["enrichment"] == {"skipped": True, "reason": "existed before case enrichment was introduced"}
    assert "threat_intel" not in doc
    assert "org_context" not in doc


def test_backfill_leaves_already_enriched_cases_untouched(mock_db):
    asyncio.run(mock_db["incidents"].insert_one({
        "_id": "case-1", "source_ip": "10.1.2.3",
        "threat_intel": {"indicator": "10.1.2.3"}, "org_context": {"instance_name": "web-01", "client_name": "Acme"},
        "enrichment": {"enriched_at": "2026-01-01T00:00:00+00:00"},
    }))

    modified = asyncio.run(case_enrichment.backfill_legacy_cases())

    assert modified == 0
    doc = asyncio.run(mock_db["incidents"].find_one({"_id": "case-1"}))
    assert doc["threat_intel"] == {"indicator": "10.1.2.3"}


def test_backfill_is_idempotent(mock_db):
    asyncio.run(mock_db["incidents"].insert_one({"_id": "legacy-1", "source_ip": "10.1.2.3"}))

    first = asyncio.run(case_enrichment.backfill_legacy_cases())
    second = asyncio.run(case_enrichment.backfill_legacy_cases())

    assert first == 1
    assert second == 0


# ---- enrich_case ----

def test_enrich_case_combines_threat_intel_and_org_context(mock_db, monkeypatch):
    def fake_resolve(case):
        return "198.51.100.7"

    async def fake_lookup_all(indicator):
        return {"indicator": indicator, "indicator_type": "ip", "sources": {}}

    async def fake_get_org_context(case):
        return {"instance_name": "web-01", "client_name": "Acme"}

    monkeypatch.setattr(threat_intel_module, "resolve_target_ip", fake_resolve)
    monkeypatch.setattr(threat_intel_module, "lookup_all", fake_lookup_all)
    monkeypatch.setattr(case_enrichment, "get_org_context", fake_get_org_context)

    result = asyncio.run(case_enrichment.enrich_case({"_id": "case-1", "source_ip": "10.1.2.3"}))

    assert result["threat_intel"]["indicator"] == "198.51.100.7"
    assert result["org_context"] == {"instance_name": "web-01", "client_name": "Acme"}


def test_enrich_case_threat_intel_is_none_when_no_target_ip_resolves(mock_db, monkeypatch):
    def fake_resolve(case):
        return None

    async def boom_lookup_all(indicator):
        raise AssertionError("lookup_all must not be called with no target IP")

    async def fake_get_org_context(case):
        return {"instance_name": None, "client_name": None}

    monkeypatch.setattr(threat_intel_module, "resolve_target_ip", fake_resolve)
    monkeypatch.setattr(threat_intel_module, "lookup_all", boom_lookup_all)
    monkeypatch.setattr(case_enrichment, "get_org_context", fake_get_org_context)

    result = asyncio.run(case_enrichment.enrich_case({"_id": "case-1", "source_ip": "unknown"}))

    assert result["threat_intel"] is None


def test_enrich_case_threat_intel_failure_does_not_break_enrichment(mock_db, monkeypatch):
    def fake_resolve(case):
        return "198.51.100.7"

    async def failing_lookup_all(indicator):
        raise RuntimeError("threat intel APIs unreachable")

    async def fake_get_org_context(case):
        return {"instance_name": None, "client_name": None}

    monkeypatch.setattr(threat_intel_module, "resolve_target_ip", fake_resolve)
    monkeypatch.setattr(threat_intel_module, "lookup_all", failing_lookup_all)
    monkeypatch.setattr(case_enrichment, "get_org_context", fake_get_org_context)

    result = asyncio.run(case_enrichment.enrich_case({"_id": "case-1", "source_ip": "10.1.2.3"}))

    assert result["threat_intel"] is None
    assert result["org_context"] == {"instance_name": None, "client_name": None}

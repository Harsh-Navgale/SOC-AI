import asyncio
import os
from unittest.mock import MagicMock

# Force deterministic test config regardless of what a mounted .env / env_file
# provides (e.g. when this runs via `docker compose run --rm backend ...`).
os.environ["JWT_SECRET"] = "test-secret"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-password"
os.environ["MONGO_URI"] = "mongodb://localhost:27017"
os.environ["MONGO_DB"] = "soc_ai_test"
os.environ["CHROMA_HOST"] = "localhost"
os.environ["CHROMA_PORT"] = "8000"

# app.rag creates a ChromaDB HttpClient (and calls get_or_create_collection) at import
# time. Tests never exercise the AI/RAG path, so replace it with a stub before app.main
# (which imports app.rag) is ever imported.
import chromadb  # noqa: E402

chromadb.HttpClient = MagicMock(return_value=MagicMock())

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from mongomock_motor import AsyncMongoMockClient  # noqa: E402

from app.auth import hash_password  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    from app.rate_limit import clear_all
    clear_all()
    yield
    clear_all()


@pytest.fixture
def mock_db(monkeypatch):
    mock_client = AsyncMongoMockClient()
    db = mock_client["soc_ai_test"]

    monkeypatch.setattr("app.main.raw_alerts", db["raw_alerts"])
    monkeypatch.setattr("app.main.incidents", db["incidents"])
    monkeypatch.setattr("app.main.users", db["users"])
    monkeypatch.setattr("app.main.conversations", db["conversations"])
    monkeypatch.setattr("app.main.system_heartbeats", db["system_heartbeats"])
    monkeypatch.setattr("app.auth.users", db["users"])
    monkeypatch.setattr("app.audit.audit_log", db["audit_log"])
    monkeypatch.setattr("app.exclusion_rules.exclusion_rules", db["exclusion_rules"])
    monkeypatch.setattr("app.ai_usage.ai_usage_collection", db["ai_usage"])
    monkeypatch.setattr("app.notifications.notifications_collection", db["notifications"])
    monkeypatch.setattr("app.asset_cache.asset_inventory_cache", db["asset_inventory_cache"])
    monkeypatch.setattr("app.asset_cache._cache_meta", db["asset_inventory_cache_meta"])
    monkeypatch.setattr("app.case_enrichment.org_context_cache", db["org_context_cache"])
    monkeypatch.setattr("app.case_enrichment.incidents", db["incidents"])
    monkeypatch.setattr("app.rule_health.incidents", db["incidents"])
    monkeypatch.setattr("app.rule_health.rule_fp_tracking", db["rule_fp_tracking"])
    monkeypatch.setattr("app.pipeline_settings.system_settings", db["system_settings"])
    monkeypatch.setattr("app.debug_state.system_settings", db["system_settings"])
    monkeypatch.setattr("app.eval_harness.incidents", db["incidents"])
    monkeypatch.setattr("app.eval_harness.eval_reports", db["eval_reports"])

    asyncio.run(db["users"].insert_one({
        "_id": "admin",
        "password_hash": hash_password("test-password"),
        "role": "admin",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))

    return db

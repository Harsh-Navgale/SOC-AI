import asyncio

import pytest

from app import bedrock_session, bedrock_client
from app.auth import hash_password


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


@pytest.fixture(autouse=True)
def _reset():
    bedrock_session.clear_credentials()
    yield
    bedrock_session.clear_credentials()


# ---- Bedrock credentials endpoints ----

def test_bedrock_credentials_admin_only(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "alice", "password_hash": hash_password("alice-pw"), "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "alice", "alice-pw")

    resp = client.post(
        "/api/integrations/bedrock/credentials",
        json={"access_key_id": "AKIA123", "secret_access_key": "shh", "region": "us-east-1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_bedrock_credentials_set_status_clear(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}

    set_resp = client.post(
        "/api/integrations/bedrock/credentials",
        json={"access_key_id": "AKIA123", "secret_access_key": "shh", "region": "us-west-2"},
        headers=headers,
    )
    assert set_resp.status_code == 200
    assert set_resp.json()["configured"] is True

    status_resp = client.get("/api/integrations/bedrock/status", headers=headers)
    assert status_resp.json()["configured"] is True

    clear_resp = client.delete("/api/integrations/bedrock/credentials", headers=headers)
    assert clear_resp.json()["configured"] is False


def test_bedrock_api_key_admin_only(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "alice", "password_hash": hash_password("alice-pw"), "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "alice", "alice-pw")

    resp = client.post(
        "/api/integrations/bedrock/api-key",
        json={"api_key": "bedrock-api-key-abc", "region": "us-east-1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_bedrock_api_key_set_status_clear(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}

    set_resp = client.post(
        "/api/integrations/bedrock/api-key",
        json={"api_key": "bedrock-api-key-abc", "region": "us-east-1"},
        headers=headers,
    )
    assert set_resp.status_code == 200
    body = set_resp.json()
    assert body["configured"] is True
    assert body["auth_mode"] == "api_key"

    status_resp = client.get("/api/integrations/bedrock/status", headers=headers)
    assert status_resp.json()["auth_mode"] == "api_key"

    clear_resp = client.delete("/api/integrations/bedrock/credentials", headers=headers)
    assert clear_resp.json()["configured"] is False


def test_bedrock_credentials_is_a_separate_session_from_aws(client, mock_db):
    # Connecting Bedrock must not also connect (or be satisfied by) the existing AWS/S3 session —
    # that separation was the whole point of the AskUserQuestion answer this feature is built on.
    headers = {"Authorization": f"Bearer {_login(client)}"}
    client.post(
        "/api/integrations/aws/credentials",
        json={"access_key_id": "AKIA-S3", "secret_access_key": "s3-secret", "region": "us-east-1"},
        headers=headers,
    )

    bedrock_status = client.get("/api/integrations/bedrock/status", headers=headers).json()
    assert bedrock_status["configured"] is False


# ---- /api/ai/models ----

def test_ai_models_requires_bedrock_connection(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/ai/models", headers=headers)

    assert resp.status_code == 503


def test_ai_models_returns_bedrock_list_when_connected(client, mock_db, monkeypatch):
    async def fake_bedrock_models():
        return [{"model_id": "anthropic.claude-haiku-4-5-v1:0", "label": "Claude Haiku 4.5", "provider": "bedrock"}]

    monkeypatch.setattr(bedrock_client, "list_models", fake_bedrock_models)
    bedrock_session.set_credentials("AKIA123", "shh", None, "us-east-1")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/ai/models", headers=headers)

    assert resp.status_code == 200
    assert resp.json() == [{"name": "bedrock:anthropic.claude-haiku-4-5-v1:0", "label": "Claude Haiku 4.5", "provider": "bedrock"}]


def test_ai_models_503_when_bedrock_list_fails(client, mock_db, monkeypatch):
    async def boom_bedrock():
        raise RuntimeError("AWS unreachable")

    monkeypatch.setattr(bedrock_client, "list_models", boom_bedrock)
    bedrock_session.set_credentials("AKIA123", "shh", None, "us-east-1")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/ai/models", headers=headers)

    assert resp.status_code == 503


# ---- default AI model setting ----

def test_default_ai_model_setting_defaults_to_none(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/default-ai-model", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"model_id": None}


def test_admin_can_set_default_ai_model(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post(
        "/api/settings/default-ai-model",
        json={"model_id": "bedrock:anthropic.claude-haiku-4-5-v1:0"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["model_id"] == "bedrock:anthropic.claude-haiku-4-5-v1:0"

    assert client.get("/api/settings/default-ai-model", headers=headers).json() == {
        "model_id": "bedrock:anthropic.claude-haiku-4-5-v1:0",
    }


def test_non_admin_cannot_set_default_ai_model(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "alice", "password_hash": hash_password("alice-pw"), "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "alice", "alice-pw")

    resp = client.post(
        "/api/settings/default-ai-model", json={"model_id": "phi3:mini"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


# ---- fallback AI model setting ----

def test_fallback_ai_model_setting_defaults_to_none(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/fallback-ai-model", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"model_id": None}


def test_admin_can_set_fallback_ai_model(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post(
        "/api/settings/fallback-ai-model",
        json={"model_id": "bedrock:anthropic.claude-haiku-4-5-v1:0"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["model_id"] == "bedrock:anthropic.claude-haiku-4-5-v1:0"

    assert client.get("/api/settings/fallback-ai-model", headers=headers).json() == {
        "model_id": "bedrock:anthropic.claude-haiku-4-5-v1:0",
    }


def test_non_admin_cannot_set_fallback_ai_model(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "carol", "password_hash": hash_password("carol-pw"), "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "carol", "carol-pw")

    resp = client.post(
        "/api/settings/fallback-ai-model", json={"model_id": "phi3:mini"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


# ---- /api/ai/embedding-models ----

def test_ai_embedding_models_returns_empty_list_when_bedrock_not_connected(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/ai/embedding-models", headers=headers)

    assert resp.status_code == 200
    assert resp.json() == []


def test_ai_embedding_models_includes_bedrock_once_connected(client, mock_db, monkeypatch):
    async def fake_bedrock_embedding_models():
        return [{"model_id": "amazon.titan-embed-text-v2:0", "label": "Titan Text Embeddings V2", "provider": "bedrock"}]

    monkeypatch.setattr(bedrock_client, "list_embedding_models", fake_bedrock_embedding_models)
    bedrock_session.set_credentials("AKIA123", "shh", None, "us-east-1")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/ai/embedding-models", headers=headers)

    assert resp.json() == [{"name": "bedrock:amazon.titan-embed-text-v2:0", "label": "Titan Text Embeddings V2", "provider": "bedrock"}]


def test_ai_embedding_models_survives_bedrock_listing_failure(client, mock_db, monkeypatch):
    async def boom_bedrock(*a, **kw):
        raise RuntimeError("AWS unreachable")

    monkeypatch.setattr(bedrock_client, "list_embedding_models", boom_bedrock)
    bedrock_session.set_credentials("AKIA123", "shh", None, "us-east-1")
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.get("/api/ai/embedding-models", headers=headers)

    assert resp.status_code == 200
    assert resp.json() == []


# ---- default embedding model setting ----

def test_default_embedding_model_setting_defaults_to_none(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/settings/default-embedding-model", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"model_id": None}


def test_admin_can_set_default_embedding_model(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post(
        "/api/settings/default-embedding-model",
        json={"model_id": "bedrock:amazon.titan-embed-text-v2:0"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["model_id"] == "bedrock:amazon.titan-embed-text-v2:0"

    assert client.get("/api/settings/default-embedding-model", headers=headers).json() == {
        "model_id": "bedrock:amazon.titan-embed-text-v2:0",
    }


def test_non_admin_cannot_set_default_embedding_model(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "bob", "password_hash": hash_password("bob-pw"), "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "bob", "bob-pw")

    resp = client.post(
        "/api/settings/default-embedding-model", json={"model_id": "amazon.titan-embed-text-v2:0"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403

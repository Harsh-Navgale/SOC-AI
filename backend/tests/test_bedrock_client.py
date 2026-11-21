import asyncio
import os

import pytest
from botocore.exceptions import ClientError

from app import bedrock_client, bedrock_session


@pytest.fixture(autouse=True)
def _reset():
    bedrock_session.clear_credentials()
    yield
    bedrock_session.clear_credentials()


# ---- price_for ----

def test_price_for_matches_known_prefix():
    assert bedrock_client.price_for("anthropic.claude-haiku-4-5-20251001-v1:0") == (1.0, 5.0)
    assert bedrock_client.price_for("amazon.nova-micro-v1:0") == (0.035, 0.14)


def test_price_for_returns_none_for_unrecognized_model():
    assert bedrock_client.price_for("some.made-up-model-v1:0") is None


# ---- invoke ----

def test_invoke_raises_credentials_required_with_no_session():
    with pytest.raises(bedrock_client.BedrockCredentialsRequired):
        asyncio.run(bedrock_client.invoke("hello", "anthropic.claude-haiku-4-5-v1:0"))


def test_invoke_returns_generate_compatible_shape(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeRuntime:
        def converse(self, modelId, messages):
            return {
                "output": {"message": {"content": [{"text": "Hello from Bedrock"}]}},
                "usage": {"inputTokens": 42, "outputTokens": 7},
            }

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    result = asyncio.run(bedrock_client.invoke("hi there", "anthropic.claude-haiku-4-5-v1:0"))

    assert result == {
        "text": "Hello from Bedrock",
        "model_used": "anthropic.claude-haiku-4-5-v1:0",
        "prompt_tokens": 42,
        "completion_tokens": 7,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
    }


def test_invoke_joins_multiple_content_blocks(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeRuntime:
        def converse(self, modelId, messages):
            return {
                "output": {"message": {"content": [{"text": "Part one. "}, {"text": "Part two."}]}},
                "usage": {"inputTokens": 1, "outputTokens": 1},
            }

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    result = asyncio.run(bedrock_client.invoke("hi", "some-model"))
    assert result["text"] == "Part one. Part two."


def test_invoke_clears_session_and_raises_on_auth_error(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeRuntime:
        def converse(self, modelId, messages):
            raise ClientError({"Error": {"Code": "ExpiredToken", "Message": "expired"}}, "Converse")

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    with pytest.raises(bedrock_client.BedrockAuthenticationFailed):
        asyncio.run(bedrock_client.invoke("hi", "some-model"))

    assert bedrock_session.get_credentials() is None


def test_invoke_reraises_non_auth_client_errors(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeRuntime:
        def converse(self, modelId, messages):
            raise ClientError({"Error": {"Code": "ValidationException", "Message": "bad request"}}, "Converse")

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    with pytest.raises(ClientError):
        asyncio.run(bedrock_client.invoke("hi", "some-model"))
    # Not an auth failure — the session is still good, unlike the ExpiredToken case above.
    assert bedrock_session.get_credentials() is not None


# ---- prompt caching (system_text) ----

def test_invoke_sends_a_cache_point_for_a_claude_model_with_system_text(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")
    captured = {}

    class FakeRuntime:
        def converse(self, **kwargs):
            captured.update(kwargs)
            return {
                "output": {"message": {"content": [{"text": "ok"}]}},
                "usage": {"inputTokens": 1, "outputTokens": 1, "cacheReadInputTokens": 5, "cacheWriteInputTokens": 0},
            }

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    result = asyncio.run(bedrock_client.invoke("user text", "anthropic.claude-haiku-4-5-v1:0", system_text="stable instructions"))

    assert captured["system"] == [{"text": "stable instructions"}, {"cachePoint": {"type": "default"}}]
    assert captured["messages"] == [{"role": "user", "content": [{"text": "user text"}]}]
    assert result["cache_read_tokens"] == 5
    assert result["cache_write_tokens"] == 0


def test_invoke_skips_cache_point_for_a_non_claude_model(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")
    captured = {}

    class FakeRuntime:
        def converse(self, **kwargs):
            captured.update(kwargs)
            return {"output": {"message": {"content": [{"text": "ok"}]}}, "usage": {"inputTokens": 1, "outputTokens": 1}}

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    asyncio.run(bedrock_client.invoke("user text", "amazon.nova-micro-v1:0", system_text="stable instructions"))

    assert "system" not in captured  # Nova's cache support isn't verified, so no cachePoint is sent


def test_invoke_skips_cache_point_with_no_system_text(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")
    captured = {}

    class FakeRuntime:
        def converse(self, **kwargs):
            captured.update(kwargs)
            return {"output": {"message": {"content": [{"text": "ok"}]}}, "usage": {"inputTokens": 1, "outputTokens": 1}}

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    asyncio.run(bedrock_client.invoke("user text", "anthropic.claude-haiku-4-5-v1:0"))

    assert "system" not in captured


def test_invoke_retries_uncached_when_bedrock_rejects_the_cache_point(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")
    calls = []

    class FakeRuntime:
        def converse(self, **kwargs):
            calls.append(kwargs)
            if "system" in kwargs:
                raise ClientError({"Error": {"Code": "ValidationException", "Message": "cachePoint not supported"}}, "Converse")
            return {"output": {"message": {"content": [{"text": "ok, uncached"}]}}, "usage": {"inputTokens": 1, "outputTokens": 1}}

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    result = asyncio.run(bedrock_client.invoke("user text", "anthropic.claude-haiku-4-5-v1:0", system_text="stable instructions"))

    assert len(calls) == 2  # cached attempt, then the uncached retry
    assert result["text"] == "ok, uncached"


# ---- invoke_structured ----

_SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}, "required": ["verdict"]}


def test_invoke_structured_sends_tool_config_and_returns_parsed_data(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")
    captured = {}

    class FakeRuntime:
        def converse(self, **kwargs):
            captured.update(kwargs)
            return {
                "output": {"message": {"content": [{"toolUse": {"name": "submit", "input": {"verdict": "true_positive"}}}]}},
                "usage": {"inputTokens": 10, "outputTokens": 3},
            }

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    result = asyncio.run(bedrock_client.invoke_structured("analyze this", "anthropic.claude-haiku-4-5-v1:0", "submit", _SCHEMA))

    assert captured["toolConfig"] == {
        "tools": [{"toolSpec": {"name": "submit", "inputSchema": {"json": _SCHEMA}}}],
        "toolChoice": {"tool": {"name": "submit"}},
    }
    assert captured["messages"] == [{"role": "user", "content": [{"text": "analyze this"}]}]
    assert "system" not in captured
    assert result == {
        "data": {"verdict": "true_positive"},
        "model_used": "anthropic.claude-haiku-4-5-v1:0",
        "prompt_tokens": 10,
        "completion_tokens": 3,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
    }


def test_invoke_structured_raises_structured_output_failed_with_no_tool_use_block(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeRuntime:
        def converse(self, **kwargs):
            return {"output": {"message": {"content": [{"text": "I'd rather just talk about it"}]}}, "usage": {}}

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    with pytest.raises(bedrock_client.StructuredOutputFailed):
        asyncio.run(bedrock_client.invoke_structured("analyze this", "anthropic.claude-haiku-4-5-v1:0", "submit", _SCHEMA))


def test_invoke_structured_raises_structured_output_failed_on_client_error(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeRuntime:
        def converse(self, **kwargs):
            raise ClientError({"Error": {"Code": "ValidationException", "Message": "bad schema"}}, "Converse")

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    with pytest.raises(bedrock_client.StructuredOutputFailed):
        asyncio.run(bedrock_client.invoke_structured("analyze this", "anthropic.claude-haiku-4-5-v1:0", "submit", _SCHEMA))


def test_invoke_structured_carries_cache_fields_through(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeRuntime:
        def converse(self, **kwargs):
            return {
                "output": {"message": {"content": [{"toolUse": {"name": "submit", "input": {"verdict": "true_positive"}}}]}},
                "usage": {"inputTokens": 10, "outputTokens": 3, "cacheReadInputTokens": 7, "cacheWriteInputTokens": 2},
            }

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    result = asyncio.run(bedrock_client.invoke_structured(
        "analyze this", "anthropic.claude-haiku-4-5-v1:0", "submit", _SCHEMA, system_text="stable instructions",
    ))

    assert result["cache_read_tokens"] == 7
    assert result["cache_write_tokens"] == 2


# ---- list_models ----

def test_list_models_filters_to_text_output_models(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeControl:
        def list_foundation_models(self):
            return {"modelSummaries": [
                {"modelId": "anthropic.claude-haiku-4-5-v1:0", "modelName": "Claude Haiku 4.5", "outputModalities": ["TEXT"], "inferenceTypesSupported": ["ON_DEMAND"]},
                {"modelId": "amazon.titan-image-generator-v1", "modelName": "Titan Image", "outputModalities": ["IMAGE"], "inferenceTypesSupported": ["ON_DEMAND"]},
            ]}

    monkeypatch.setattr(bedrock_client, "_control_client", lambda: FakeControl())

    models = asyncio.run(bedrock_client.list_models())

    assert models == [{"model_id": "anthropic.claude-haiku-4-5-v1:0", "label": "Claude Haiku 4.5", "provider": "bedrock"}]


def test_list_models_resolves_profile_only_models_to_a_real_cross_region_id(monkeypatch):
    # This is the exact shape AWS returns for Nova in a region (e.g. ap-south-1) with no direct
    # on-demand access — inferenceTypesSupported has no "ON_DEMAND", only "INFERENCE_PROFILE".
    bedrock_session.set_credentials("AKIA...", "secret", None, "ap-south-1")

    class FakeControl:
        def list_foundation_models(self):
            return {"modelSummaries": [
                {"modelId": "amazon.nova-pro-v1:0", "modelName": "Nova Pro", "outputModalities": ["TEXT"], "inferenceTypesSupported": ["INFERENCE_PROFILE"]},
            ]}

        def list_inference_profiles(self, typeEquals=None, nextToken=None):
            return {"inferenceProfileSummaries": [
                {
                    "inferenceProfileId": "apac.amazon.nova-pro-v1:0",
                    "models": [{"modelArn": "arn:aws:bedrock:ap-south-1::foundation-model/amazon.nova-pro-v1:0"}],
                },
            ]}

    monkeypatch.setattr(bedrock_client, "_control_client", lambda: FakeControl())

    models = asyncio.run(bedrock_client.list_models())

    assert models == [{"model_id": "apac.amazon.nova-pro-v1:0", "label": "Nova Pro (cross-region)", "provider": "bedrock"}]


def test_list_models_omits_a_profile_only_model_with_no_matching_profile(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "ap-south-1")

    class FakeControl:
        def list_foundation_models(self):
            return {"modelSummaries": [
                {"modelId": "amazon.nova-pro-v1:0", "modelName": "Nova Pro", "outputModalities": ["TEXT"], "inferenceTypesSupported": ["INFERENCE_PROFILE"]},
            ]}

        def list_inference_profiles(self, typeEquals=None, nextToken=None):
            return {"inferenceProfileSummaries": []}  # nothing matches — known boto3 gap, or genuinely unavailable

    monkeypatch.setattr(bedrock_client, "_control_client", lambda: FakeControl())

    models = asyncio.run(bedrock_client.list_models())

    assert models == []


def test_list_models_paginates_inference_profiles(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "ap-south-1")

    class FakeControl:
        def list_foundation_models(self):
            return {"modelSummaries": [
                {"modelId": "amazon.nova-micro-v1:0", "modelName": "Nova Micro", "outputModalities": ["TEXT"], "inferenceTypesSupported": ["INFERENCE_PROFILE"]},
            ]}

        def list_inference_profiles(self, typeEquals=None, nextToken=None):
            if nextToken is None:
                return {
                    "inferenceProfileSummaries": [{"inferenceProfileId": "other.model", "models": [{"modelArn": ".../foundation-model/some.other-model-v1:0"}]}],
                    "nextToken": "page2",
                }
            return {
                "inferenceProfileSummaries": [{"inferenceProfileId": "apac.amazon.nova-micro-v1:0", "models": [{"modelArn": ".../foundation-model/amazon.nova-micro-v1:0"}]}],
            }

    monkeypatch.setattr(bedrock_client, "_control_client", lambda: FakeControl())

    models = asyncio.run(bedrock_client.list_models())

    assert models == [{"model_id": "apac.amazon.nova-micro-v1:0", "label": "Nova Micro (cross-region)", "provider": "bedrock"}]


def test_list_models_raises_credentials_required_with_no_session():
    with pytest.raises(bedrock_client.BedrockCredentialsRequired):
        asyncio.run(bedrock_client.list_models())


# ---- price_for with a cross-region profile id ----

def test_price_for_strips_geo_prefix_before_matching():
    assert bedrock_client.price_for("apac.amazon.nova-pro-v1:0") == (0.8, 3.2)
    assert bedrock_client.price_for("us.anthropic.claude-haiku-4-5-v1:0") == (1.0, 5.0)


# ---- _apply_credentials: the two auth modes and the bearer-token env var they share ----

def test_apply_credentials_iam_mode_returns_explicit_kwargs_and_no_bearer_token(monkeypatch):
    monkeypatch.delenv(bedrock_client._BEARER_TOKEN_ENV_VAR, raising=False)
    bedrock_session.set_credentials("AKIA...", "secret", "tok", "us-west-2")

    kwargs = bedrock_client._apply_credentials()

    assert kwargs == {
        "aws_access_key_id": "AKIA...",
        "aws_secret_access_key": "secret",
        "region_name": "us-west-2",
        "aws_session_token": "tok",
    }
    assert bedrock_client._BEARER_TOKEN_ENV_VAR not in os.environ


def test_apply_credentials_api_key_mode_sets_bearer_token_and_no_explicit_creds(monkeypatch):
    monkeypatch.delenv(bedrock_client._BEARER_TOKEN_ENV_VAR, raising=False)
    bedrock_session.set_api_key("bedrock-api-key-abc", "us-east-1")

    kwargs = bedrock_client._apply_credentials()

    assert kwargs == {"region_name": "us-east-1"}
    assert os.environ[bedrock_client._BEARER_TOKEN_ENV_VAR] == "bedrock-api-key-abc"


def test_apply_credentials_iam_mode_clears_a_stale_bearer_token(monkeypatch):
    # A previous api_key connection could have left this set — an IAM-mode client must never
    # pick up a leftover bearer token from an earlier, different connection.
    monkeypatch.setenv(bedrock_client._BEARER_TOKEN_ENV_VAR, "stale-token")
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    bedrock_client._apply_credentials()

    assert bedrock_client._BEARER_TOKEN_ENV_VAR not in os.environ


def test_apply_credentials_clears_bearer_token_when_nothing_is_connected(monkeypatch):
    monkeypatch.setenv(bedrock_client._BEARER_TOKEN_ENV_VAR, "stale-token")

    with pytest.raises(bedrock_client.BedrockCredentialsRequired):
        bedrock_client._apply_credentials()

    assert bedrock_client._BEARER_TOKEN_ENV_VAR not in os.environ


def test_invoke_works_in_api_key_mode(monkeypatch):
    bedrock_session.set_api_key("bedrock-api-key-abc", "us-east-1")

    class FakeRuntime:
        def converse(self, modelId, messages):
            return {
                "output": {"message": {"content": [{"text": "hi"}]}},
                "usage": {"inputTokens": 1, "outputTokens": 1},
            }

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    result = asyncio.run(bedrock_client.invoke("hello", "amazon.nova-micro-v1:0"))
    assert result["text"] == "hi"


# ---- embed ----

def test_embed_raises_credentials_required_with_no_session():
    with pytest.raises(bedrock_client.BedrockCredentialsRequired):
        asyncio.run(bedrock_client.embed("hello", "amazon.titan-embed-text-v2:0"))


def test_embed_returns_the_embedding_vector(monkeypatch):
    import io
    import json

    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeRuntime:
        def invoke_model(self, modelId, body, contentType, accept):
            assert modelId == "amazon.titan-embed-text-v2:0"
            assert json.loads(body) == {"inputText": "hello world"}
            return {"body": io.BytesIO(json.dumps({"embedding": [0.1, 0.2, 0.3]}).encode())}

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    result = asyncio.run(bedrock_client.embed("hello world", "amazon.titan-embed-text-v2:0"))
    assert result == [0.1, 0.2, 0.3]


def test_embed_clears_session_and_raises_on_auth_error(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeRuntime:
        def invoke_model(self, modelId, body, contentType, accept):
            raise ClientError({"Error": {"Code": "ExpiredToken", "Message": "expired"}}, "InvokeModel")

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    with pytest.raises(bedrock_client.BedrockAuthenticationFailed):
        asyncio.run(bedrock_client.embed("hello", "amazon.titan-embed-text-v2:0"))

    assert bedrock_session.get_credentials() is None


def test_embed_reraises_non_auth_client_errors(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeRuntime:
        def invoke_model(self, modelId, body, contentType, accept):
            raise ClientError({"Error": {"Code": "ValidationException", "Message": "bad request"}}, "InvokeModel")

    monkeypatch.setattr(bedrock_client, "_client", lambda: FakeRuntime())

    with pytest.raises(ClientError):
        asyncio.run(bedrock_client.embed("hello", "amazon.titan-embed-text-v2:0"))
    assert bedrock_session.get_credentials() is not None


# ---- list_embedding_models ----

def test_list_embedding_models_filters_to_embedding_output_models(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    class FakeControl:
        def list_foundation_models(self):
            return {"modelSummaries": [
                {"modelId": "amazon.titan-embed-text-v2:0", "modelName": "Titan Text Embeddings V2", "outputModalities": ["EMBEDDING"], "inferenceTypesSupported": ["ON_DEMAND"]},
                {"modelId": "anthropic.claude-haiku-4-5-v1:0", "modelName": "Claude Haiku 4.5", "outputModalities": ["TEXT"], "inferenceTypesSupported": ["ON_DEMAND"]},
            ]}

    monkeypatch.setattr(bedrock_client, "_control_client", lambda: FakeControl())

    models = asyncio.run(bedrock_client.list_embedding_models())

    assert models == [{"model_id": "amazon.titan-embed-text-v2:0", "label": "Titan Text Embeddings V2", "provider": "bedrock"}]


def test_list_embedding_models_raises_credentials_required_with_no_session():
    with pytest.raises(bedrock_client.BedrockCredentialsRequired):
        asyncio.run(bedrock_client.list_embedding_models())

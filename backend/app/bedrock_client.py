"""AWS Bedrock — the sole AI provider for both text generation (rag.py's _generate() routes to
invoke() below) and embeddings (rag.py's embed_text() routes to embed() the same way). Model ids
are conventionally "bedrock:"-prefixed in stored settings/ai_usage records — see rag.py for that
convention.

Uses its own credential session (bedrock_session.py), separate from aws_session.py's S3 one, so
a different AWS account/role can back Bedrock than backs the S3 asset inventory.
"""
import asyncio
import json
import logging
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app import bedrock_session
from app.config import BEDROCK_REGION

# boto3 has no way to pass a Bedrock API key (bearer token) directly to client()/Session() as of
# this writing — it's only ever picked up from this process environment variable. See
# _apply_credentials() below for how it gets set/cleared around each call in "api_key" mode.
_BEARER_TOKEN_ENV_VAR = "AWS_BEARER_TOKEN_BEDROCK"

logger = logging.getLogger("soc.bedrock")

_AUTH_ERROR_CODES = {
    "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId",
    "SignatureDoesNotMatch", "UnrecognizedClientException", "AccessDenied",
    "InvalidAccessKeyId", "AuthFailure", "InvalidToken",
}

# Matched by prefix (not exact string) against a real model id, since Bedrock model ids carry a
# dated version suffix (e.g. "-20251001-v1:0") that changes as providers release new snapshots —
# a prefix match keeps working across those without needing an update each time. Rates are
# $/1M tokens (input, output), from the same research behind ai_usage.py's cost-estimate default.
# Verify against a real `list_models()` call if a rate looks stale — these are best-effort, not
# pulled live from AWS (Bedrock has no pricing API).
BEDROCK_PRICING: dict[str, tuple[float, float]] = {
    "anthropic.claude-haiku-4-5": (1.0, 5.0),
    "anthropic.claude-sonnet-5": (3.0, 15.0),
    "anthropic.claude-opus-5": (15.0, 75.0),
    "amazon.nova-micro": (0.035, 0.14),
    "amazon.nova-lite": (0.06, 0.24),
    "amazon.nova-pro": (0.8, 3.2),
}


class BedrockNotConfigured(Exception):
    pass


class BedrockCredentialsRequired(Exception):
    """No Bedrock session is set (or SOC-AI's own 12h tracking already expired it)."""
    pass


class BedrockAuthenticationFailed(Exception):
    """AWS itself rejected the credentials (expired/invalid) — distinct from
    BedrockCredentialsRequired so the caller knows to prompt for fresh ones, not just "connect"."""
    pass


def _apply_credentials() -> dict:
    """Prepares this process for the next boto3 client call based on whichever auth mode is
    actually connected, and returns the client kwargs to use.

    "api_key" mode sets AWS_BEARER_TOKEN_BEDROCK in the process environment (the only way boto3
    currently accepts a Bedrock API key at all) and passes no explicit credential kwargs, letting
    boto3's own default chain pick that env var up. "iam" mode does the opposite: passes explicit
    keys, and — importantly — clears any bearer token left over from a previous api_key
    connection first, so a stale token can't end up affecting an IAM-credentialed client.
    """
    creds = bedrock_session.get_credentials()
    if creds is None:
        os.environ.pop(_BEARER_TOKEN_ENV_VAR, None)
        raise BedrockCredentialsRequired("Bedrock session not connected or expired")

    region = creds.get("region") or BEDROCK_REGION

    if creds["auth_mode"] == "api_key":
        os.environ[_BEARER_TOKEN_ENV_VAR] = creds["api_key"]
        return {"region_name": region}

    os.environ.pop(_BEARER_TOKEN_ENV_VAR, None)
    kwargs = {
        "aws_access_key_id": creds["access_key_id"],
        "aws_secret_access_key": creds["secret_access_key"],
        "region_name": region,
    }
    if creds.get("session_token"):
        kwargs["aws_session_token"] = creds["session_token"]
    return kwargs


def _client():
    return boto3.client("bedrock-runtime", **_apply_credentials())


def _control_client():
    return boto3.client("bedrock", **_apply_credentials())


# Cross-region inference profile ids are geo-prefixed ("apac.amazon.nova-pro-v1:0") — strip a
# known prefix before matching so pricing still resolves for a model this app can only reach via
# a profile, not just a bare on-demand model id.
_GEO_PROFILE_PREFIXES = ("us.", "eu.", "apac.", "jp.", "global.")


def price_for(model_id: str) -> tuple[float, float] | None:
    bare = model_id
    for geo in _GEO_PROFILE_PREFIXES:
        if bare.startswith(geo):
            bare = bare[len(geo):]
            break
    for prefix, rates in BEDROCK_PRICING.items():
        if bare.startswith(prefix):
            return rates
    return None


def _handle_client_error(exc: ClientError, action: str):
    code = exc.response.get("Error", {}).get("Code", "")
    if code in _AUTH_ERROR_CODES:
        # Proven-bad credentials — clear them now so the next status check (and the frontend's
        # "reconnect" prompt) reflects reality immediately, rather than waiting out the 12h TTL.
        bedrock_session.clear_credentials()
        logger.warning("AWS rejected the stored Bedrock credentials (%s); session cleared", code)
        raise BedrockAuthenticationFailed(f"AWS rejected the credentials: {code}") from exc
    logger.warning("Bedrock %s failed: %s", action, exc)
    raise


def _resolve_cross_region_profile_ids(client) -> dict[str, str]:
    """Maps a base foundation model id (e.g. "amazon.nova-pro-v1:0") to the real, AWS-defined
    cross-region inference profile id that can actually invoke it (e.g.
    "apac.amazon.nova-pro-v1:0"), built from list_inference_profiles() rather than guessed —
    the geo prefix isn't a fixed function of the region alone (not every model supports every
    geo grouping), so this asks AWS directly instead of constructing a prefix by hand.
    """
    mapping: dict[str, str] = {}
    next_token = None
    while True:
        kwargs = {"typeEquals": "SYSTEM_DEFINED"}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_inference_profiles(**kwargs)
        for profile in resp.get("inferenceProfileSummaries", []):
            profile_id = profile["inferenceProfileId"]
            for model in profile.get("models", []):
                arn = model.get("modelArn", "")
                # Format: "arn:aws:bedrock:<region>::foundation-model/<model-id>" — note no "/"
                # before "foundation-model" (the account-id component is simply empty, so it's
                # preceded by "::" not "/foundation-model/").
                if "foundation-model/" in arn:
                    base_model_id = arn.split("foundation-model/", 1)[1]
                    # Prefer the first (typically shortest-named, e.g. "us.") match if a model
                    # is reachable through more than one geo profile.
                    mapping.setdefault(base_model_id, profile_id)
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return mapping


def _list_models_by_modality_sync(client, modality: str) -> list[dict]:
    """Shared by list_models() (modality="TEXT", for chat/generation) and
    list_embedding_models() (modality="EMBEDDING") — same on-demand-or-cross-region-profile
    resolution either way, just filtered to a different output modality.
    """
    try:
        resp = client.list_foundation_models()
    except ClientError as exc:
        _handle_client_error(exc, f"list_models({modality})")
    except BotoCoreError as exc:
        logger.warning("Bedrock list_models(%s) failed: %s", modality, exc)
        raise

    matching = [m for m in resp.get("modelSummaries", []) if modality in (m.get("outputModalities") or [])]
    needs_profile = [m for m in matching if "ON_DEMAND" not in (m.get("inferenceTypesSupported") or [])]

    profile_ids: dict[str, str] = {}
    if needs_profile:
        try:
            profile_ids = _resolve_cross_region_profile_ids(client)
        except (ClientError, BotoCoreError):
            # Non-fatal — on-demand models (the common case) still list fine without this;
            # only the profile-only ones (e.g. Nova in a region with no direct on-demand access)
            # would be missing.
            logger.warning("Could not resolve cross-region inference profiles; profile-only models will be omitted", exc_info=True)

    results = []
    for m in matching:
        model_id = m["modelId"]
        label = m.get("modelName", model_id)
        if "ON_DEMAND" in (m.get("inferenceTypesSupported") or []):
            results.append({"model_id": model_id, "label": label, "provider": "bedrock"})
            continue
        resolved = profile_ids.get(model_id)
        if resolved:
            results.append({"model_id": resolved, "label": f"{label} (cross-region)", "provider": "bedrock"})
        # else: genuinely not invokable from this account/region combo right now — omit rather
        # than listing an id that would just fail on invoke.
    return results


def _list_models_sync() -> list[dict]:
    return _list_models_by_modality_sync(_control_client(), "TEXT")


def _list_embedding_models_sync() -> list[dict]:
    return _list_models_by_modality_sync(_control_client(), "EMBEDDING")


async def list_models() -> list[dict]:
    return await asyncio.to_thread(_list_models_sync)


async def list_embedding_models() -> list[dict]:
    return await asyncio.to_thread(_list_embedding_models_sync)


def _supports_prompt_caching(model_id: str) -> bool:
    """Bedrock's cachePoint content block is only verified working for Claude models here —
    gated by prefix (after stripping the same geo-profile prefix price_for() strips) rather than
    assumed for every provider this app can reach (Nova's cache support, if any, isn't verified)."""
    bare = model_id
    for geo in _GEO_PROFILE_PREFIXES:
        if bare.startswith(geo):
            bare = bare[len(geo):]
            break
    return bare.startswith("anthropic.claude")


def _invoke_sync(prompt: str, model_id: str, system_text: str = "") -> dict:
    client = _client()
    use_cache = bool(system_text) and _supports_prompt_caching(model_id)

    def _call(with_cache: bool) -> dict:
        kwargs = {"modelId": model_id, "messages": [{"role": "user", "content": [{"text": prompt}]}]}
        if with_cache:
            kwargs["system"] = [{"text": system_text}, {"cachePoint": {"type": "default"}}]
        return client.converse(**kwargs)

    try:
        resp = _call(use_cache)
    except ClientError as exc:
        if use_cache and exc.response.get("Error", {}).get("Code") == "ValidationException":
            # A wrong assumption about this specific model's cache support must not break
            # generation outright — retry once, uncached, exactly like the pre-caching behavior.
            logger.warning("Bedrock rejected the cachePoint for %s; retrying uncached", model_id)
            try:
                resp = _call(False)
            except ClientError as exc2:
                _handle_client_error(exc2, "invoke")
            except BotoCoreError as exc2:
                logger.warning("Bedrock invoke failed: %s", exc2)
                raise
        else:
            _handle_client_error(exc, "invoke")
    except BotoCoreError as exc:
        logger.warning("Bedrock invoke failed: %s", exc)
        raise

    text = "".join(
        block.get("text", "") for block in resp["output"]["message"]["content"]
    )
    usage = resp.get("usage", {})
    return {
        "text": text,
        "model_used": model_id,
        "prompt_tokens": usage.get("inputTokens", 0),
        "completion_tokens": usage.get("outputTokens", 0),
        "cache_read_tokens": usage.get("cacheReadInputTokens", 0),
        "cache_write_tokens": usage.get("cacheWriteInputTokens", 0),
    }


class StructuredOutputFailed(Exception):
    """Raised instead of degrading silently — the caller (rag.py) needs to know structured
    output didn't happen at all so it can fall back to the freeform-text path for this call,
    rather than get back a worse or empty answer without knowing why."""
    pass


def _invoke_structured_sync(user_text: str, model_id: str, tool_name: str, tool_schema: dict, system_text: str = "") -> dict:
    client = _client()
    use_cache = bool(system_text) and _supports_prompt_caching(model_id)

    def _call(with_cache: bool) -> dict:
        kwargs = {
            "modelId": model_id,
            "messages": [{"role": "user", "content": [{"text": user_text}]}],
            "toolConfig": {
                "tools": [{"toolSpec": {"name": tool_name, "inputSchema": {"json": tool_schema}}}],
                "toolChoice": {"tool": {"name": tool_name}},
            },
        }
        if system_text:
            kwargs["system"] = [{"text": system_text}, {"cachePoint": {"type": "default"}}] if with_cache else [{"text": system_text}]
        return client.converse(**kwargs)

    try:
        resp = _call(use_cache)
    except ClientError as exc:
        if use_cache and exc.response.get("Error", {}).get("Code") == "ValidationException":
            logger.warning("Bedrock rejected the cachePoint for %s; retrying uncached", model_id)
            try:
                resp = _call(False)
            except (ClientError, BotoCoreError) as exc2:
                raise StructuredOutputFailed(f"Bedrock structured invoke failed for {model_id}: {exc2}") from exc2
        else:
            raise StructuredOutputFailed(f"Bedrock structured invoke failed for {model_id}: {exc}") from exc
    except BotoCoreError as exc:
        raise StructuredOutputFailed(f"Bedrock structured invoke failed for {model_id}: {exc}") from exc

    tool_input = None
    for block in resp["output"]["message"]["content"]:
        if "toolUse" in block:
            tool_input = block["toolUse"].get("input")
            break
    if tool_input is None:
        raise StructuredOutputFailed(f"Bedrock response for {model_id} carried no toolUse block")

    usage = resp.get("usage", {})
    return {
        "data": tool_input,
        "model_used": model_id,
        "prompt_tokens": usage.get("inputTokens", 0),
        "completion_tokens": usage.get("outputTokens", 0),
        "cache_read_tokens": usage.get("cacheReadInputTokens", 0),
        "cache_write_tokens": usage.get("cacheWriteInputTokens", 0),
    }


async def invoke_structured(user_text: str, model_id: str, tool_name: str, tool_schema: dict, system_text: str = "") -> dict:
    """Forces the model to answer by calling a single tool (tool_name) whose arguments must match
    tool_schema (a JSON Schema object) — Bedrock parses and validates the JSON for the caller, no
    regex involved. Returns {"data": <parsed dict>, "model_used", "prompt_tokens",
    "completion_tokens", "cache_read_tokens", "cache_write_tokens"} — same cache-usage shape as
    invoke(). Raises StructuredOutputFailed on any failure (auth errors aside, which still raise
    their own BedrockAuthenticationFailed) rather than degrading quietly, since a caller that asked
    for structured output has no other way to tell it didn't get it.
    """
    return await asyncio.to_thread(_invoke_structured_sync, user_text, model_id, tool_name, tool_schema, system_text)


async def invoke(prompt: str, model_id: str, system_text: str = "") -> dict:
    """Same return shape as rag.py's _generate() — {"text", "model_used", "prompt_tokens",
    "completion_tokens"} — plus "cache_read_tokens"/"cache_write_tokens" (both 0 unless
    system_text is given and the model actually supports/used caching). Every existing caller
    (system_text omitted) works unchanged regardless of which provider actually served the
    request. system_text, when given, becomes a cached Converse API `system` block for Claude
    models on Bedrock (see _supports_prompt_caching) — the stable, repeated part of a prompt
    (role instructions, format spec) billed once per cache window instead of every call; for
    anything else it's silently ignored and `prompt` alone is sent, same as before this existed.
    """
    return await asyncio.to_thread(_invoke_sync, prompt, model_id, system_text)


def _embed_sync(text: str, model_id: str) -> list[float]:
    # Embedding models use the raw invoke_model API, not converse() — converse is for
    # chat/text-generation models only, embedding models were never wired into it.
    client = _client()
    try:
        resp = client.invoke_model(
            modelId=model_id,
            body=json.dumps({"inputText": text}),
            contentType="application/json",
            accept="application/json",
        )
    except ClientError as exc:
        _handle_client_error(exc, "embed")
    except BotoCoreError as exc:
        logger.warning("Bedrock embed failed: %s", exc)
        raise

    body = json.loads(resp["body"].read())
    return body["embedding"]


async def embed(text: str, model_id: str) -> list[float]:
    """Same return shape as rag.py's embed_text() — a plain list of floats. Note: switching the
    active embedding model changes the vector dimensionality (e.g. Titan Text Embeddings V2
    defaults to 1024-dim, other Bedrock embedding models may differ) — safe to change freely
    while ChromaDB's org_knowledge collection is empty, but once it holds real vectors, changing
    embedding models means re-embedding everything already in it, not just new documents.
    """
    return await asyncio.to_thread(_embed_sync, text, model_id)

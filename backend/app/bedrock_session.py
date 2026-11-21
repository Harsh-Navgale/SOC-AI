"""In-memory Bedrock credential cache — a separate connection from aws_session.py's S3 one, on
purpose, so a different AWS account/role can back Bedrock than backs the S3 asset inventory.

Two mutually exclusive auth modes, matching what Bedrock itself actually supports:
  - "iam": a full access key/secret (+ optional session token) pair, SigV4-signed like every
    other AWS service.
  - "api_key": a Bedrock API key (bearer token) — simpler to generate/rotate, but a real boto3
    limitation as of this writing is that it's only ever picked up via the AWS_BEARER_TOKEN_BEDROCK
    process environment variable, not as an explicit boto3.client()/Session() parameter. See
    bedrock_client.py's _apply_credentials() for how that env var gets set/cleared around this.

Deliberately NOT persisted to Mongo or disk — secrets only ever live in this process's memory,
for at most SESSION_TTL_SECONDS. This only works correctly with a single uvicorn worker process
(see backend/Dockerfile — no --workers flag); a multi-worker deployment would need a shared store
instead, which would mean this could no longer stay memory-only.
"""
import os
import time
from datetime import datetime, timezone
from typing import Optional

SESSION_TTL_SECONDS = 12 * 60 * 60  # 12 hours

# Mirrors bedrock_client.py's _BEARER_TOKEN_ENV_VAR — duplicated as a literal rather than
# imported to avoid a bedrock_client <-> bedrock_session import cycle (bedrock_client already
# imports this module for credentials; this module has no reason to import bedrock_client back).
_BEARER_TOKEN_ENV_VAR = "AWS_BEARER_TOKEN_BEDROCK"

_session: dict = {
    "auth_mode": None,  # "iam" | "api_key"
    "access_key_id": None,
    "secret_access_key": None,
    "session_token": None,
    "api_key": None,
    "region": None,
    "expires_at": None,
}


def set_credentials(access_key_id: str, secret_access_key: str, session_token: Optional[str], region: str):
    _session["auth_mode"] = "iam"
    _session["access_key_id"] = access_key_id
    _session["secret_access_key"] = secret_access_key
    _session["session_token"] = session_token
    _session["api_key"] = None
    _session["region"] = region
    _session["expires_at"] = time.time() + SESSION_TTL_SECONDS


def set_api_key(api_key: str, region: str):
    _session["auth_mode"] = "api_key"
    _session["access_key_id"] = None
    _session["secret_access_key"] = None
    _session["session_token"] = None
    _session["api_key"] = api_key
    _session["region"] = region
    _session["expires_at"] = time.time() + SESSION_TTL_SECONDS


def clear_credentials():
    for key in _session:
        _session[key] = None
    os.environ.pop(_BEARER_TOKEN_ENV_VAR, None)


def _is_valid() -> bool:
    return _session["expires_at"] is not None and time.time() < _session["expires_at"]


def get_credentials() -> Optional[dict]:
    if not _is_valid():
        clear_credentials()
        return None
    return {
        "auth_mode": _session["auth_mode"],
        "access_key_id": _session["access_key_id"],
        "secret_access_key": _session["secret_access_key"],
        "session_token": _session["session_token"],
        "api_key": _session["api_key"],
        "region": _session["region"],
    }


def status() -> dict:
    if not _is_valid():
        return {"configured": False, "expires_at": None, "auth_mode": None}
    return {
        "configured": True,
        "expires_at": datetime.fromtimestamp(_session["expires_at"], tz=timezone.utc).isoformat(),
        "auth_mode": _session["auth_mode"],
    }

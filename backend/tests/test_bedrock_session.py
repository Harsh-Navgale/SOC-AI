import os
import time

import pytest

from app import bedrock_session


@pytest.fixture(autouse=True)
def _reset():
    bedrock_session.clear_credentials()
    yield
    bedrock_session.clear_credentials()


def test_get_credentials_none_before_connecting():
    assert bedrock_session.get_credentials() is None


def test_set_and_get_credentials_roundtrip():
    bedrock_session.set_credentials("AKIA...", "secret", "token123", "us-west-2")

    creds = bedrock_session.get_credentials()
    assert creds == {
        "auth_mode": "iam",
        "access_key_id": "AKIA...",
        "secret_access_key": "secret",
        "session_token": "token123",
        "api_key": None,
        "region": "us-west-2",
    }


def test_clear_credentials_removes_them():
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")
    bedrock_session.clear_credentials()

    assert bedrock_session.get_credentials() is None


def test_status_reports_configured_and_expiry():
    assert bedrock_session.status() == {"configured": False, "expires_at": None, "auth_mode": None}

    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")
    status = bedrock_session.status()
    assert status["configured"] is True
    assert status["expires_at"] is not None
    assert status["auth_mode"] == "iam"


def test_get_credentials_none_and_auto_cleared_once_expired(monkeypatch):
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")
    monkeypatch.setattr(time, "time", lambda: bedrock_session._session["expires_at"] + 1)

    assert bedrock_session.get_credentials() is None
    # Expiry is not just reported — the stale session is actually cleared out.
    assert bedrock_session._session["access_key_id"] is None


# ---- api_key auth mode ----

def test_set_api_key_roundtrip():
    bedrock_session.set_api_key("bedrock-api-key-abc", "us-west-2")

    creds = bedrock_session.get_credentials()
    assert creds == {
        "auth_mode": "api_key",
        "access_key_id": None,
        "secret_access_key": None,
        "session_token": None,
        "api_key": "bedrock-api-key-abc",
        "region": "us-west-2",
    }
    assert bedrock_session.status()["auth_mode"] == "api_key"


def test_switching_from_api_key_to_iam_clears_the_old_api_key():
    bedrock_session.set_api_key("bedrock-api-key-abc", "us-east-1")
    bedrock_session.set_credentials("AKIA...", "secret", None, "us-east-1")

    creds = bedrock_session.get_credentials()
    assert creds["auth_mode"] == "iam"
    assert creds["api_key"] is None


def test_switching_from_iam_to_api_key_clears_the_old_iam_keys():
    bedrock_session.set_credentials("AKIA...", "secret", "token", "us-east-1")
    bedrock_session.set_api_key("bedrock-api-key-abc", "us-east-1")

    creds = bedrock_session.get_credentials()
    assert creds["auth_mode"] == "api_key"
    assert creds["access_key_id"] is None
    assert creds["secret_access_key"] is None
    assert creds["session_token"] is None


def test_clear_credentials_also_clears_the_bearer_token_env_var(monkeypatch):
    monkeypatch.setenv(bedrock_session._BEARER_TOKEN_ENV_VAR, "leftover-token")

    bedrock_session.clear_credentials()

    assert bedrock_session._BEARER_TOKEN_ENV_VAR not in os.environ

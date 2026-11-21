import asyncio

import pytest
from botocore.exceptions import ClientError

from app import asset_coverage, aws_session, s3_inventory
from app.auth import hash_password
from app.s3_inventory import S3CredentialsRequired, S3AuthenticationFailed
from app.wazuh_manager_client import WazuhManagerNotConfigured


@pytest.fixture(autouse=True)
def _reset_aws_session():
    aws_session.clear_credentials()
    yield
    aws_session.clear_credentials()


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def test_reconcile_preserves_full_s3_record_fields(monkeypatch):
    """Every column from the S3 export (not just hostname/ip) must survive into the
    reconciliation output — the frontend's CSV export and any future consumer need the
    original data, not a truncated subset."""
    agents = [{"id": "001", "name": "web01", "ip": "10.0.0.1", "status": "active"}]
    inventory = [
        {"hostname": "web01", "ip": "10.0.0.1", "raw": {"hostname": "web01", "ip": "10.0.0.1", "env": "prod", "instance_id": "i-abc123"}},
        {"hostname": "web02", "ip": "10.0.0.2", "raw": {"hostname": "web02", "ip": "10.0.0.2", "env": "staging", "instance_id": "i-def456"}},
    ]

    async def fake_list_agents():
        return agents

    async def fake_fetch_inventory():
        return inventory

    monkeypatch.setattr("app.wazuh_manager_client.list_agents", fake_list_agents)
    monkeypatch.setattr("app.s3_inventory.fetch_latest_inventory", fake_fetch_inventory)

    result = asyncio.run(asset_coverage.reconcile())

    assert result["connected"][0]["s3_record"] == {"hostname": "web01", "ip": "10.0.0.1", "env": "prod", "instance_id": "i-abc123"}
    assert result["missing"][0]["s3_record"] == {"hostname": "web02", "ip": "10.0.0.2", "env": "staging", "instance_id": "i-def456"}


# ---- s3_inventory: derive IP from AWS's auto-generated EC2 hostname when no explicit
# IP column is present/recognized ----

def test_extract_ip_derives_from_aws_ec2_internal_hostname():
    """Real-world regression: an S3 record whose only address info is AWS's
    auto-generated private DNS hostname (no separate IP column at all) was being reported
    as 'missing coverage' even though the instance is genuinely active in Wazuh, because no
    IP could be extracted to match against. The private IP is embedded directly in this
    hostname format and should be derived instead of giving up."""
    record = {"hostname": "ip-10-10-13-64.ap-south-1.compute.internal"}
    assert s3_inventory._extract_ip(record) == "10.10.13.64"


def test_extract_ip_prefers_explicit_ip_field_over_derived_hostname():
    record = {"hostname": "ip-10-10-13-64.ap-south-1.compute.internal", "ip": "192.168.1.1"}
    assert s3_inventory._extract_ip(record) == "192.168.1.1"


def test_extract_ip_returns_none_for_non_aws_style_hostname():
    record = {"hostname": "some-random-server-name"}
    assert s3_inventory._extract_ip(record) is None


def test_reconcile_matches_ec2_internal_hostname_via_derived_ip(monkeypatch):
    agents = [{"id": "001", "name": "some-agent-name", "ip": "10.10.13.64", "status": "active"}]
    inventory = [
        {
            "hostname": "ip-10-10-13-64.ap-south-1.compute.internal",
            "ip": s3_inventory._extract_ip({"hostname": "ip-10-10-13-64.ap-south-1.compute.internal"}),
            "raw": {"hostname": "ip-10-10-13-64.ap-south-1.compute.internal"},
        },
    ]

    async def fake_list_agents():
        return agents

    async def fake_fetch_inventory():
        return inventory

    monkeypatch.setattr("app.wazuh_manager_client.list_agents", fake_list_agents)
    monkeypatch.setattr("app.s3_inventory.fetch_latest_inventory", fake_fetch_inventory)

    result = asyncio.run(asset_coverage.reconcile())
    assert result["summary"]["connected"] == 1
    assert result["summary"]["missing"] == 0


# ---- s3_inventory: never drop rows, handle BOM'd CSV headers ----

def test_parse_body_strips_utf8_bom_from_csv_header():
    """PowerShell's Export-Csv and Excel commonly prepend a UTF-8 BOM, which otherwise glues
    onto the first column name (e.g. b'\\xef\\xbb\\xbfhostname') and silently breaks hostname
    detection even when the column is spelled correctly."""
    raw = b"\xef\xbb\xbfhostname,env\nweb01,prod\n"
    records = s3_inventory._parse_body(raw, "csv")
    assert records == [{"hostname": "web01", "env": "prod"}]
    assert s3_inventory._extract_hostname(records[0]) == "web01"


def test_fetch_sync_never_drops_rows_even_without_recognizable_hostname(monkeypatch):
    # Header row uses a column name ("server_name") that isn't in the fallback list — every
    # row in a real file like this would previously vanish silently.
    csv_body = b"server_name,env\nweb01,prod\nweb02,staging\n"
    aws_session.set_credentials("AKIA", "secret", None, "us-east-1")

    class FakeS3:
        def get_object(self, **kwargs):
            return {"Body": type("Body", (), {"read": lambda self: csv_body})()}

    monkeypatch.setattr(s3_inventory, "_client", lambda: FakeS3())
    monkeypatch.setattr(s3_inventory, "S3_INVENTORY_BUCKET", "test-bucket")
    monkeypatch.setattr(s3_inventory, "S3_INVENTORY_KEY", "latest.csv")
    monkeypatch.setattr(s3_inventory, "S3_INVENTORY_FORMAT", "csv")

    records = s3_inventory._fetch_sync()

    # both rows returned even though neither had a recognizable hostname column
    assert len(records) == 2
    assert records[0]["hostname"] is None
    assert records[0]["raw"] == {"server_name": "web01", "env": "prod"}
    assert records[1]["hostname"] is None
    assert records[1]["raw"] == {"server_name": "web02", "env": "staging"}


def test_reconcile_handles_record_with_no_detected_ip(monkeypatch):
    agents = [{"id": "001", "name": "web01", "ip": "10.0.0.1", "status": "active"}]
    inventory = [
        {"hostname": "web01", "ip": "10.0.0.1", "raw": {"hostname": "web01", "ip": "10.0.0.1"}},
        {"hostname": "web02", "ip": None, "raw": {"weird_col": "some-value"}},
    ]

    async def fake_list_agents():
        return agents

    async def fake_fetch_inventory():
        return inventory

    monkeypatch.setattr("app.wazuh_manager_client.list_agents", fake_list_agents)
    monkeypatch.setattr("app.s3_inventory.fetch_latest_inventory", fake_fetch_inventory)

    result = asyncio.run(asset_coverage.reconcile())

    assert result["summary"]["connected"] == 1
    assert result["summary"]["missing"] == 1
    assert result["missing"][0]["ip"] is None
    assert result["missing"][0]["s3_record"] == {"weird_col": "some-value"}


# ---- reconcile() matching logic ----

def test_reconcile_classifies_all_status_buckets_plus_missing_orphaned(monkeypatch):
    agents = [
        {"id": "001", "name": "web01", "ip": "10.0.0.1", "status": "active"},
        {"id": "002", "name": "web02", "ip": "10.0.0.2", "status": "disconnected"},
        {"id": "003", "name": "web03", "ip": "10.0.0.3", "status": "pending"},
        {"id": "004", "name": "web04", "ip": "10.0.0.4", "status": "never_connected"},
        {"id": "005", "name": "old-decommissioned", "ip": "10.0.0.9", "status": "active"},
    ]
    inventory = [
        # hostname deliberately does NOT match the Wazuh agent name — matching is IP-only,
        # so this must still connect purely on the IP agreeing.
        {"hostname": "web01-renamed-in-s3", "ip": "10.0.0.1"},
        {"hostname": "web02", "ip": "10.0.0.2"},
        {"hostname": "web03", "ip": "10.0.0.3"},
        {"hostname": "web04", "ip": "10.0.0.4"},
        {"hostname": "web05", "ip": "10.0.0.5"},  # no agent has this IP -> missing
    ]

    async def fake_list_agents():
        return agents

    async def fake_fetch_inventory():
        return inventory

    monkeypatch.setattr("app.wazuh_manager_client.list_agents", fake_list_agents)
    monkeypatch.setattr("app.s3_inventory.fetch_latest_inventory", fake_fetch_inventory)

    result = asyncio.run(asset_coverage.reconcile())

    assert result["match_basis"] == "ip"
    assert result["summary"] == {
        "connected": 1, "disconnected": 1, "pending": 1, "other": 1, "missing": 1, "orphaned": 1,
    }
    assert result["connected"][0]["ip"] == "10.0.0.1"
    assert result["connected"][0]["hostname"] == "web01-renamed-in-s3"  # hostname mismatch is irrelevant now
    assert result["disconnected"][0]["ip"] == "10.0.0.2"
    assert result["pending"][0]["ip"] == "10.0.0.3"
    assert result["other"][0]["ip"] == "10.0.0.4"
    assert result["missing"][0]["ip"] == "10.0.0.5"
    assert result["orphaned_agents"][0]["name"] == "old-decommissioned"


def test_reconcile_ip_matching_ignores_case(monkeypatch):
    """IPv6-style case differences (or any stray casing) shouldn't prevent a match."""
    agents = [{"id": "001", "name": "web01", "ip": "FE80::1", "status": "active"}]
    inventory = [{"hostname": "web01", "ip": "fe80::1"}]

    async def fake_list_agents():
        return agents

    async def fake_fetch_inventory():
        return inventory

    monkeypatch.setattr("app.wazuh_manager_client.list_agents", fake_list_agents)
    monkeypatch.setattr("app.s3_inventory.fetch_latest_inventory", fake_fetch_inventory)

    result = asyncio.run(asset_coverage.reconcile())
    assert result["summary"]["connected"] == 1
    assert result["summary"]["missing"] == 0


# ---- /api/assets/coverage ----

def test_asset_coverage_reports_wazuh_not_configured(client, mock_db, monkeypatch):
    token = _login(client)

    async def raise_not_configured():
        raise WazuhManagerNotConfigured()

    monkeypatch.setattr("app.main.reconcile_assets", raise_not_configured)

    resp = client.get("/api/assets/coverage", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 409
    assert "Wazuh Manager" in resp.json()["detail"]


def test_asset_coverage_reports_aws_session_required(client, mock_db, monkeypatch):
    token = _login(client)

    async def raise_creds_required():
        raise S3CredentialsRequired()

    monkeypatch.setattr("app.main.reconcile_assets", raise_creds_required)

    resp = client.get("/api/assets/coverage", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 409
    assert "AWS session" in resp.json()["detail"]


# ---- expired/invalid AWS credentials ----

def test_fetch_sync_clears_session_and_raises_on_auth_error(monkeypatch):
    aws_session.set_credentials("AKIA", "secret", None, "us-east-1")

    class FakeS3:
        def get_object(self, **kwargs):
            raise ClientError({"Error": {"Code": "ExpiredToken", "Message": "expired"}}, "GetObject")

    monkeypatch.setattr(s3_inventory, "_client", lambda: FakeS3())
    monkeypatch.setattr(s3_inventory, "S3_INVENTORY_BUCKET", "test-bucket")
    monkeypatch.setattr(s3_inventory, "S3_INVENTORY_KEY", "latest.json")

    with pytest.raises(S3AuthenticationFailed):
        s3_inventory._fetch_sync()

    # the bad credentials must be cleared immediately, not left to expire on their own
    assert aws_session.get_credentials() is None


def test_asset_coverage_reports_auth_failure_as_reconnect(client, mock_db, monkeypatch):
    token = _login(client)

    async def raise_auth_failed():
        raise S3AuthenticationFailed("AWS rejected the credentials: ExpiredToken")

    monkeypatch.setattr("app.main.reconcile_assets", raise_auth_failed)

    resp = client.get("/api/assets/coverage", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 409
    assert "AWS session" in resp.json()["detail"]


# ---- /api/assets/wazuh-agents ----

def test_wazuh_agents_endpoint_reports_not_configured(client, mock_db, monkeypatch):
    token = _login(client)

    async def raise_not_configured():
        raise WazuhManagerNotConfigured()

    monkeypatch.setattr("app.main.list_agents_with_fallback", raise_not_configured)

    resp = client.get("/api/assets/wazuh-agents", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 409
    assert "Wazuh Manager" in resp.json()["detail"]


def test_wazuh_agents_endpoint_returns_list(client, mock_db, monkeypatch):
    token = _login(client)

    async def fake_list_agents():
        return [{"id": "001", "name": "web01", "ip": "10.0.0.1", "status": "active"}], "live"

    monkeypatch.setattr("app.main.list_agents_with_fallback", fake_list_agents)

    resp = client.get("/api/assets/wazuh-agents", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["agents"][0]["name"] == "web01"


def test_wazuh_agents_endpoint_requires_auth(client, mock_db):
    resp = client.get("/api/assets/wazuh-agents")
    assert resp.status_code == 401


# ---- /api/assets/s3-inventory ----

def test_s3_inventory_reports_aws_session_required(client, mock_db, monkeypatch):
    token = _login(client)

    async def raise_creds_required():
        raise S3CredentialsRequired()

    monkeypatch.setattr("app.main.fetch_latest_inventory", raise_creds_required)

    resp = client.get("/api/assets/s3-inventory", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 409
    assert "AWS session" in resp.json()["detail"]


def test_s3_inventory_returns_records(client, mock_db, monkeypatch):
    token = _login(client)

    async def fake_fetch():
        return [{"hostname": "web01", "raw": {"hostname": "web01", "env": "prod"}}]

    monkeypatch.setattr("app.main.fetch_latest_inventory", fake_fetch)

    resp = client.get("/api/assets/s3-inventory", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["records"][0]["hostname"] == "web01"


# ---- AWS credentials endpoints ----

def test_aws_credentials_admin_only(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "alice",
        "password_hash": hash_password("alice-pw"),
        "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "alice", "alice-pw")

    resp = client.post(
        "/api/integrations/aws/credentials",
        json={"access_key_id": "AKIA123", "secret_access_key": "shh", "region": "us-east-1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_aws_credentials_set_status_clear(client, mock_db):
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    set_resp = client.post(
        "/api/integrations/aws/credentials",
        json={"access_key_id": "AKIA123", "secret_access_key": "shh", "region": "us-east-1"},
        headers=headers,
    )
    assert set_resp.status_code == 200
    assert set_resp.json()["configured"] is True

    status_resp = client.get("/api/integrations/aws/status", headers=headers)
    assert status_resp.json()["configured"] is True

    clear_resp = client.delete("/api/integrations/aws/credentials", headers=headers)
    assert clear_resp.json()["configured"] is False

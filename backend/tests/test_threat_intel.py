import asyncio

import httpx
import pytest

from app import threat_intel, threat_intel_session
from app.auth import hash_password


@pytest.fixture(autouse=True)
def _reset_state():
    threat_intel_session.clear_credentials()
    threat_intel._cache.clear()
    yield
    threat_intel_session.clear_credentials()
    threat_intel._cache.clear()


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


# ---- resolve_target_ip ----

def test_resolve_target_ip_uses_the_single_external_srcip():
    incident = {"source_ip": "10.29.12.215", "unique_values": {"data.srcip": ["198.51.100.7"]}}
    assert threat_intel.resolve_target_ip(incident) == "198.51.100.7"


def test_resolve_target_ip_falls_back_when_multiple_external_srcips():
    # No single "the" attacker IP to pick out of several different callers — fall back to the
    # host's own IP rather than arbitrarily choosing one.
    incident = {"source_ip": "10.29.12.215", "unique_values": {"data.srcip": ["198.51.100.7", "198.51.100.8"]}}
    assert threat_intel.resolve_target_ip(incident) == "10.29.12.215"


def test_resolve_target_ip_falls_back_when_no_external_srcip_recorded():
    incident = {"source_ip": "10.29.12.215", "unique_values": {"full_log": ["some log line"]}}
    assert threat_intel.resolve_target_ip(incident) == "10.29.12.215"


def test_resolve_target_ip_falls_back_when_no_unique_values_at_all():
    incident = {"source_ip": "10.29.12.215"}
    assert threat_intel.resolve_target_ip(incident) == "10.29.12.215"


def test_resolve_target_ip_returns_none_when_nothing_available():
    assert threat_intel.resolve_target_ip({}) is None


# ---- detect_indicator_type ----

@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", "ip"),
    ("2001:4860:4860::8888", "ip"),
    ("example.com", "domain"),
    ("d41d8cd98f00b204e9800998ecf8427e", "hash"),      # md5, 32 hex chars
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash"),  # sha1, 40 hex chars
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash"),  # sha256, 64
    ("http://evil.example.com/payload", "url"),
    ("https://evil.example.com/payload", "url"),
])
def test_detect_indicator_type(value, expected):
    assert threat_intel.detect_indicator_type(value) == expected


# ---- per-source lookups (mocked httpx) ----

class _FakeResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=self)


class _FakeAsyncClient:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, *a, **kw):
        return self._response

    async def post(self, *a, **kw):
        return self._response


def test_lookup_virustotal_not_configured():
    result = asyncio.run(threat_intel.lookup_virustotal("8.8.8.8", "ip"))
    assert result == {"status": "not_configured"}


def test_lookup_virustotal_ok(monkeypatch):
    threat_intel_session.set_credentials("vt-key", None)
    fake = _FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "harmless": 60}, "reputation": -5}}})
    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", lambda timeout=None: _FakeAsyncClient(fake))

    result = asyncio.run(threat_intel.lookup_virustotal("8.8.8.8", "ip"))
    assert result["status"] == "ok"
    assert result["data"]["malicious"] == 3
    assert result["data"]["reputation"] == -5


def test_lookup_abuseipdb_not_applicable_for_non_ip():
    result = asyncio.run(threat_intel.lookup_abuseipdb("example.com", "domain"))
    assert result == {"status": "not_applicable"}


def test_lookup_abuseipdb_not_configured():
    result = asyncio.run(threat_intel.lookup_abuseipdb("8.8.8.8", "ip"))
    assert result == {"status": "not_configured"}


def test_lookup_abuseipdb_ok(monkeypatch):
    threat_intel_session.set_credentials(None, "abuse-key")
    fake = _FakeResponse(200, {"data": {"abuseConfidenceScore": 42, "totalReports": 7, "countryCode": "US"}})
    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", lambda timeout=None: _FakeAsyncClient(fake))

    result = asyncio.run(threat_intel.lookup_abuseipdb("8.8.8.8", "ip"))
    assert result["status"] == "ok"
    assert result["data"]["abuse_confidence_score"] == 42


def test_lookup_urlhaus_not_configured_without_abusech_key():
    """abuse.ch now requires a free Auth-Key for URLhaus/ThreatFox too — this used to be a
    fully public/keyless API, so make sure the "no key set" path is actually handled rather
    than silently hitting abuse.ch and getting a 401."""
    result = asyncio.run(threat_intel.lookup_urlhaus("example.com", "domain"))
    assert result == {"status": "not_configured"}


def test_lookup_urlhaus_ok_with_key(monkeypatch):
    threat_intel_session.set_credentials(None, None, "abusech-key")
    fake = _FakeResponse(200, {"query_status": "no_results"})
    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", lambda timeout=None: _FakeAsyncClient(fake))

    result = asyncio.run(threat_intel.lookup_urlhaus("example.com", "domain"))
    assert result == {"status": "ok", "data": {"found": False}}


def test_lookup_urlhaus_not_applicable_for_sha1_even_without_a_key():
    """Applicability is checked before configuration — a sha1 hash is unsupported by
    URLhaus's payload endpoint regardless of whether a key is set."""
    result = asyncio.run(threat_intel.lookup_urlhaus("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash"))
    assert result == {"status": "not_applicable"}


def test_lookup_threatfox_not_configured_without_abusech_key():
    result = asyncio.run(threat_intel.lookup_threatfox("8.8.8.8", "ip"))
    assert result == {"status": "not_configured"}


def test_lookup_threatfox_ok(monkeypatch):
    threat_intel_session.set_credentials(None, None, "abusech-key")
    fake = _FakeResponse(200, {"query_status": "ok", "data": [{"malware_printable": "Emotet", "threat_type": "botnet_cc", "confidence_level": 90, "first_seen": "2026-01-01"}]})
    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", lambda timeout=None: _FakeAsyncClient(fake))

    result = asyncio.run(threat_intel.lookup_threatfox("8.8.8.8", "ip"))
    assert result["status"] == "ok"
    assert result["data"]["malware"] == "Emotet"


def test_lookup_source_error_is_isolated(monkeypatch):
    """A source raising an exception becomes {"status": "error"} rather than propagating."""
    threat_intel_session.set_credentials(None, None, "abusech-key")

    class _RaisingClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **kw):
            raise ConnectionError("network unreachable")

    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", lambda timeout=None: _RaisingClient())
    result = asyncio.run(threat_intel.lookup_threatfox("8.8.8.8", "ip"))
    assert result["status"] == "error"
    assert "network unreachable" in result["error"]


# ---- lookup_all orchestration ----

def test_lookup_all_isolates_one_failing_source(monkeypatch):
    """VirusTotal/AbuseIPDB unconfigured, URLhaus errors, ThreatFox succeeds — the whole
    response still comes back with all four keys, not an exception."""
    async def fake_urlhaus(indicator, itype):
        return {"status": "error", "error": "boom"}

    async def fake_threatfox(indicator, itype):
        return {"status": "ok", "data": {"found": True, "ioc_count": 1}}

    monkeypatch.setattr(threat_intel, "lookup_urlhaus", fake_urlhaus)
    monkeypatch.setattr(threat_intel, "lookup_threatfox", fake_threatfox)

    result = asyncio.run(threat_intel.lookup_all("8.8.8.8"))
    assert result["indicator_type"] == "ip"
    assert result["sources"]["virustotal"]["status"] == "not_configured"
    assert result["sources"]["abuseipdb"]["status"] == "not_configured"
    assert result["sources"]["urlhaus"]["status"] == "error"
    assert result["sources"]["threatfox"]["status"] == "ok"


def test_lookup_all_caches_repeat_lookups(monkeypatch):
    call_count = {"n": 0}

    async def fake_threatfox(indicator, itype):
        call_count["n"] += 1
        return {"status": "ok", "data": {"found": False}}

    monkeypatch.setattr(threat_intel, "lookup_urlhaus", fake_threatfox)
    monkeypatch.setattr(threat_intel, "lookup_threatfox", fake_threatfox)

    asyncio.run(threat_intel.lookup_all("1.2.3.4"))
    asyncio.run(threat_intel.lookup_all("1.2.3.4"))
    asyncio.run(threat_intel.lookup_all("1.2.3.4"))

    # Two sources called once each on the first lookup only — the next two calls hit the cache.
    assert call_count["n"] == 2


def test_clear_cache_prevents_stale_not_configured_result(monkeypatch):
    """Regression: a lookup made before any key was set used to stay cached as
    'not_configured' for the full TTL even after an admin added a real key — the endpoint
    calls threat_intel.clear_cache() whenever credentials change specifically to prevent
    this."""
    result1 = asyncio.run(threat_intel.lookup_all("8.8.8.8"))
    assert result1["sources"]["virustotal"]["status"] == "not_configured"

    threat_intel_session.set_credentials("real-key", None, None)
    fake = _FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 60}}}})
    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", lambda timeout=None: _FakeAsyncClient(fake))

    # Without the fix, this would still read "not_configured" from the cached first call.
    threat_intel.clear_cache()
    result2 = asyncio.run(threat_intel.lookup_all("8.8.8.8"))
    assert result2["sources"]["virustotal"]["status"] == "ok"


# ---- endpoints ----

def test_threat_intel_credentials_admin_only(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "alice", "password_hash": hash_password("alice-pw"), "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "alice", "alice-pw")
    resp = client.post(
        "/api/integrations/threat-intel/credentials",
        json={"virustotal_api_key": "x"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_threat_intel_credentials_set_status_clear(client, mock_db):
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post(
        "/api/integrations/threat-intel/credentials",
        json={"virustotal_api_key": "vt-key", "abuseipdb_api_key": None},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["virustotal_configured"] is True
    assert resp.json()["abuseipdb_configured"] is False

    status = client.get("/api/integrations/threat-intel/status", headers=headers).json()
    assert status["virustotal_configured"] is True

    cleared = client.delete("/api/integrations/threat-intel/credentials", headers=headers)
    assert cleared.status_code == 200
    assert cleared.json()["virustotal_configured"] is False


def test_lookup_endpoint_requires_indicator(client, mock_db):
    token = _login(client)
    resp = client.get("/api/threat-intel/lookup?indicator=", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 422


def test_lookup_endpoint_returns_combined_result(client, mock_db, monkeypatch):
    token = _login(client)

    async def fake_lookup_all(indicator):
        return {"indicator": indicator, "indicator_type": "ip", "sources": {"urlhaus": {"status": "ok", "data": {"found": False}}}}

    monkeypatch.setattr("app.main.threat_intel.lookup_all", fake_lookup_all)
    resp = client.get("/api/threat-intel/lookup?indicator=8.8.8.8", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["indicator_type"] == "ip"

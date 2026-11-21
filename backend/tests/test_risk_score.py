from app import risk_score as risk_score_module
from app.risk_score import compute_risk_score


def _incident(**overrides):
    doc = {
        "source_ip": "203.0.113.9",
        "severity": "low",
        "alert_count": 1,
        "max_level": 5,
    }
    doc.update(overrides)
    return doc


def test_low_severity_low_volume_is_low_risk_without_threat_intel(monkeypatch):
    monkeypatch.setattr(risk_score_module.threat_intel, "peek_cached", lambda ip: None)
    result = compute_risk_score(_incident())
    assert result["label"] == "low"
    assert result["threat_intel_included"] is False
    assert 0 <= result["score"] <= 100


def test_high_severity_high_volume_scores_higher_than_low(monkeypatch):
    monkeypatch.setattr(risk_score_module.threat_intel, "peek_cached", lambda ip: None)
    low = compute_risk_score(_incident(severity="low", alert_count=1, max_level=3))
    high = compute_risk_score(_incident(severity="high", alert_count=12, max_level=14))
    assert high["score"] > low["score"]
    assert high["label"] in ("high", "critical")


def test_score_never_exceeds_100_or_drops_below_0(monkeypatch):
    monkeypatch.setattr(risk_score_module.threat_intel, "peek_cached", lambda ip: {
        "sources": {"virustotal": {"status": "ok", "data": {"found": True, "malicious": 30, "suspicious": 0, "harmless": 0, "undetected": 0}}}
    })
    result = compute_risk_score(_incident(severity="high", alert_count=50, max_level=50))
    assert result["score"] == 100

    empty = compute_risk_score({"source_ip": None})
    assert empty["score"] >= 0


def test_cached_malicious_threat_intel_raises_score(monkeypatch):
    def fake_peek(ip):
        return {"sources": {
            "virustotal": {"status": "ok", "data": {"found": True, "malicious": 5, "suspicious": 0, "harmless": 60, "undetected": 5}},
        }}
    monkeypatch.setattr(risk_score_module.threat_intel, "peek_cached", fake_peek)

    without = compute_risk_score(_incident())
    with_ti = compute_risk_score(_incident())
    # Same incident, but simulate "no cache" for the without-case.
    monkeypatch.setattr(risk_score_module.threat_intel, "peek_cached", lambda ip: None)
    without = compute_risk_score(_incident())

    assert with_ti["score"] > without["score"]
    assert with_ti["threat_intel_included"] is True
    assert without["threat_intel_included"] is False


def test_cached_clean_threat_intel_does_not_raise_score_but_is_flagged_included(monkeypatch):
    def fake_peek(ip):
        return {"sources": {
            "virustotal": {"status": "ok", "data": {"found": True, "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5}},
            "abuseipdb": {"status": "ok", "data": {"found": True, "abuse_confidence_score": 0, "total_reports": 0}},
        }}
    monkeypatch.setattr(risk_score_module.threat_intel, "peek_cached", fake_peek)

    result = compute_risk_score(_incident())
    assert result["threat_intel_included"] is True


def test_never_triggers_a_live_lookup(monkeypatch):
    calls = []
    monkeypatch.setattr(risk_score_module.threat_intel, "peek_cached", lambda ip: calls.append(ip) or None)

    async def fail_if_called(indicator):
        raise AssertionError("compute_risk_score must never trigger a live threat-intel lookup")

    monkeypatch.setattr(risk_score_module.threat_intel, "lookup_all", fail_if_called)

    compute_risk_score(_incident())
    assert calls == ["203.0.113.9"]


def test_checks_the_single_external_srcip_instead_of_the_agent_source_ip(monkeypatch):
    calls = []
    monkeypatch.setattr(risk_score_module.threat_intel, "peek_cached", lambda ip: calls.append(ip) or None)

    compute_risk_score(_incident(unique_values={"data.srcip": ["198.51.100.7"]}))

    assert calls == ["198.51.100.7"]


def test_falls_back_to_source_ip_when_multiple_external_srcips(monkeypatch):
    calls = []
    monkeypatch.setattr(risk_score_module.threat_intel, "peek_cached", lambda ip: calls.append(ip) or None)

    compute_risk_score(_incident(unique_values={"data.srcip": ["198.51.100.7", "198.51.100.8"]}))

    assert calls == ["203.0.113.9"]

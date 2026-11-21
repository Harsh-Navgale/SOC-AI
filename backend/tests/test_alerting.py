import asyncio

from app import alerting


def teardown_function(_):
    alerting._consecutive_failures.clear()
    alerting._active_alerts.clear()


def test_alert_activates_only_after_threshold_consecutive_failures(monkeypatch):
    broadcasts = []
    monkeypatch.setattr(alerting.ws_manager, "broadcast", lambda msg: broadcasts.append(msg) or asyncio.sleep(0))

    asyncio.run(alerting.record_failure("poll_wazuh", "boom"))
    asyncio.run(alerting.record_failure("poll_wazuh", "boom"))
    assert alerting.active_alerts() == []  # 2 failures, threshold is 3 — not active yet

    asyncio.run(alerting.record_failure("poll_wazuh", "boom"))
    active = alerting.active_alerts()
    assert len(active) == 1
    assert active[0]["source"] == "poll_wazuh"
    assert len(broadcasts) == 1
    assert broadcasts[0]["type"] == "alert_triggered"


def test_alert_does_not_re_broadcast_while_still_failing(monkeypatch):
    broadcasts = []
    monkeypatch.setattr(alerting.ws_manager, "broadcast", lambda msg: broadcasts.append(msg) or asyncio.sleep(0))

    for _ in range(5):
        asyncio.run(alerting.record_failure("auto_investigate_cases", "still down"))

    assert len(alerting.active_alerts()) == 1
    assert len(broadcasts) == 1  # activated once, not once per failure


def test_success_clears_an_active_alert_and_broadcasts_recovery(monkeypatch):
    broadcasts = []
    monkeypatch.setattr(alerting.ws_manager, "broadcast", lambda msg: broadcasts.append(msg) or asyncio.sleep(0))

    for _ in range(3):
        asyncio.run(alerting.record_failure("correlator", "down"))
    assert len(alerting.active_alerts()) == 1

    asyncio.run(alerting.record_success("correlator"))
    assert alerting.active_alerts() == []
    assert broadcasts[-1]["type"] == "alert_resolved"


def test_success_with_no_active_alert_is_a_no_op(monkeypatch):
    broadcasts = []
    monkeypatch.setattr(alerting.ws_manager, "broadcast", lambda msg: broadcasts.append(msg) or asyncio.sleep(0))

    asyncio.run(alerting.record_success("poll_wazuh"))

    assert broadcasts == []


def test_webhook_is_posted_when_configured(monkeypatch):
    posted = {}

    class FakeResponse:
        pass

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def post(self, url, json):
            posted["url"] = url
            posted["json"] = json
            return FakeResponse()

    monkeypatch.setattr(alerting, "ALERT_WEBHOOK_URL", "https://hooks.example/incoming")
    monkeypatch.setattr(alerting.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(alerting.ws_manager, "broadcast", lambda msg: asyncio.sleep(0))

    for _ in range(3):
        asyncio.run(alerting.record_failure("poll_wazuh", "unreachable"))

    assert posted["url"] == "https://hooks.example/incoming"
    assert "poll_wazuh" in posted["json"]["text"]


def test_webhook_not_posted_when_unconfigured(monkeypatch):
    called = {"n": 0}

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            called["n"] += 1

    monkeypatch.setattr(alerting, "ALERT_WEBHOOK_URL", None)
    monkeypatch.setattr(alerting.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(alerting.ws_manager, "broadcast", lambda msg: asyncio.sleep(0))

    for _ in range(3):
        asyncio.run(alerting.record_failure("poll_wazuh", "unreachable"))

    assert called["n"] == 0

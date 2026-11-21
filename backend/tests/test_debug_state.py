import asyncio
import logging

import pytest
from mongomock_motor import AsyncMongoMockClient

from app import debug_state


@pytest.fixture(autouse=True)
def _mock_system_settings(monkeypatch):
    mock_client = AsyncMongoMockClient()
    db = mock_client["soc_ai_debug_state_test"]
    monkeypatch.setattr(debug_state, "system_settings", db["system_settings"])
    yield db


def teardown_function(_):
    # Reset the in-memory flag/logger level directly rather than through set_debug_mode() —
    # the autouse mongomock fixture above has already torn down by the time this xunit-style
    # hook runs, and a fresh asyncio.run() here would try to use a Mongo client bound to that
    # fixture's now-closed event loop.
    debug_state.debug_mode_enabled = False
    logging.getLogger("soc").setLevel(logging.INFO)
    debug_state._recent_errors.clear()


def test_set_debug_mode_raises_soc_logger_to_debug():
    asyncio.run(debug_state.set_debug_mode(True))
    assert logging.getLogger("soc").level == logging.DEBUG
    assert debug_state.get_debug_mode() is True

    asyncio.run(debug_state.set_debug_mode(False))
    assert logging.getLogger("soc").level == logging.INFO
    assert debug_state.get_debug_mode() is False


def test_set_debug_mode_persists_to_mongo(_mock_system_settings):
    asyncio.run(debug_state.set_debug_mode(True))

    doc = asyncio.run(_mock_system_settings["system_settings"].find_one({"_id": "debug_mode"}))
    assert doc["enabled"] is True


def test_load_debug_mode_restores_persisted_true_value():
    asyncio.run(debug_state.set_debug_mode(True))
    debug_state.debug_mode_enabled = False  # simulate a fresh process before the reload

    asyncio.run(debug_state.load_debug_mode())

    assert debug_state.get_debug_mode() is True
    assert logging.getLogger("soc").level == logging.DEBUG


def test_load_debug_mode_defaults_to_false_when_nothing_persisted():
    asyncio.run(debug_state.load_debug_mode())
    assert debug_state.get_debug_mode() is False


def test_recent_errors_are_newest_first():
    debug_state.record_error("a", "first")
    debug_state.record_error("b", "second")

    errors = debug_state.recent_errors()
    assert errors[0]["source"] == "b"
    assert errors[1]["source"] == "a"


def test_recent_errors_ring_buffer_caps_at_twenty():
    for i in range(25):
        debug_state.record_error("job", f"error {i}")

    errors = debug_state.recent_errors()
    assert len(errors) == 20
    assert errors[0]["detail"] == "error 24"

import asyncio

import pytest

from app import ws_manager


def _login(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
    return resp.json()["access_token"]


def test_ws_events_rejects_missing_or_invalid_token(client, mock_db):
    with pytest.raises(Exception):
        with client.websocket_connect("/api/ws/events?token=not-a-real-token"):
            pass


def test_ws_events_rejects_no_token(client, mock_db):
    with pytest.raises(Exception):
        with client.websocket_connect("/api/ws/events"):
            pass


class _FakeWebSocket:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    async def accept(self):
        pass

    async def send_json(self, message):
        if self.fail:
            raise RuntimeError("connection closed")
        self.sent.append(message)


def test_ws_manager_broadcast_reaches_connected_clients():
    async def scenario():
        ws1, ws2 = _FakeWebSocket(), _FakeWebSocket()
        await ws_manager.connect(ws1)
        await ws_manager.connect(ws2)
        await ws_manager.broadcast({"type": "incidents_changed"})
        assert ws1.sent == [{"type": "incidents_changed"}]
        assert ws2.sent == [{"type": "incidents_changed"}]
        ws_manager.disconnect(ws1)
        ws_manager.disconnect(ws2)

    asyncio.run(scenario())


def test_ws_manager_prunes_dead_connections_on_send_failure():
    async def scenario():
        alive, dead = _FakeWebSocket(), _FakeWebSocket(fail=True)
        await ws_manager.connect(alive)
        await ws_manager.connect(dead)

        await ws_manager.broadcast({"type": "alerts_changed"})
        assert alive.sent == [{"type": "alerts_changed"}]

        # The failed send should have pruned `dead` — a second broadcast must not error and
        # must not reach it again (it's already gone).
        await ws_manager.broadcast({"type": "alerts_changed"})
        assert alive.sent == [{"type": "alerts_changed"}, {"type": "alerts_changed"}]

        ws_manager.disconnect(alive)

    asyncio.run(scenario())

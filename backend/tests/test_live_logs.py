import asyncio
import logging

import pytest

from app import live_logs


@pytest.fixture(autouse=True)
def _reset_live_logs_state():
    live_logs._recent_lines.clear()
    live_logs._listeners.clear()
    yield
    live_logs._recent_lines.clear()
    live_logs._listeners.clear()


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


# ---- _BroadcastLogHandler / stream() ----

def test_emit_appends_formatted_line_to_recent_buffer():
    handler = live_logs._BroadcastLogHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    record = logging.LogRecord("soc.test", logging.INFO, __file__, 1, "hello world", None, None)

    handler.emit(record)

    assert list(live_logs._recent_lines) == ["INFO hello world"]


def test_emit_broadcasts_to_every_listener_queue():
    handler = live_logs._BroadcastLogHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    q1, q2 = asyncio.Queue(), asyncio.Queue()
    live_logs._listeners.add(q1)
    live_logs._listeners.add(q2)

    record = logging.LogRecord("soc.test", logging.INFO, __file__, 1, "line one", None, None)
    handler.emit(record)

    assert q1.get_nowait() == "line one"
    assert q2.get_nowait() == "line one"


def test_emit_drops_oldest_for_a_full_listener_queue_rather_than_blocking():
    handler = live_logs._BroadcastLogHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    q = asyncio.Queue(maxsize=2)
    q.put_nowait("keep-me-out")
    q.put_nowait("also-out")
    live_logs._listeners.add(q)

    record = logging.LogRecord("soc.test", logging.INFO, __file__, 1, "newest", None, None)
    handler.emit(record)

    # The queue never grows past its maxsize, and the newest line always wins a spot.
    assert q.qsize() == 2
    remaining = [q.get_nowait(), q.get_nowait()]
    assert remaining[-1] == "newest"


def test_stream_replays_recent_buffer_before_going_live():
    live_logs._recent_lines.extend(["old line 1", "old line 2"])

    async def collect_first_n(n):
        gen = live_logs.stream()
        out = []
        for _ in range(n):
            out.append(await gen.__anext__())
        await gen.aclose()
        return out

    lines = asyncio.run(collect_first_n(2))
    assert lines == ["old line 1\n", "old line 2\n"]


def test_stream_registers_and_unregisters_a_listener_queue():
    async def run():
        gen = live_logs.stream()
        # Prime the generator up to the point it's waiting on the live queue.
        task = asyncio.ensure_future(gen.__anext__())
        await asyncio.sleep(0.05)
        assert len(live_logs._listeners) == 1
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await gen.aclose()

    asyncio.run(run())
    assert len(live_logs._listeners) == 0


def test_stream_yields_new_lines_broadcast_after_it_starts():
    async def run():
        gen = live_logs.stream()
        task = asyncio.ensure_future(gen.__anext__())
        await asyncio.sleep(0.05)  # let stream() reach `await queue.get()` and register its queue

        handler = live_logs._BroadcastLogHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        handler.emit(logging.LogRecord("soc.test", logging.INFO, __file__, 1, "live line", None, None))

        line = await asyncio.wait_for(task, timeout=1)
        await gen.aclose()
        return line

    assert asyncio.run(run()) == "live line\n"


# ---- GET /api/debug/logs/all: only the auth-rejection paths — the endpoint's success path is
# an infinite stream and isn't something a synchronous TestClient .get() can safely consume
# without hanging, so that's covered at the live_logs unit level above instead. ----

def test_stream_logs_requires_a_token(client, mock_db):
    resp = client.get("/api/debug/logs/all")
    assert resp.status_code == 401


def test_stream_logs_rejects_an_invalid_token(client, mock_db):
    resp = client.get("/api/debug/logs/all", params={"token": "not-a-real-token"})
    assert resp.status_code == 401


def test_stream_logs_rejects_a_non_admin_token(client, mock_db):
    from app.auth import hash_password
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"), "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")
    resp = client.get("/api/debug/logs/all", params={"token": token})
    assert resp.status_code == 403

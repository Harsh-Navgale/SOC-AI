"""In-process WebSocket broadcast hub for live incident/alert updates. No Redis or other shared
pub/sub in this stack — this is a single backend container, so an in-memory connection set is
the right amount of infrastructure; it would need to move to a shared broker only if the backend
were ever scaled to multiple replicas, which it isn't.
"""
import logging

from fastapi import WebSocket

logger = logging.getLogger("soc.ws")

_connections: set[WebSocket] = set()


async def connect(websocket: WebSocket):
    await websocket.accept()
    _connections.add(websocket)


def disconnect(websocket: WebSocket):
    _connections.discard(websocket)


async def broadcast(message: dict):
    dead = []
    for ws in list(_connections):
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _connections.discard(ws)

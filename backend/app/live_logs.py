"""Real-time plain-text log tailing for GET /api/debug/logs/all. Attached to the root logger
(not just "soc.*") — the whole point of this endpoint is "everything happening in this process",
which includes uvicorn's own access logs and apscheduler's job-run lines, not just this app's own
loggers. Scope is deliberately this one container: reaching into the correlator/frontend/mongodb
containers' own log streams would mean mounting the Docker socket into the backend, which is a
much bigger, genuinely security-sensitive change this doesn't make on its own.
"""
import asyncio
import logging
from collections import deque

_BUFFER_SIZE = 500  # replayed to a client the moment it connects, so it isn't staring at nothing
_QUEUE_MAXSIZE = 1000  # per connection; a slow/stalled client drops its own oldest lines instead
# of this growing without bound.

_recent_lines: deque[str] = deque(maxlen=_BUFFER_SIZE)
_listeners: set[asyncio.Queue] = set()


class _BroadcastLogHandler(logging.Handler):
    def emit(self, record):
        try:
            line = self.format(record)
        except Exception:
            return
        _recent_lines.append(line)
        # Logging handlers run synchronously and, in this app, always from the event loop's own
        # thread (nothing here logs from a worker thread), so plain Queue.put_nowait is safe —
        # it never actually awaits anything, it just mutates the queue's internal deque.
        for q in list(_listeners):
            try:
                q.put_nowait(line)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()  # drop this listener's oldest line to make room for the newest
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(line)
                except asyncio.QueueFull:
                    pass


def install():
    handler = _BroadcastLogHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.getLogger().addHandler(handler)


async def stream():
    """Yields the recent buffer first, then every new log line as it's emitted, for as long as
    the caller keeps consuming — a StreamingResponse simply stops iterating this once the client
    disconnects, which is what ends the loop below."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
    for line in list(_recent_lines):
        yield line + "\n"
    _listeners.add(queue)
    try:
        while True:
            line = await queue.get()
            yield line + "\n"
    finally:
        _listeners.discard(queue)

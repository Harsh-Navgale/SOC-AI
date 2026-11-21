"""Admin-only debug mode: a runtime switch (not a config file setting) so it can be flipped
on/off without a restart. Turning it on does two things — raises the "soc.*" logger namespace
to DEBUG (every submodule logger here is created as "soc.<name>" with no explicit level of its
own, so this one call affects all of them via normal logging-hierarchy inheritance), and gates
whether the frontend shows raw AI prompt/response tracing. `recent_errors` is a small in-memory
ring buffer the background scheduler jobs write to, surfaced on the diagnostics endpoint so an
admin doesn't have to `docker compose logs backend` to see what a failing job actually hit.

Unlike the pipeline pause toggles (auto_investigate_enabled, alert_ingestion_enabled —
deliberate safety valves that are SUPPOSED to reset to their safe default on a restart), an
admin turning debug mode on is a standing diagnostic preference, not a safety valve — it's
persisted in Mongo and reloaded at startup (see load_debug_mode(), called from main.py's
lifespan) so a backend restart doesn't silently turn off incident/AI-chat prompt tracing an
admin is actively relying on. get_debug_mode() itself still just reads the in-memory flag —
every real caller is on a hot path (logging, request handling) that shouldn't pay for a Mongo
round trip — set_debug_mode()/load_debug_mode() are what keep it in sync with the persisted copy.
"""
import logging
from collections import deque
from datetime import datetime, timezone

from app.db import system_settings

logger = logging.getLogger("soc.debug")

_SOC_LOGGER = logging.getLogger("soc")

debug_mode_enabled = False

_MAX_RECENT_ERRORS = 20
_recent_errors: deque = deque(maxlen=_MAX_RECENT_ERRORS)


def get_debug_mode() -> bool:
    return debug_mode_enabled


async def set_debug_mode(enabled: bool):
    global debug_mode_enabled
    debug_mode_enabled = enabled
    _SOC_LOGGER.setLevel(logging.DEBUG if enabled else logging.INFO)
    await system_settings.update_one({"_id": "debug_mode"}, {"$set": {"enabled": enabled}}, upsert=True)


async def load_debug_mode():
    global debug_mode_enabled
    doc = await system_settings.find_one({"_id": "debug_mode"})
    debug_mode_enabled = bool(doc and doc.get("enabled"))
    _SOC_LOGGER.setLevel(logging.DEBUG if debug_mode_enabled else logging.INFO)


def record_error(source: str, detail: str):
    _recent_errors.appendleft({
        "source": source,
        "detail": detail,
        "at": datetime.now(timezone.utc).isoformat(),
    })


def recent_errors() -> list[dict]:
    return list(_recent_errors)

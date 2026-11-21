"""Alerting for scheduler/correlator failure states — the gap that let a past AI-provider outage
go unnoticed for hours. Two channels, both best-effort: an in-app banner (via the existing WS
broadcast — see ws_manager) that every connected dashboard picks up immediately, and an optional
generic webhook (Slack Incoming Webhooks and most chat-ops tools accept a bare {"text": ...}
POST) for when nobody happens to have the tab open. Neither channel is required for the other to
work; an unset ALERT_WEBHOOK_URL just means "in-app only," not "alerting disabled."

An alert activates only after `ALERT_FAILURE_THRESHOLD` consecutive failures from the same
source — a single blip (one dropped connection) is normal and expected; a streak is not. It
clears automatically on the next success, with its own "recovered" notification, so a fixed
problem doesn't sit there looking broken forever.
"""
import logging

import httpx

from app import ws_manager
from app.config import ALERT_WEBHOOK_URL, ALERT_FAILURE_THRESHOLD

logger = logging.getLogger("soc.alerting")

_consecutive_failures: dict[str, int] = {}
_active_alerts: dict[str, dict] = {}


async def _dispatch_webhook(text: str):
    if not ALERT_WEBHOOK_URL:
        return
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(ALERT_WEBHOOK_URL, json={"text": text})
    except Exception:
        logger.exception("Failed to deliver alert webhook (in-app banner is unaffected)")


async def record_failure(source: str, detail: str):
    count = _consecutive_failures.get(source, 0) + 1
    _consecutive_failures[source] = count

    if count < ALERT_FAILURE_THRESHOLD or source in _active_alerts:
        return

    message = f"{source} has failed {count} times in a row: {detail}"
    _active_alerts[source] = {"source": source, "message": message, "count": count}
    logger.warning("Alert activated: %s", message)
    await ws_manager.broadcast({"type": "alert_triggered", "source": source, "message": message})
    await _dispatch_webhook(f":rotating_light: SOC-AI alert — {message}")


async def record_success(source: str):
    _consecutive_failures[source] = 0
    if source not in _active_alerts:
        return

    del _active_alerts[source]
    message = f"{source} has recovered"
    logger.info(message)
    await ws_manager.broadcast({"type": "alert_resolved", "source": source, "message": message})
    await _dispatch_webhook(f":white_check_mark: SOC-AI — {message}")


def active_alerts() -> list[dict]:
    return list(_active_alerts.values())

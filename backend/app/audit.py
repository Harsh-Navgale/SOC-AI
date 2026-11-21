"""Audit trail for admin-sensitive and case-workflow actions. A SOC tool that can't say who
closed a case, added/removed a user, or changed an integration credential is missing exactly the
kind of accountability record it exists to provide for everything else.
"""
import logging
import uuid
from datetime import datetime, timezone

from app.db import db

logger = logging.getLogger("soc.audit")

audit_log = db["audit_log"]


async def log_action(actor: str, action: str, target: str | None = None, details: dict | None = None):
    try:
        await audit_log.insert_one({
            "_id": str(uuid.uuid4()),
            "actor": actor,
            "action": action,
            "target": target,
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:
        # Audit logging must never be the reason a real action (closing a case, deleting a
        # user) fails — log and move on rather than raising into the caller.
        logger.exception("Failed to write audit log entry for action=%s target=%s", action, target)

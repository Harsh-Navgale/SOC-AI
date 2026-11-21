"""In-app notifications — case assignment and case-aging alerts. Deliberately simple: a flat
Mongo collection, no per-connection WS targeting. Every client just refetches its own filtered
list whenever a shared "notifications_changed" ping arrives (the same pattern already used for
alerts_changed/incidents_changed), rather than the backend tracking which socket belongs to
which logged-in user.
"""
import uuid
from datetime import datetime, timezone

from app.db import notifications as notifications_collection


def _visibility_query(username: str, is_admin: bool) -> dict:
    # An assigned case notifies that analyst specifically; an unassigned aging case (user=None)
    # is an admin's problem to triage, not every analyst's.
    if is_admin:
        return {"$or": [{"user": username}, {"user": None}]}
    return {"user": username}


async def create(message: str, type_: str, user: str | None = None, incident_id: str | None = None):
    doc = {
        "_id": str(uuid.uuid4()),
        "user": user,
        "type": type_,
        "message": message,
        "incident_id": incident_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "read": False,
    }
    await notifications_collection.insert_one(doc)
    return doc


async def list_for_user(username: str, is_admin: bool, limit: int = 50) -> list[dict]:
    cursor = notifications_collection.find(_visibility_query(username, is_admin)).sort("created_at", -1).limit(limit)
    return [doc async for doc in cursor]


async def unread_count(username: str, is_admin: bool) -> int:
    query = dict(_visibility_query(username, is_admin))
    query["read"] = False
    return await notifications_collection.count_documents(query)


async def mark_read(notification_id: str):
    await notifications_collection.update_one({"_id": notification_id}, {"$set": {"read": True}})


async def mark_all_read(username: str, is_admin: bool):
    await notifications_collection.update_many(_visibility_query(username, is_admin), {"$set": {"read": True}})

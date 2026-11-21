import asyncio

from mongomock_motor import AsyncMongoMockClient

from app import notifications


def _db(monkeypatch):
    mock_client = AsyncMongoMockClient()
    db = mock_client["soc_ai_notifications_test"]
    monkeypatch.setattr(notifications, "notifications_collection", db["notifications"])
    return db["notifications"]


def test_assigned_notification_visible_only_to_that_analyst(monkeypatch):
    col = _db(monkeypatch)
    asyncio.run(notifications.create("you got a case", "case_assigned", user="eve", incident_id="inc-1"))

    eve_items = asyncio.run(notifications.list_for_user("eve", is_admin=False))
    bob_items = asyncio.run(notifications.list_for_user("bob", is_admin=False))

    assert len(eve_items) == 1
    assert bob_items == []


def test_unassigned_aging_notification_visible_to_admins_only(monkeypatch):
    _db(monkeypatch)
    asyncio.run(notifications.create("case aging", "case_aging", user=None, incident_id="inc-2"))

    admin_items = asyncio.run(notifications.list_for_user("admin", is_admin=True))
    analyst_items = asyncio.run(notifications.list_for_user("eve", is_admin=False))

    assert len(admin_items) == 1
    assert analyst_items == []


def test_unread_count_and_mark_read(monkeypatch):
    _db(monkeypatch)
    doc = asyncio.run(notifications.create("hi", "case_assigned", user="eve"))
    asyncio.run(notifications.create("hi again", "case_assigned", user="eve"))

    assert asyncio.run(notifications.unread_count("eve", is_admin=False)) == 2

    asyncio.run(notifications.mark_read(doc["_id"]))
    assert asyncio.run(notifications.unread_count("eve", is_admin=False)) == 1


def test_mark_all_read_for_admin_clears_own_and_unassigned(monkeypatch):
    _db(monkeypatch)
    asyncio.run(notifications.create("assigned to admin", "case_assigned", user="admin"))
    asyncio.run(notifications.create("unassigned aging", "case_aging", user=None))

    asyncio.run(notifications.mark_all_read("admin", is_admin=True))

    assert asyncio.run(notifications.unread_count("admin", is_admin=True)) == 0

import asyncio

from app.auth import hash_password


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def _create_analyst(mock_db, username="alice", password="alice-pw"):
    asyncio.run(mock_db["users"].insert_one({
        "_id": username,
        "password_hash": hash_password(password),
        "role": "analyst",
        "created_at": "2026-01-01T00:00:00+00:00",
    }))


# /api/ai/models (Bedrock-only) is covered in test_bedrock_integration.py.


def _fake_ask_ai_factory(captured, answer="ok", elapsed=0.5, sources=None, chunks=None):
    async def fake_ask_ai(question, model=None, history=None, incident_context=""):
        captured["question"] = question
        captured["model"] = model
        captured["history"] = history
        return {
            "answer": answer,
            "sources": sources or [],
            "context_chunks": chunks or [],
            "model": model or "phi3:mini",
            "elapsed_seconds": elapsed,
        }
    return fake_ask_ai


def test_ask_passes_model_through(client, mock_db, monkeypatch):
    token = _login(client)
    captured = {}
    monkeypatch.setattr(
        "app.main.ask_ai",
        _fake_ask_ai_factory(captured, answer="Block the IP and rotate credentials.",
                              elapsed=1.23, sources=["case-123"],
                              chunks=[{"source": "case-123", "text": "Past incident notes"}]),
    )

    resp = client.post(
        "/api/ask",
        json={"question": "What should I do about repeated SSH failures?", "model": "llama3.1:8b"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["model"] == "llama3.1:8b"
    assert body["elapsed_seconds"] == 1.23
    assert body["context_chunks"][0]["source"] == "case-123"
    assert captured["model"] == "llama3.1:8b"
    assert captured["history"] is None


def test_ask_returns_and_persists_prompt_for_debug_tracing(client, mock_db, monkeypatch):
    token = _login(client)

    async def fake_ask_ai(question, model=None, history=None, incident_context=""):
        return {
            "answer": "ok", "sources": [], "context_chunks": [],
            "model": model or "phi3:mini", "elapsed_seconds": 0.1,
            "prompt": f"SYSTEM PROMPT\n\nQuestion: {question}",
        }

    monkeypatch.setattr("app.main.ask_ai", fake_ask_ai)

    resp = client.post("/api/ask", json={"question": "why is this IP flagged?"}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["prompt"] == "SYSTEM PROMPT\n\nQuestion: why is this IP flagged?"

    convo = client.get(f"/api/conversations/{body['conversation_id']}", headers={"Authorization": f"Bearer {token}"}).json()
    assistant_msg = next(m for m in convo["messages"] if m["role"] == "assistant")
    assert assistant_msg["prompt"] == "SYSTEM PROMPT\n\nQuestion: why is this IP flagged?"


def test_ask_without_model_creates_conversation(client, mock_db, monkeypatch):
    token = _login(client)
    captured = {}
    monkeypatch.setattr("app.main.ask_ai", _fake_ask_ai_factory(captured))

    resp = client.post("/api/ask", json={"question": "hello"}, headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    body = resp.json()
    assert captured["model"] is None
    assert captured["history"] is None
    assert body["conversation_id"]

    convo = asyncio.run(mock_db["conversations"].find_one({"_id": body["conversation_id"]}))
    assert convo["author"] == "admin"
    assert convo["title"] == "hello"
    assert convo["message_count"] == 2
    assert [m["role"] for m in convo["messages"]] == ["user", "assistant"]


def test_ask_with_conversation_id_appends_and_builds_history_from_any_user(client, mock_db, monkeypatch):
    """Conversations are shared team-wide, not owned by a single user — a second analyst
    should be able to continue someone else's conversation, and the prior turns (from
    whoever sent them) become the history passed to ask_ai."""
    admin_token = _login(client)
    captured = {}
    monkeypatch.setattr("app.main.ask_ai", _fake_ask_ai_factory(captured, answer="first answer"))

    first = client.post(
        "/api/ask", json={"question": "What is a brute-force attack?"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    conversation_id = first.json()["conversation_id"]

    _create_analyst(mock_db)
    alice_token = _login(client, "alice", "alice-pw")
    monkeypatch.setattr("app.main.ask_ai", _fake_ask_ai_factory(captured, answer="second answer"))

    second = client.post(
        "/api/ask",
        json={"question": "How do I block it?", "conversation_id": conversation_id},
        headers={"Authorization": f"Bearer {alice_token}"},
    )

    assert second.status_code == 200
    assert second.json()["conversation_id"] == conversation_id
    assert captured["history"] == [
        {"role": "user", "content": "What is a brute-force attack?"},
        {"role": "assistant", "content": "first answer"},
    ]

    convo = asyncio.run(mock_db["conversations"].find_one({"_id": conversation_id}))
    assert convo["author"] == "admin"  # started by admin, unchanged
    assert convo["message_count"] == 4
    assert convo["messages"][2]["author"] == "alice"


def test_ask_with_unknown_conversation_id_returns_404(client, mock_db, monkeypatch):
    token = _login(client)
    monkeypatch.setattr("app.main.ask_ai", _fake_ask_ai_factory({}))

    resp = client.post(
        "/api/ask", json={"question": "hi", "conversation_id": "does-not-exist"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


def test_list_conversations_shared_across_users(client, mock_db, monkeypatch):
    token = _login(client)
    monkeypatch.setattr("app.main.ask_ai", _fake_ask_ai_factory({}))
    client.post("/api/ask", json={"question": "hi"}, headers={"Authorization": f"Bearer {token}"})

    _create_analyst(mock_db)
    alice_token = _login(client, "alice", "alice-pw")

    resp = client.get("/api/conversations", headers={"Authorization": f"Bearer {alice_token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["author"] == "admin"
    assert body[0]["message_count"] == 2
    assert "messages" not in body[0]


def test_rename_and_delete_conversation_from_different_user(client, mock_db, monkeypatch):
    token = _login(client)
    monkeypatch.setattr("app.main.ask_ai", _fake_ask_ai_factory({}))
    created = client.post("/api/ask", json={"question": "hi"}, headers={"Authorization": f"Bearer {token}"})
    conversation_id = created.json()["conversation_id"]

    _create_analyst(mock_db)
    alice_token = _login(client, "alice", "alice-pw")
    alice_headers = {"Authorization": f"Bearer {alice_token}"}

    rename = client.patch(f"/api/conversations/{conversation_id}", json={"title": "Renamed by alice"}, headers=alice_headers)
    assert rename.status_code == 200
    assert rename.json()["title"] == "Renamed by alice"

    fetched = client.get(f"/api/conversations/{conversation_id}", headers=alice_headers)
    assert fetched.json()["title"] == "Renamed by alice"

    deleted = client.delete(f"/api/conversations/{conversation_id}", headers=alice_headers)
    assert deleted.status_code == 200

    missing = client.get(f"/api/conversations/{conversation_id}", headers=alice_headers)
    assert missing.status_code == 404


def test_rename_unknown_conversation_returns_404(client, mock_db):
    token = _login(client)
    resp = client.patch("/api/conversations/does-not-exist", json={"title": "x"}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 404

import asyncio
import json
import os

from app.alerts_upload import (
    parse_wazuh_alerts_file,
    sniff_is_json_array_or_object,
    iter_alerts_jsonl_file,
)
from app.auth import hash_password
from app import main as main_module
from app import upload_jobs


def _login(client, username="admin", password="test-password"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


ALERT_A = {"id": "1690000000.1", "timestamp": "2026-01-01T00:00:00+0000",
           "rule": {"level": 10, "description": "brute force"}, "agent": {"name": "web-01", "ip": "10.0.0.5"}}
ALERT_B = {"id": "1690000000.2", "timestamp": "2026-01-01T00:00:01+0000",
           "rule": {"level": 7, "description": "login ok"}, "agent": {"name": "web-02", "ip": "10.0.0.6"}}


# ---- parsing ----

def test_parse_json_array():
    text = json.dumps([ALERT_A, ALERT_B])
    assert parse_wazuh_alerts_file(text) == [ALERT_A, ALERT_B]


def test_parse_single_bare_object():
    assert parse_wazuh_alerts_file(json.dumps(ALERT_A)) == [ALERT_A]


SINGLE_HIT = {
    "_index": "wazuh-alerts-4.x-2026.08.21",
    "_id": "eB4BJqABJKeZtH7Ktpj5",
    "_version": 1,
    "_score": None,
    "_source": {
        "agent": {"ip": "10.15.12.35", "name": "web-host", "id": "40516"},
        "data": {"protocol": "POST", "srcip": "150.230.134.137", "id": "400", "url": "/api/lead/create"},
        "rule": {"level": 10, "description": "Multiple web server 400 error codes from same source ip.",
                 "id": "31151", "mitre": {"id": ["T1595.002"], "tactic": ["Reconnaissance"]}},
        "timestamp": "2026-08-22T01:57:14.782+0530",
        "id": "1787344034.10159158",
    },
    "fields": {"timestamp": ["2026-08-21T20:27:14.782Z"]},
    "sort": [1787344034782],
}


def test_parse_single_bare_opensearch_hit():
    # Exactly what "view single document JSON" in a Dashboard's Discover panel produces — one
    # raw hit, no hits.hits wrapper at all. The real alert fields live under _source.
    alerts = parse_wazuh_alerts_file(json.dumps(SINGLE_HIT))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule"]["description"] == "Multiple web server 400 error codes from same source ip."
    assert alert["agent"]["name"] == "web-host"
    assert alert["_id"] == "eB4BJqABJKeZtH7Ktpj5"
    # Wazuh's own alert id (nested under _source) survives too, alongside the OpenSearch _id.
    assert alert["id"] == "1787344034.10159158"


def test_parse_array_of_raw_hits_unwraps_each_one():
    hit_a = {**SINGLE_HIT, "_id": "hit-a"}
    hit_b = {**SINGLE_HIT, "_id": "hit-b", "_source": {**SINGLE_HIT["_source"], "id": "other-id"}}
    alerts = parse_wazuh_alerts_file(json.dumps([hit_a, hit_b]))
    assert len(alerts) == 2
    assert {a["_id"] for a in alerts} == {"hit-a", "hit-b"}


def test_parse_single_hit_nested_under_a_wrapper_key():
    wrapped = {"panel": "discover", "hit": SINGLE_HIT}
    alerts = parse_wazuh_alerts_file(json.dumps(wrapped))
    assert len(alerts) == 1
    assert alerts[0]["_id"] == "eB4BJqABJKeZtH7Ktpj5"


def test_parse_json_lines():
    text = json.dumps(ALERT_A) + "\n" + json.dumps(ALERT_B) + "\n"
    assert parse_wazuh_alerts_file(text) == [ALERT_A, ALERT_B]


def test_parse_json_lines_tolerates_trailing_comma_and_blank_lines():
    text = json.dumps(ALERT_A) + ",\n\n" + json.dumps(ALERT_B) + "\n"
    assert parse_wazuh_alerts_file(text) == [ALERT_A, ALERT_B]


def test_parse_json_lines_skips_garbage_lines():
    text = "not json\n" + json.dumps(ALERT_A) + "\n"
    assert parse_wazuh_alerts_file(text) == [ALERT_A]


def test_parse_empty_file_returns_empty_list():
    assert parse_wazuh_alerts_file("") == []
    assert parse_wazuh_alerts_file("   \n  ") == []


def test_parse_unwraps_opensearch_search_response():
    search_response = {
        "took": 5,
        "hits": {
            "total": {"value": 2},
            "hits": [
                {"_index": "wazuh-alerts-4.x", "_id": "os-id-1", "_source": ALERT_A},
                {"_index": "wazuh-alerts-4.x", "_id": "os-id-2", "_source": ALERT_B},
            ],
        },
    }
    alerts = parse_wazuh_alerts_file(json.dumps(search_response))
    assert len(alerts) == 2
    assert alerts[0]["_id"] == "os-id-1"
    assert alerts[0]["rule"]["description"] == "brute force"
    assert alerts[1]["_id"] == "os-id-2"


def test_parse_search_response_with_no_hits_returns_empty_list():
    search_response = {"took": 1, "hits": {"total": {"value": 0}, "hits": []}}
    assert parse_wazuh_alerts_file(json.dumps(search_response)) == []


def test_parse_unwraps_a_search_response_nested_under_an_arbitrary_wrapper_key():
    # Mirrors what copying a cURL out of a Dashboard's browser dev tools typically produces —
    # the real OpenSearch response sits one or more levels deeper under the dashboard server's
    # own envelope key (commonly "rawResponse"), not at the top level.
    dashboard_response = {
        "id": "some-search-request-id",
        "rawResponse": {
            "took": 3,
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {"_index": "wazuh-alerts-4.x", "_id": "os-id-1", "_source": ALERT_A},
                    {"_index": "wazuh-alerts-4.x", "_id": "os-id-2", "_source": ALERT_B},
                ],
            },
        },
    }
    alerts = parse_wazuh_alerts_file(json.dumps(dashboard_response))
    assert len(alerts) == 2
    assert alerts[0]["_id"] == "os-id-1"
    assert alerts[1]["_id"] == "os-id-2"


def test_parse_unwraps_msearch_style_responses_array():
    msearch_response = {
        "responses": [
            {"hits": {"hits": [{"_index": "x", "_id": "os-id-1", "_source": ALERT_A}]}},
            {"hits": {"hits": [{"_index": "x", "_id": "os-id-2", "_source": ALERT_B}]}},
        ]
    }
    alerts = parse_wazuh_alerts_file(json.dumps(msearch_response))
    assert {a["_id"] for a in alerts} == {"os-id-1", "os-id-2"}  # merged across all sub-responses


def test_parse_does_not_misread_a_plain_alert_containing_a_hits_field_as_a_search_response():
    # An alert whose own rule/data happens to contain a "hits" key that isn't shaped like a
    # search response (not a dict-of-hits) must still be treated as one bare alert, not dropped.
    odd_alert = {"id": "x", "hits": 3, "rule": {"level": 6, "description": "odd"}}
    assert parse_wazuh_alerts_file(json.dumps(odd_alert)) == [odd_alert]


# ---- minimum rule level filter ----

def test_parse_drops_alerts_below_the_minimum_rule_level():
    below = {"id": "below", "rule": {"level": 5, "description": "low"}, "agent": {}}
    at_min = {"id": "at-min", "rule": {"level": 6, "description": "kept"}, "agent": {}}
    text = "\n".join(json.dumps(a) for a in [below, ALERT_A, at_min])
    alerts = parse_wazuh_alerts_file(text)
    assert {a["id"] for a in alerts} == {ALERT_A["id"], "at-min"}


def test_parse_drops_alerts_with_no_rule_at_all():
    no_rule = {"id": "archive-event", "agent": {}, "data": {"audit": {"type": "BPF"}}}
    text = json.dumps(no_rule) + "\n" + json.dumps(ALERT_A) + "\n"
    alerts = parse_wazuh_alerts_file(text)
    assert [a["id"] for a in alerts] == [ALERT_A["id"]]


def test_large_import_filters_low_severity_and_counts_them(mock_db, tmp_path):
    below = {"id": "below", "rule": {"level": 5, "description": "low"}, "agent": {}}
    no_rule = {"id": "archive-event", "agent": {}}
    text = "\n".join(json.dumps(a) for a in [below, ALERT_A, no_rule]) + "\n"
    p = tmp_path / "alerts.jsonl"
    p.write_bytes(text.encode())
    job_id = upload_jobs.create_job("alerts.json", p.stat().st_size)

    asyncio.run(main_module._run_large_alert_import(job_id, str(p)))

    job = upload_jobs.get_job(job_id)
    assert job["status"] == "done"
    assert job["inserted"] == 1
    assert job["skipped_low_severity"] == 2
    # Progress must still reach 100% even though the filtered-out lines are the ones nearest
    # the end of the file — byte tracking is independent of what got kept.
    assert job["bytes_processed"] == job["total_bytes"]

    stored = asyncio.run(mock_db["raw_alerts"].find_one({"_id": "below"}))
    assert stored is None
    stored = asyncio.run(mock_db["raw_alerts"].find_one({"_id": "archive-event"}))
    assert stored is None


# ---- streaming path (large-file import) ----

def test_sniff_detects_json_array(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps([ALERT_A, ALERT_B]))
    assert sniff_is_json_array_or_object(str(p)) is True


def test_sniff_ignores_leading_whitespace_before_array(tmp_path):
    p = tmp_path / "a.json"
    p.write_text("   \n\n  " + json.dumps([ALERT_A]))
    assert sniff_is_json_array_or_object(str(p)) is True


def test_sniff_is_false_for_json_lines(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text(json.dumps(ALERT_A) + "\n" + json.dumps(ALERT_B) + "\n")
    assert sniff_is_json_array_or_object(str(p)) is False


def test_sniff_is_false_for_empty_or_whitespace_only_file(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("   \n  ")
    assert sniff_is_json_array_or_object(str(p)) is False


def test_iter_jsonl_yields_alerts_with_cumulative_byte_counts(tmp_path):
    text = json.dumps(ALERT_A) + "\n" + json.dumps(ALERT_B) + "\n"
    p = tmp_path / "a.jsonl"
    p.write_bytes(text.encode())

    results = list(iter_alerts_jsonl_file(str(p)))
    assert [a for a, _ in results] == [ALERT_A, ALERT_B]
    # byte counts are non-decreasing and the last one matches the full file size
    counts = [c for _, c in results]
    assert counts == sorted(counts)
    assert counts[-1] == len(text.encode())


def test_iter_jsonl_handles_no_trailing_newline(tmp_path):
    text = json.dumps(ALERT_A) + "\n" + json.dumps(ALERT_B)  # no trailing \n
    p = tmp_path / "a.jsonl"
    p.write_bytes(text.encode())

    alerts = [a for a, _ in iter_alerts_jsonl_file(str(p))]
    assert alerts == [ALERT_A, ALERT_B]


def test_iter_jsonl_tolerates_trailing_commas_and_blank_and_garbage_lines(tmp_path):
    text = json.dumps(ALERT_A) + ",\n\nnot json\n" + json.dumps(ALERT_B) + "\n"
    p = tmp_path / "a.jsonl"
    p.write_bytes(text.encode())

    alerts = [a for a, _ in iter_alerts_jsonl_file(str(p))]
    assert alerts == [ALERT_A, ALERT_B]


def test_iter_jsonl_reads_across_chunk_boundaries(tmp_path):
    # Force a tiny chunk_size so a single alert's JSON is split across multiple reads —
    # exercises the buffer-carryover logic, not just the common "one big read" case.
    text = json.dumps(ALERT_A) + "\n" + json.dumps(ALERT_B) + "\n"
    p = tmp_path / "a.jsonl"
    p.write_bytes(text.encode())

    alerts = [a for a, _ in iter_alerts_jsonl_file(str(p), chunk_size=5)]
    assert alerts == [ALERT_A, ALERT_B]


# ---- endpoint ----

def test_upload_alerts_endpoint_ingests_json_lines(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    text = json.dumps(ALERT_A) + "\n" + json.dumps(ALERT_B) + "\n"

    resp = client.post(
        "/api/alerts/upload", headers=headers,
        files={"file": ("alerts.json", text, "application/json")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["inserted"] == 2
    assert body["skipped_duplicates"] == 0

    stored = asyncio.run(mock_db["raw_alerts"].find_one({"_id": "1690000000.1"}))
    assert stored["correlated"] is False
    assert stored["rule"]["description"] == "brute force"
    assert "id" not in stored


def test_upload_alerts_endpoint_ingests_single_bare_hit(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}

    resp = client.post(
        "/api/alerts/upload", headers=headers,
        files={"file": ("hit.json", json.dumps(SINGLE_HIT), "application/json")},
    )
    assert resp.status_code == 200
    assert resp.json()["inserted"] == 1

    # Wazuh's own alert id (nested under _source in the raw hit) is what ends up as the
    # document's real _id — same priority as every other ingestion path in this module.
    stored = asyncio.run(mock_db["raw_alerts"].find_one({"_id": "1787344034.10159158"}))
    assert stored is not None
    assert stored["rule"]["description"] == "Multiple web server 400 error codes from same source ip."
    assert stored["agent"]["name"] == "web-host"
    # Regression check: when both "id" and the OpenSearch "_id" are present on the same alert,
    # a short-circuited `alert.pop("id") or alert.pop("_id")` would skip popping "_id" — leaking
    # it into the stored body and letting it silently win over the intended _id on upsert.
    assert "id" not in stored
    assert stored["_id"] == "1787344034.10159158"  # not "eB4BJqABJKeZtH7Ktpj5"
    assert stored["correlated"] is False


def test_upload_alerts_skips_duplicates_on_second_upload(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    text = json.dumps(ALERT_A)

    first = client.post("/api/alerts/upload", headers=headers, files={"file": ("a.json", text, "application/json")})
    assert first.json()["inserted"] == 1

    second = client.post("/api/alerts/upload", headers=headers, files={"file": ("a.json", text, "application/json")})
    assert second.json()["inserted"] == 0
    assert second.json()["skipped_duplicates"] == 1


def test_upload_alerts_generates_id_when_missing(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    no_id_alert = {"timestamp": "2026-01-01T00:00:00+0000", "rule": {"level": 6, "description": "x"}, "agent": {}}

    resp = client.post(
        "/api/alerts/upload", headers=headers,
        files={"file": ("a.json", json.dumps(no_id_alert), "application/json")},
    )
    assert resp.json()["inserted"] == 1

    listed = client.get("/api/alerts", headers=headers).json()
    assert listed["total"] == 1
    assert listed["items"][0]["_id"]  # some generated id, non-empty


def test_upload_alerts_rejects_invalid_file(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.post("/api/alerts/upload", headers=headers, files={"file": ("a.json", "not json at all", "application/json")})
    assert resp.status_code == 400


def test_upload_alerts_requires_admin(client, mock_db):
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"),
        "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")
    resp = client.post(
        "/api/alerts/upload", headers={"Authorization": f"Bearer {token}"},
        files={"file": ("a.json", json.dumps(ALERT_A), "application/json")},
    )
    assert resp.status_code == 403


def test_upload_alerts_survives_a_per_document_mongo_failure(client, mock_db, monkeypatch):
    from pymongo.errors import BulkWriteError

    headers = {"Authorization": f"Bearer {_login(client)}"}
    text = json.dumps(ALERT_A) + "\n" + json.dumps(ALERT_B) + "\n"

    real_bulk_write = mock_db["raw_alerts"].bulk_write

    async def flaky_bulk_write(ops, ordered=False, **kwargs):
        # Simulates one op (ALERT_A, index 0) being rejected as oversized while the other
        # (index 1) really gets written — ordered=False's actual Mongo semantics — by
        # delegating the surviving op to the real bulk_write and raising a BulkWriteError
        # shaped the way real Mongo reports a partial unordered-batch failure.
        good_result = await real_bulk_write([ops[1]], ordered=False, **kwargs)
        raise BulkWriteError({
            "writeErrors": [{"index": 0, "code": 2, "errmsg": "'update' command document too large"}],
            "upserted": [{"index": 1, "_id": "1690000000.2"}],
            "nUpserted": good_result.upserted_count,
        })

    monkeypatch.setattr("app.main.raw_alerts.bulk_write", flaky_bulk_write)

    resp = client.post(
        "/api/alerts/upload", headers=headers,
        files={"file": ("alerts.jsonl", text, "application/json")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["inserted"] == 1
    assert body["failed"] == 1
    assert body["total"] == 2

    # The one alert that failed to store must not exist as a partial/corrupt document.
    stored = asyncio.run(mock_db["raw_alerts"].find_one({"_id": "1690000000.1"}))
    assert stored is None
    stored_ok = asyncio.run(mock_db["raw_alerts"].find_one({"_id": "1690000000.2"}))
    assert stored_ok is not None


def test_upload_alerts_is_audited(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    client.post(
        "/api/alerts/upload", headers=headers,
        files={"file": ("a.json", json.dumps(ALERT_A), "application/json")},
    )
    entries = client.get("/api/audit-log", headers=headers).json()
    match = next(e for e in entries if e["action"] == "alerts.upload")
    assert match["details"]["inserted"] == 1


# ---- endpoint: large-file background path ----

# The background import (_run_large_alert_import) is exercised directly as a plain async
# function here, rather than through the HTTP endpoint + status polling — Starlette's TestClient
# doesn't guarantee the same event loop stays alive across separate client.get()/post() calls,
# so a fire-and-forget asyncio.create_task() from one request has no reliable way to keep
# running while a *later* request polls for it in tests. The endpoint-level tests below only
# check what genuinely happens synchronously, before the response is returned (kicking off the
# job, the audit entry) — everything about what the job actually does when it runs is covered
# as its own unit here.

def test_large_import_ingests_alerts_and_marks_the_job_done(mock_db, tmp_path):
    text = json.dumps(ALERT_A) + "\n" + json.dumps(ALERT_B) + "\n"
    p = tmp_path / "alerts.jsonl"
    p.write_bytes(text.encode())
    job_id = upload_jobs.create_job("alerts.json", p.stat().st_size)

    asyncio.run(main_module._run_large_alert_import(job_id, str(p)))

    job = upload_jobs.get_job(job_id)
    assert job["status"] == "done"
    assert job["inserted"] == 2
    assert job["duplicates"] == 0
    assert job["failed"] == 0
    assert job["bytes_processed"] == job["total_bytes"]

    stored = asyncio.run(mock_db["raw_alerts"].find_one({"_id": "1690000000.1"}))
    assert stored is not None
    assert stored["rule"]["description"] == "brute force"
    assert stored["correlated"] is False
    assert not os.path.exists(p)  # temp file is cleaned up once the job finishes


def test_large_import_counts_duplicates_on_a_second_run(mock_db, tmp_path):
    text = json.dumps(ALERT_A) + "\n"
    p1 = tmp_path / "a.jsonl"
    p1.write_bytes(text.encode())
    job1 = upload_jobs.create_job("a.json", p1.stat().st_size)
    asyncio.run(main_module._run_large_alert_import(job1, str(p1)))

    p2 = tmp_path / "b.jsonl"
    p2.write_bytes(text.encode())
    job2 = upload_jobs.create_job("a.json", p2.stat().st_size)
    asyncio.run(main_module._run_large_alert_import(job2, str(p2)))

    job = upload_jobs.get_job(job2)
    assert job["inserted"] == 0
    assert job["duplicates"] == 1


def test_large_import_spans_multiple_batches(mock_db, tmp_path):
    # 5 alerts through a batch_size of 2 forces three batches (2, 2, 1) — exercises the
    # pull_batch/bulk_write loop actually looping, not just handling everything in one shot.
    alerts = [{"id": str(i), "rule": {"level": 6, "description": "x"}, "agent": {}} for i in range(5)]
    text = "\n".join(json.dumps(a) for a in alerts) + "\n"
    p = tmp_path / "alerts.jsonl"
    p.write_bytes(text.encode())
    job_id = upload_jobs.create_job("alerts.json", p.stat().st_size)

    asyncio.run(main_module._run_large_alert_import(job_id, str(p), batch_size=2))

    job = upload_jobs.get_job(job_id)
    assert job["status"] == "done"
    assert job["inserted"] == 5
    assert asyncio.run(mock_db["raw_alerts"].count_documents({})) == 5


def test_large_import_counts_a_failing_batch_without_aborting_the_job(mock_db, tmp_path, monkeypatch):
    p = tmp_path / "alerts.jsonl"
    p.write_bytes((json.dumps(ALERT_A) + "\n").encode())
    job_id = upload_jobs.create_job("alerts.json", p.stat().st_size)

    async def boom(*args, **kwargs):
        raise RuntimeError("mongo is on fire")

    monkeypatch.setattr("app.main.raw_alerts.bulk_write", boom)

    asyncio.run(main_module._run_large_alert_import(job_id, str(p)))

    job = upload_jobs.get_job(job_id)
    # A single batch's exception is caught per-batch (counted as failed, not fatal) — the job
    # still finishes normally rather than aborting, matching the small-file path's "one bad
    # batch doesn't sink the import" behavior.
    assert job["status"] == "done"
    assert job["failed"] == 1


def test_large_import_marks_job_as_error_when_the_file_itself_is_unreadable(mock_db, tmp_path):
    job_id = upload_jobs.create_job("alerts.json", 0)

    asyncio.run(main_module._run_large_alert_import(job_id, str(tmp_path / "does-not-exist.jsonl")))

    job = upload_jobs.get_job(job_id)
    assert job["status"] == "error"
    assert job["error"]


def test_large_upload_returns_a_job_id_immediately(client, mock_db, monkeypatch):
    monkeypatch.setattr("app.main.LARGE_FILE_THRESHOLD_BYTES", 1)
    headers = {"Authorization": f"Bearer {_login(client)}"}
    text = json.dumps(ALERT_A) + "\n" + json.dumps(ALERT_B) + "\n"

    resp = client.post(
        "/api/alerts/upload", headers=headers,
        files={"file": ("alerts.json", text, "application/json")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "job_id" in body
    assert body["total_bytes"] == len(text.encode())


def test_large_upload_rejects_a_json_array_with_a_clear_message(client, mock_db, monkeypatch):
    monkeypatch.setattr("app.main.LARGE_FILE_THRESHOLD_BYTES", 1)
    headers = {"Authorization": f"Bearer {_login(client)}"}
    text = json.dumps([ALERT_A, ALERT_B])

    resp = client.post(
        "/api/alerts/upload", headers=headers,
        files={"file": ("alerts.json", text, "application/json")},
    )
    assert resp.status_code == 400
    assert "JSON Lines" in resp.json()["detail"]


def test_large_upload_status_requires_auth(client, mock_db):
    resp = client.get("/api/alerts/upload/status/does-not-exist")
    assert resp.status_code == 401


def test_large_upload_status_404_for_unknown_job(client, mock_db):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    resp = client.get("/api/alerts/upload/status/does-not-exist", headers=headers)
    assert resp.status_code == 404


def test_large_upload_is_audited_on_start(client, mock_db, monkeypatch):
    # The audit entry is written synchronously, before the response is returned — it doesn't
    # depend on the background job ever running, let alone finishing.
    monkeypatch.setattr("app.main.LARGE_FILE_THRESHOLD_BYTES", 1)
    headers = {"Authorization": f"Bearer {_login(client)}"}
    text = json.dumps(ALERT_A) + "\n"

    resp = client.post("/api/alerts/upload", headers=headers, files={"file": ("a.json", text, "application/json")})
    job_id = resp.json()["job_id"]

    entries = client.get("/api/audit-log", headers=headers).json()
    match = next(e for e in entries if e["action"] == "alerts.upload.start")
    assert match["details"]["job_id"] == job_id


def test_large_upload_requires_admin(client, mock_db, monkeypatch):
    monkeypatch.setattr("app.main.LARGE_FILE_THRESHOLD_BYTES", 1)
    asyncio.run(mock_db["users"].insert_one({
        "_id": "eve", "password_hash": hash_password("eve-pw"),
        "role": "analyst", "created_at": "2026-01-01T00:00:00+00:00",
    }))
    token = _login(client, "eve", "eve-pw")
    resp = client.post(
        "/api/alerts/upload", headers={"Authorization": f"Bearer {token}"},
        files={"file": ("a.json", json.dumps(ALERT_A) + "\n", "application/json")},
    )
    assert resp.status_code == 403

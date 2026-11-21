"""Parses an uploaded file of Wazuh alert JSON into the same document shape the live poller
(`scheduler.py`) already stores in `raw_alerts` — lets an analyst backfill or replay real alert
data through the exact same correlation -> incident -> AI pipeline without needing a live Wazuh
Indexer connection configured. Accepted shapes, covering the different ways people actually end
up with a file of alerts:

  1. Wazuh's own alerts.json — JSON Lines, one alert object per line.
  2. A plain JSON array of alert objects, or a single bare alert object.
  3. Any JSON document with an OpenSearch/Elasticsearch `_search`-style `{"hits": {"hits":
     [...]}}` block buried *somewhere* inside it — not just at the top level. A raw curl against
     the Indexer puts it at the top; copying a cURL out of the Dashboard's browser dev tools
     usually hits the Dashboard server's own internal search API instead, which wraps the real
     OpenSearch response another level or two deeper (commonly under a "rawResponse" key, but
     the exact wrapper name isn't guessable up front and isn't worth hard-coding — this walks
     the whole document looking for the hits.hits shape instead of assuming where it sits).
  4. A single bare OpenSearch *hit* — `{"_index", "_id", "_source": {...}, ...}` with no
     surrounding hits.hits array at all. This is what "view single document JSON" in a
     Dashboard's Discover panel gives you — one row's raw document, not a search response.

Each hit (from #3 or #4) is unwrapped to `hit["_source"]` merged with `hit["_id"]`, identical to
what `wazuh_client.py`'s live-poll path itself produces from the same API. Skipping this
unwrapping has two failure modes depending on the shape: a multi-hit search response gets
misread as one giant "alert" (easily over MongoDB's 16MB document limit), while a single bare
hit gets stored with its real fields (rule/agent/timestamp) nested under `_source` instead of at
the top level, where the rest of this app expects to find them — it "uploads successfully" but
never shows anything.

Both the whole-file parser and the streaming path also drop anything below
MIN_RULE_LEVEL_FOR_UPLOAD (including alerts with no "rule" block at all, e.g. Wazuh archive/audit
log lines that never matched a detection rule) — an export of *everything* Wazuh ingested, not
just what it alerted on, is a real shape people upload (it's what makes a 100GB file), but this
app's alerts table, severity filters, and correlation pipeline are all built around genuine rule
matches.
"""
import json

import orjson

# Above this, the whole-file parser below (which holds the entire file, plus its fully-parsed
# Python object tree, in memory at once) stops being viable — a multi-GB file would either blow
# past the backend container's memory limit or take an unreasonable amount of time just to read.
# Files this large go through iter_alerts_jsonl_file() instead: a bounded-memory streaming parser
# for real Wazuh alerts.json exports, which are JSON Lines (one alert object per line) by nature.
LARGE_FILE_THRESHOLD_BYTES = 50 * 1024 * 1024  # 50MB

# Anything below this never matched a real detection rule — a raw archive/audit-log line, or a
# very low-signal one — and the rest of this app (severity filters, correlation, incidents, the
# AI pipeline) is built around genuine rule matches, not raw log noise. Applies uniformly to both
# upload paths so behavior doesn't change based on file size.
MIN_RULE_LEVEL_FOR_UPLOAD = 6


def _meets_min_rule_level(alert: dict) -> bool:
    """True when `alert` has a real rule match at or above MIN_RULE_LEVEL_FOR_UPLOAD. An alert
    with no "rule" block at all (e.g. a raw Wazuh archive event that never triggered a rule) or
    a non-numeric level fails this the same as one that's simply too low."""
    rule = alert.get("rule")
    if not isinstance(rule, dict):
        return False
    level = rule.get("level")
    return isinstance(level, (int, float)) and level >= MIN_RULE_LEVEL_FOR_UPLOAD


class NotJsonLines(Exception):
    """Raised when a file over LARGE_FILE_THRESHOLD_BYTES doesn't look like JSON Lines — the only
    shape the streaming path can safely handle without holding the whole document in memory."""
    pass


def _as_hit(obj: dict) -> dict | None:
    """Unwraps a single OpenSearch hit — {"_index", "_id", "_source": {...}} — to its alert
    fields plus _id. Returns None if `obj` isn't shaped like a hit at all."""
    if isinstance(obj.get("_source"), dict) and "_id" in obj and "_index" in obj:
        return {**obj["_source"], "_id": obj["_id"]}
    return None


def _unwrap_hits(hits_block: dict) -> list[dict] | None:
    """Returns None when hits_block doesn't actually have a hits *array* (shape doesn't match
    at all) — but a real, empty list (not None) when it does match and simply has zero results,
    so callers can tell "found a search response with nothing in it" apart from "not a search
    response"."""
    hits = hits_block.get("hits")
    if not isinstance(hits, list):
        return None
    return [_as_hit(hit) for hit in hits if isinstance(hit, dict) and _as_hit(hit)]


def _find_search_response(node) -> list[dict] | None:
    """Walks a parsed JSON structure looking for OpenSearch/Elasticsearch shapes at any depth —
    a hits.hits search-response block, or a single bare hit copied on its own — merging every
    match found (a document can legitimately contain more than one, e.g. an _msearch "responses"
    array holds one hits.hits block per sub-query). Returns None only if neither shape exists
    anywhere in the document; an empty list means a real (empty) search response was found,
    which the caller must not then reinterpret as "not a search response after all"."""
    found: list[dict] = []
    matched = False

    def visit(value):
        nonlocal matched
        if isinstance(value, dict):
            if isinstance(value.get("hits"), dict):
                unwrapped = _unwrap_hits(value["hits"])
                if unwrapped is not None:
                    matched = True
                    found.extend(unwrapped)
                    return  # a hits.hits block's own contents aren't searched further
            hit = _as_hit(value)
            if hit:
                matched = True
                found.append(hit)
                return  # a hit's own _source isn't searched further either
            for v in value.values():
                visit(v)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(node)
    return found if matched else None


def parse_wazuh_alerts_file(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        return []

    alerts: list[dict] | None = None

    # A plain JSON array, a single bare object, or a (possibly nested) OpenSearch/Elasticsearch
    # search response all parse as one whole-file JSON document.
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            # Each item might be a raw OpenSearch hit (unwrap it) or already a bare alert
            # (Wazuh's own shape) — either way, use it directly rather than searching further.
            alerts = [_as_hit(a) or a for a in parsed if isinstance(a, dict)]
            if not alerts:
                alerts = _find_search_response(parsed)
        elif isinstance(parsed, dict):
            alerts = _find_search_response(parsed)
            if alerts is None:
                alerts = [parsed]
    except json.JSONDecodeError:
        pass

    # Otherwise fall back to JSON Lines — Wazuh's native alerts.json format.
    if alerts is None:
        alerts = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")  # tolerate a stray trailing comma some exports leave
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                alerts.append(obj)

    # No alert-count cap here — LARGE_FILE_THRESHOLD_BYTES (checked by the caller before this
    # function is even reached) is what actually protects this whole-file-in-memory parser from
    # an oversized file; a count limit on top of that byte-size gate was redundant and, worse,
    # inconsistent — the streaming path for files over that threshold has never had one.
    return [a for a in alerts if _meets_min_rule_level(a)]


def sniff_is_json_array_or_object(path: str) -> bool:
    """Peeks at the first non-whitespace byte of a file to tell "starts like a JSON array/bare
    object" (`[` or `{`) apart from JSON Lines (which, alert-by-alert, always starts a line with
    `{` too — but the *file's very first* non-whitespace character being `[` is a reliable tell
    for a whole-document array, and a single giant `{...}` spanning the whole file is exceedingly
    unlikely to actually be one JSON Lines record). Used only to fail large uploads fast with a
    clear message instead of silently mis-parsing them line-by-line."""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                return False
            stripped = chunk.lstrip(b" \t\r\n")
            if stripped:
                return stripped[0:1] == b"["
            # chunk was all whitespace — keep reading


def iter_alerts_jsonl_file(path: str, chunk_size: int = 4 * 1024 * 1024):
    """Streams alert dicts out of a JSON Lines file at `path` one at a time, holding at most one
    read buffer (chunk_size) and one in-progress line in memory at once — this is what makes a
    multi-GB alerts.json file importable at all inside a memory-limited container. Yields
    (alert_dict, bytes_consumed_so_far) so a caller can report progress against the file's known
    total size without a separate counting pass.

    Same per-line tolerances as parse_wazuh_alerts_file's JSON Lines fallback: a stray trailing
    comma some exports leave, and blank/unparseable lines skipped rather than aborting the import
    over one bad row. Each line also gets the same _as_hit() unwrapping as the small-file path —
    an export where every line is one bare OpenSearch hit (`{"_index", "_id", "_source": {...}}`)
    is JSON Lines too, and without this a large file of them "uploads successfully" but every row
    ends up with rule/agent/timestamp nested under _source instead of at the top level, where the
    rest of this app expects to find them (see this module's docstring).

    Parses each line with orjson rather than the stdlib json module — a straight drop-in here
    (both take bytes, both return plain dicts/lists/etc.), just meaningfully faster on the kind
    of file this function exists for: this is the CPU-bound step in a multi-GB import, running
    for however many millions of lines the file has.
    """
    buffer = b""
    consumed = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            consumed += len(chunk)
            buffer += chunk
            lines = buffer.split(b"\n")
            buffer = lines.pop()  # last entry may be a partial line — carry it to the next read
            for raw_line in lines:
                line = raw_line.strip().rstrip(b",")
                if not line:
                    continue
                try:
                    obj = orjson.loads(line)
                except orjson.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    yield _as_hit(obj) or obj, consumed
    line = buffer.strip().rstrip(b",")
    if line:
        try:
            obj = orjson.loads(line)
            if isinstance(obj, dict):
                yield _as_hit(obj) or obj, consumed
        except orjson.JSONDecodeError:
            pass

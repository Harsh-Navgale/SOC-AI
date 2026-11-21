# SOC-AI: Production Notes

What's actually built, how to operate it day to day, how to connect a real Wazuh manager, and
what's still a known, deliberate limitation rather than a bug. For first-time setup, see
`BUILD_GUIDE.md`. This file is the source of truth for current capabilities — if you add a
feature, update this file in the same change rather than letting it drift (it has drifted
before; see the git history around November 2026 for what that cost).

## Quick start

```bash
make setup          # creates .env, generates JWT secret + admin password + TLS cert
make build
make up
make seed            # optional: synthetic demo alerts, see below
```

Then open **https://localhost:8443** (self-signed certificate warning is expected for a
local/lab deployment — accept it). Log in with the admin username/password `make setup` printed.

## What's in the dashboard

Fifteen tabs, grouped by what they actually do:

**Core pipeline**
- **Overview** — KPI tiles, an hourly alert-volume trend chart, severity/case-status breakdowns.
- **Correlated Alerts** / **Incidents** — the same `IncidentsList` view filtered by whether an
  AI investigation has run yet. Click a row to open the case: status, assignment, notes,
  threat-intel/asset/org-context summary, the AI investigation report, close-with-disposition.
- **AI Queue** — cases waiting for `auto_investigate_cases` to pick them up, or for manual
  investigation.
- **Raw Alerts** — individual ingested alerts, with manual "promote to case" for anything the
  correlator's volume threshold hasn't folded in yet, and bulk upload (see below).

**Enrichment & tuning**
- **Asset Coverage** — Wazuh agents vs. the S3 instance-inventory export, reconciled by IP;
  flags assets with no agent (monitoring blind spot) and agents with no matching asset record.
- **Threat Intel** — ad-hoc VirusTotal / AbuseIPDB / URLhaus / ThreatFox lookups; the same
  sources `case_enrichment.py` runs automatically against every new case's source IP.
- **Alert Exclusions** — admin-authored, pre-correlation suppression rules (by `rule.id`,
  `rule.description`, agent, IP, or MITRE tactic), either typed as plain criteria or described
  in plain language and AI-structured into criteria once.
- **Rule Health** (admin-only) — per-rule rollup of *human-confirmed* dispositions from closed
  cases (confirmed FP/TP/benign counts and rate), with the AI's own unconfirmed per-investigation
  opinion shown as a clearly separate, secondary column. Flags a rule after 3 confirmed false
  positives (`RULE_FP_NOTIFY_THRESHOLD`) with a one-time admin notification, and can generate a
  copy-pasteable Wazuh `local_rules.xml` suppression snippet for a flagged rule — nothing here
  is ever applied to Wazuh automatically.

**AI**
- **Ask AI** — free-text question box; embeds the question, retrieves relevant chunks from the
  `org_knowledge` Chroma collection (org docs + previously-resolved-case precedents, labeled
  distinctly from each other in the prompt), answers via AWS Bedrock using the configured
  default model.
- Per-case **Investigate with AI** (inside a case, not a separate tab) — the same
  retrieval-augmented approach, producing a structured report: severity, confidence, verdict,
  origin, category, a secondary "rule health" opinion (skipped for Vulnerability Detection
  findings — see below), owning team, impact, priority, probable cause, summary, recommended
  actions.

**Admin / ops**
- **System Health** — backend uptime, MongoDB, ChromaDB, the correlator (heartbeat
  staleness), Wazuh **manager** (agent counts, version) and **indexer** (cluster status, alert
  storage size), each checked independently so one being down doesn't blank the rest.
- **Users** (admin-only) — two roles, `admin`/`analyst`; accounts live in MongoDB, bcrypt-hashed.
- **Activity** (admin-only) — the audit log: every admin/analyst action that changes state
  (user management, credential changes, case close/delete, exclusion rules, logout), who did it,
  when.
- **Debug** (admin-only) — a runtime toggle that raises backend logging to DEBUG (shows raw
  AI prompts/responses in the UI) and a live log tail, plus a small ring buffer of recent
  scheduler-job errors.

A notification bell (any tab) surfaces case assignments, case-aging alerts, and rule-health
threshold flags; everything live-updates over a single shared WebSocket
(`backend/app/ws_manager.py`) rather than polling.

## Connecting your real Wazuh manager

Edit `.env`:

```
WAZUH_INDEXER_HOST=https://<your-indexer-host>:9200
WAZUH_INDEXER_USER=<user>
WAZUH_INDEXER_PASSWORD=<password>
WAZUH_INDEXER_VERIFY_SSL=true
WAZUH_CA_BUNDLE=/certs/your-ca.pem   # only if your indexer uses a private/internal CA
```

Then `docker compose restart backend`. Until this is filled in correctly, the backend logs a
warning every ~30s and keeps retrying — it will not crash, and the rest of the dashboard keeps
working.

For the System Health manager card and Asset Coverage's Wazuh-agents view, also set the
**manager** API creds (separate service/port from the indexer):

```
WAZUH_MANAGER_HOST=https://<your-manager-host>:55000
WAZUH_MANAGER_USER=<user>
WAZUH_MANAGER_PASSWORD=<password>
```

Like AWS (below), both can instead be connected at runtime from the UI, held in backend-process
memory for 12 hours — no `.env` edit or restart needed, but also nothing persisted to disk, so a
backend restart means re-entering them.

### Use a scoped, read-only Wazuh API account — not an admin one

Wazuh's own API RBAC model (users → roles → policies, with white-list/deny-by-default mode
recommended for production) is built exactly for this: a service account should hold only the
permissions this app actually exercises, not the Wazuh admin account. Concretely, this app only
ever needs:
- Indexer: search-only on the alerts index (`WAZUH_INDEXER_*`).
- Manager: `GET /agents`, `GET /manager/info`, `GET /manager/status`, `GET /manager/stats`.

Create a dedicated role scoped to just those, assign it to a new user via the Wazuh API
(`POST /security/users` → `POST /security/roles/{id}/policies` →
`POST /security/users/{username}/roles`), and use that user's credentials here instead of an
admin account. This is a one-time setup step on the Wazuh side, not something this app enforces
for you.

### Vulnerability Detection findings are tagged and handled separately

A Wazuh alert whose `rule.groups` mentions "vulnerability" (a CVE match from the Vulnerability
Detection module — state drift, "Active"/"Solved", not a point-in-time event) is tagged
`is_vulnerability_alert` on its incident by both the correlator and manual promotion. These
incidents are excluded from the Rule Health rollup and skip the AI's "rule health" question
entirely — "is this rule miscalibrated" isn't a meaningful judgment for a CVE match. If a rule
in that category is flagged false-positive-prone in practice, the fix belongs in Wazuh's own
vulnerability-detection config, not here.

## AI provider: AWS Bedrock

Every AI call (chat generation and embeddings) goes through one dispatch point each in
`backend/app/rag.py` (`_generate`/`embed_text`) — both always resolve to a Bedrock model id
(conventionally `"bedrock:"`-prefixed in stored settings, kept for backward compatibility; a
bare id is treated as a raw Bedrock model id directly). Both the default and fallback
model/embedding-model are explicit, admin-set choices (Settings, via the AI Chat page's Bedrock
settings card), falling back to `DEFAULT_BEDROCK_CHAT_MODEL`/`DEFAULT_BEDROCK_EMBED_MODEL` when
nothing's configured yet — never auto-picked, since silently falling back to an unvetted model
on failure could incur real, unexpected per-token cost. The fallback model is only consulted
when the default model is unavailable outright (Bedrock session expired/not connected, or that
specific model/region having an outage), not on a single bad answer.

**AWS Bedrock** — connected at runtime from the AI Chat page (IAM access key/secret/session
token, or a Bedrock API key), held in backend-process memory for 12 hours, same session model as
AWS/Wazuh-Manager credentials above. **The embedding model cannot be changed once
`org_knowledge` holds vectors** — different Bedrock embedding models produce different vector
dimensionalities; switching after the fact would need every existing vector re-embedded. Decide
this once, early.

## Threat intelligence enrichment

`case_enrichment.py` runs automatically on every newly-correlated case, before AI investigation:
VirusTotal, AbuseIPDB, URLhaus, and ThreatFox lookups against the case's source IP, with a
10-minute cache (protects VirusTotal's 4 req/min free-tier limit) and a uniform
`ok`/`error`/`not_configured`/`not_applicable` shape per source so one missing key doesn't block
the others. The same lookups are available ad hoc from the **Threat Intel** tab. Credentials are
entered once from that tab (not `.env`), same 12h in-memory session pattern as AWS/Wazuh.

## Case management, AI investigation, and the knowledge feedback loop

- **Closing a case now requires a confirmed disposition** (`true_positive` / `false_positive` /
  `benign_positive`), not just a free-text resolution — this is the human-confirmed ground truth
  everything else (Rule Health's rollup, the precedent-matching below) is built on. The AI's own
  verdict is never auto-promoted to this; an analyst has to actually pick one, for every close,
  including bulk-close.
- The resolution + disposition get embedded into the same `org_knowledge` Chroma collection as
  org docs, tagged `type: resolved_case` with the disposition and rule key in its metadata.
  Future investigations retrieve these and present them to the model as **labeled, confirmed
  precedent**, distinct from generic org-doc/playbook chunks — "similar to a confirmed false
  positive on this same rule," not just undifferentiated "organizational knowledge."
- A closed case's correlator grouping is final: a new alert burst from the same source IP/rule
  after closure opens a **new** case.

## Resumable large alert uploads

`POST /api/alerts/upload` holds a whole file in memory only below `LARGE_FILE_THRESHOLD_BYTES`
(50MB) — matters given the backend's 256MB container limit. Above that, the frontend switches to
a chunked, resumable upload (`upload_sessions.py` + `upload_jobs.py`): init → chunk-by-chunk PUT
with offset checking → complete, parsed as streaming JSON Lines so a multi-GB `alerts.json`
export never needs to fit in memory at once. There's no cap on alert *count* in either path —
only the byte-size threshold decides which code path runs.

## Security notes

- **Login is rate-limited** (5 attempts / 5 minutes per IP) and threat-intel lookups are
  separately rate-limited to protect free-tier API keys — both in-memory, single-process
  (`rate_limit.py`).
- **Logout actually revokes the token server-side** (`POST /api/auth/logout`), not just
  client-side — an in-memory revocation list keyed by the token's `jti`, pruned lazily. A stolen
  token can no longer outlive an analyst's own logout.
- **nginx sends HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and a CSP**
  scoped to `'self'` — everything this app serves (scripts, styles, fonts) is self-hosted, no CDN.
- AWS/Bedrock/Wazuh-Manager credentials are **never written to `.env` or Mongo** when entered
  from the UI — process memory only, 12h TTL, wiped on restart. This only works correctly with
  the single backend worker this app runs (see Known limitations).

## Data retention — two independent clocks

`raw_alerts` has a Mongo TTL index (`RAW_ALERT_RETENTION_DAYS`, default 30 days) so local disk
use doesn't grow unbounded. The Wazuh Indexer manages its **own**, separate retention via
OpenSearch ISM (commonly a ~90-day default) — these are not the same clock, and nothing keeps
them in sync automatically. In practice this rarely matters: an incident's `unique_values` is
flattened onto the incident document at correlation time and survives `raw_alerts`'s TTL fine, so
case history and the AI investigation report don't depend on the original raw alert document
still existing. The one thing that *does* depend on it is any future feature that re-fetches a
raw alert by `alert_ids` for display — if you build one, check it degrades gracefully past 30
days rather than 404ing. Raise `RAW_ALERT_RETENTION_DAYS` if you need a longer local window.

## System Health dashboard

`GET /api/system/health` aggregates six subsystems independently, so one being down doesn't
blank the rest: backend uptime, MongoDB, ChromaDB, the correlator (heartbeat staleness),
Wazuh manager, Wazuh indexer. Anything not configured shows `not_configured`, not an error.

## Asset Coverage (S3 inventory vs. Wazuh agents)

Two sub-tabs:
- **Wazuh Agents** — raw browse of every registered agent, searchable by name/IP.
- **Coverage Comparison** — reconciles the S3 instance-inventory export against those agents by
  IP (not hostname — hostname is display-only), broken down by Wazuh's own agent status
  (connected/disconnected/pending/other) plus **missing** (in S3, no agent — the actual finding)
  and **orphaned** (registered agent, no matching S3 record).

If there's no live Wazuh Manager access, upload a manual agent CSV (`name`/`ip`/`status`
columns) from the same tab instead — also held in memory for 12h. The live API is always tried
first; if it fails or isn't configured and a manual sheet was uploaded, that's used instead
automatically, with the response tagged `source: "live" | "manual"` either way.

Config (`.env`, non-secret):
```
AWS_DEFAULT_REGION=us-east-1
S3_INVENTORY_BUCKET=<bucket>
S3_INVENTORY_PREFIX=
S3_INVENTORY_KEY=
S3_INVENTORY_FORMAT=csv
S3_INVENTORY_HOSTNAME_FIELD=hostname
S3_INVENTORY_IP_FIELD=
```
Refresh is on-demand (no background job, no persisted history) — revisit caching if this ends up
called more often than the S3 export's own daily cadence.

## Loading org-specific knowledge

Drop `.md`/`.txt` files into `org_docs/`, then `docker attach soc-console`, option 1 to ingest.
Detach with `Ctrl+P` then `Ctrl+Q` — not `Ctrl+C`, which stops the container.

## Demo data without a real Wazuh connection

`make seed` inserts synthetic SSH brute-force alerts (fake IP `198.51.100.23`, RFC 5737 range)
directly into `raw_alerts`. The correlator picks them up within ~10-20s. Never touches real
exported Wazuh data.

## Backup / restore

Two named volumes hold all state: `mongo-data` and `chroma-data`.

```bash
# Backup
docker run --rm -v soc-ai_mongo-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/mongo-backup.tgz -C /data .
docker run --rm -v soc-ai_chroma-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/chroma-backup.tgz -C /data .

# Restore (into a fresh volume, stack stopped)
docker run --rm -v soc-ai_mongo-data:/data -v "$PWD":/backup alpine \
  sh -c "cd /data && tar xzf /backup/mongo-backup.tgz"
```

(Volume names are prefixed with the compose project name — check `docker volume ls` if different.)

## Tests

```bash
make test
```

Runs `pytest` for both the backend (500+ tests — auth, health, correlation-adjacent endpoints,
RAG/AI dispatch, rule health, threat intel, asset coverage, uploads, etc. — against a mocked
Mongo and a stubbed Chroma client, no live services needed) and the correlator (grouping/
threshold/exclusion/vulnerability-tagging logic against `mongomock`). Frontend: `cd frontend &&
npm test` (vitest). Requires `.env` to exist first (`make setup`).

## Known limitations (intentional, for current scale — confirm these still hold before UAT)

- **Single uvicorn worker is load-bearing, not incidental.** AWS/Bedrock/Wazuh credentials,
  rate-limit buckets, the JWT revocation list, WebSocket connections, and upload-job progress all
  live in module-level process memory. Adding `--workers` doesn't error — it just makes each of
  those work only part of the time. Fine for one small team behind one backend; a hard ceiling
  for horizontal scaling.
- **Two roles only** (`admin`/`analyst`), no per-case permissions or approval workflows.
- **Single Wazuh manager/indexer assumed throughout** — no cluster awareness. Wazuh's own
  guidance treats single-node as appropriate roughly up to ~100 endpoints; past that, or past
  whatever EPS a single manager can actually sustain, this assumption needs revisiting on the
  Wazuh side (this app has no visibility into whether the manager is silently dropping events
  under load — `wazuh-analysisd.state`'s `events_dropped` isn't currently surfaced here).
- **The correlator's grouping (same source_ip + rule, rolling window) is intentionally simple.**
  A good demonstration of the architecture, not a rules engine replacement.
- **No active response / auto-remediation of any kind.** AI investigation output is advisory
  text only — "recommended actions," never an executed action. Any future auto-containment
  should extend Wazuh's own Active Response (`ossec.conf`), not invent a parallel mechanism, and
  needs its own allowlist/self-lockout protection (Wazuh's own docs don't provide this either).
- **No AI-suggested rule change is ever auto-applied.** Rule Health's suggested `local_rules.xml`
  snippet is a copy-pasteable suggestion for a human to review and apply via Wazuh's own
  `wazuh-logtest`-validated workflow — matches Wazuh's own documented tuning process, which also
  never auto-applies a rule change. (Note: Wazuh 5.0, as of this writing in RC, has removed the
  `/logtest` API/CLI entirely with no replacement — a live dry-run integration here was
  deliberately not built against a moving target; revisit once 5.0's replacement, if any, ships.)
- **Credentials entered via the UI (AWS, Bedrock, Wazuh Manager, threat-intel keys) don't
  survive a backend restart** — 12h in-memory session, by design (never written to `.env` or
  Mongo), but real operational friction: every restart means every admin re-pastes them.
- AI investigation reports are parsed from a fixed-format text prompt (small local models don't
  reliably emit valid JSON), not a strict schema — `raw` is always kept alongside the parsed
  fields so nothing is lost if the model deviates from the format.

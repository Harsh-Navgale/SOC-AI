# SOC-AI Build Guide

Step-by-step guide to running this project (Wazuh + FastAPI + ChromaDB + AWS Bedrock +
MongoDB + React), assuming no prior experience with these tools. For what changed in the
production-readiness pass and how to operate an already-running stack, see `PRODUCTION.md`.

## 0. What you're building

```
Wazuh (your existing manager/indexer — local or remote, not part of this Docker stack)
        |  alerts, via the Wazuh Indexer (OpenSearch) search API on port 9200
        v
+------------------------------- Docker (soc-net) --------------------------------+
|  frontend (nginx, TLS)  <-- only port published to the host: 8443              |
|       |  serves the React dashboard, reverse-proxies /api/* to backend          |
|       v                                                                         |
|  backend (FastAPI)  -- polls Wazuh, JWT auth, RAG chat endpoint                 |
|       |                                                                         |
|       v                                                                         |
|  correlator          -- groups alerts into incidents, tags MITRE ATT&CK data    |
|                                                                                  |
|  mongodb              -- raw_alerts + incidents (internal-network only)         |
|  chromadb (Vector DB) -- embedded org docs / playbooks (internal-network only)  |
|  console               -- CLI: ingest org docs into the Vector DB               |
+----------------------------------------------------------------------------------+
        |
        v
AWS Bedrock (connected at runtime from the dashboard, admin-only — see step 6)
```

Every arrow in the original architecture diagram maps to a real file:

| Diagram element        | File(s) |
|---|---|
| Wazuh API -> Fast API   | `backend/app/wazuh_client.py`, `backend/app/scheduler.py` |
| Fast API -> Corellator  | `backend` writes to Mongo `raw_alerts`; `correlator/correlator.py` reads it |
| Corellator -> MongoDB   | `correlator/correlator.py` (`incidents` collection) |
| MongoDB -> Bedrock Model | `backend/app/rag.py` (`ask_ai`), `backend/app/bedrock_client.py` |
| Console / Lightweight Linux | `console/console.py` |
| Custom Files / Org Specific Files | `org_docs/` folder |
| Console -> Vector DB    | `console/console.py` `ingest_docs()` |
| Vector DB / Fast API -> Dashboard | `backend/app/main.py` (`/api/*`), `frontend/` |

## 1. Prerequisites

- Linux with Docker Engine + the Compose plugin (`docker --version`, `docker compose version`).
- `openssl` (for generating the TLS cert and secrets — normally preinstalled).
- An AWS account with Bedrock model access enabled in your target region, and either an IAM
  access key or a Bedrock API key to connect from the dashboard (step 5) — see `PRODUCTION.md`'s
  "AI provider: AWS Bedrock" section. AI features (Ask AI, Investigate, knowledge feedback)
  return `503` until Bedrock is connected; everything else works regardless.
- Either an existing Wazuh manager/indexer you can reach (local or remote), or none yet — the
  stack runs fine without one, see step 6.
- At least a few GB of free RAM/disk.

## 2. One-time setup

```bash
cd /home/harshnavgale/SOC-AI
make setup
```

This creates `.env` from `.env.example`, generates a random `JWT_SECRET`, a random admin
login password (printed once — save it), a random Mongo password, and a self-signed TLS
certificate in `certs/`. **Save the printed admin password now.**

## 3. Build and start the stack

```bash
make build
make up
docker compose ps
```

All services should report `healthy`. If not:

```bash
make logs
```

## 4. Log in and connect Bedrock

Open **https://localhost:8443**. Your browser will warn about the self-signed certificate —
that's expected for a local/lab deployment; accept it and continue. Log in with the admin
username/password from step 2 — this bootstraps the first admin account into MongoDB (accounts
are DB-backed, not env-based, after this point). From the **Users** tab (admin-only) you can
add analyst accounts for teammates.

From the **Ask AI** tab (admin-only settings card), connect Bedrock with an IAM access key or a
Bedrock API key — held in the backend's memory for 12h, never written to `.env` or Mongo (same
as the Wazuh Manager and threat-intel connections). AI features return `503` until this is
done.

See `PRODUCTION.md`'s "What's in the dashboard" for the full, current tab-by-tab breakdown —
it's grown well past the five tabs this guide originally shipped with, and that file is kept
up to date with it instead of this one.

## 5. Connect (or skip) your Wazuh manager

If you already have a Wazuh manager/indexer running somewhere, edit `.env`:

```
WAZUH_INDEXER_HOST=https://<your-indexer-host>:9200
WAZUH_INDEXER_USER=<user>
WAZUH_INDEXER_PASSWORD=<password>
```

then `docker compose restart backend`. If you don't have Wazuh set up yet, or want to try the
pipeline before wiring in the real thing:

```bash
make seed
```

This inserts a batch of synthetic SSH-brute-force-shaped alerts so you can watch alerts flow
into MongoDB, get correlated into an incident, and show up on the dashboard, without needing
a real Wazuh connection yet.

### If you need to install a Wazuh manager from scratch

If you have no Wazuh manager at all (local test box, not the case if you already administer
one elsewhere), the official all-in-one installer sets up manager + indexer + dashboard:

```bash
# Pin a specific version, not a generic "4.x" path — that wildcard has been seen to 403 on
# packages.wazuh.com; check https://documentation.wazuh.com for the current release and update
# this if 4.14 is no longer current by the time you read this.
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
sudo tar -xvf wazuh-install-files.tar.gz
cat wazuh-install-files/wazuh-passwords.txt   # indexer admin password is in here
```

Then point `WAZUH_INDEXER_HOST` at `https://<that-host>:9200` (use `host.docker.internal` if
it's the same machine running this Docker stack).

## 6. Load your organization's knowledge into the Vector DB

Drop `.md`/`.txt` files (playbooks, policies, past incident write-ups) into `org_docs/`, then:

```bash
docker attach soc-console
```

Choose option `1` to ingest everything in `org_docs/` (routes through the backend's own
`/api/ingest`, so embeddings use whatever Bedrock model is configured). Detach without
stopping the container with `Ctrl+P` then `Ctrl+Q` (do **not** press Ctrl+C — that stops it).

## 7. Use the dashboard

See `PRODUCTION.md`'s "What's in the dashboard" for the current tab-by-tab breakdown (it covers
a lot more than Incidents/Raw Alerts/Ask AI at this point — asset coverage, threat intel, rule
health, exclusions, and more).

## 8. Run the tests

```bash
make test
```

## 9. Common problems

- **Backend can't reach Wazuh indexer**: check `docker compose logs backend` for the warning —
  it retries automatically, it won't crash the stack. Verify the host/creds in `.env`.
- **AI features return 503**: Bedrock isn't connected (or the session expired — 12h TTL).
  Reconnect from the Ask AI tab's settings card.
- **Chroma collection empty / AI says "no knowledge available"**: run the console ingest step
  (step 6) — `org_docs/` needs at least one `.md`/`.txt` file ingested.
- **A service won't go healthy**: `docker compose ps` shows which one; `docker compose logs
  <service>` for why. Common cause: `.env` missing (`make setup` first).
- **Port already in use**: this stack only publishes `8443`. If that's taken by something else
  on your machine, change the `frontend.ports` mapping in `docker-compose.yml`.

## 10. Where to go next

See `PRODUCTION.md` for backup/restore, what the production-readiness pass changed, and
known limitations. Ideas for extending the correlator: MITRE-aware multi-stage detection
across agents (lateral movement), rule-group-specific correlation instead of just source IP.

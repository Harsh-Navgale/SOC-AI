# SOC-AI

Self-hosted SOC: the correlator groups raw Wazuh alerts into cases, the backend runs AI
investigations on them (AWS Bedrock, with RAG over org docs in ChromaDB), the
React dashboard drives it. Five Docker containers behind nginx on :8443.

Setup, troubleshooting and deployment are in `BUILD_GUIDE.md`. Architecture decisions,
runtime behaviour and known limitations are in `PRODUCTION.md`. Read those rather than
re-deriving them; keep them updated instead of adding a third overview here.

Pipeline: `raw_alerts` -> correlator -> `incidents` (a "case") -> enrich (threat intel +
org context) -> AI investigation -> "incident". Each stage has an admin pause switch.

## Commands

```
make up / down / logs / ps     # docker compose wrappers
make test                      # both pytest suites, inside the containers
make seed                      # synthetic alerts, no Wazuh needed
```

Running pytest on the host needs **Python 3.11** — `pydantic==2.9.2` and `orjson==3.10.7`
ship no wheels for 3.12+ and will try to build from source. `uv venv --python 3.11` works.
Frontend: `cd frontend && npm test`.

## Constraints that break things silently

- **One uvicorn worker is load-bearing.** AWS/Bedrock/Wazuh/threat-intel credentials,
  rate-limit buckets, WebSocket connections and upload-job progress all live in
  module-level dicts in that single process. Adding `--workers` does not error, it just
  makes each of those work only part of the time.
- **The correlator has no network or AI dependency on purpose** (`requirements.txt` is
  pymongo alone). Asset lookup reads a cache the backend fills. Anything needing HTTP or
  a model belongs in `backend/app/case_enrichment.py`, not in that poll loop.
- **The duplication between `correlator/correlator.py` and `backend/app/main.py` is
  deliberate** — `_alert_time`, `_rule_key`, `flatten_alert_values`, `merge_unique_values`
  are copied so the two services share no code. Do not "fix" it with a shared module;
  change both copies together.
- **Backend is capped at `mem_limit: 256m`.** Anything that reads a whole upload or
  collection into memory has to stream instead.
- **The embedding model cannot change once `org_knowledge` holds vectors** — the existing
  ones would all need re-embedding. See `backend/app/pipeline_settings.py`.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.

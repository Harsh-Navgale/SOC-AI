import asyncio
import logging
import os
import queue
import re
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pymongo import UpdateOne
from pymongo.errors import BulkWriteError

from app.auth import (
    LoginRequest,
    TokenResponse,
    CreateUserRequest,
    authenticate,
    create_token,
    decode_token,
    require_auth,
    require_admin,
    bootstrap_admin,
    hash_password,
    revoke_token,
    bearer_scheme,
)
from fastapi.security import HTTPAuthorizationCredentials
from app.db import raw_alerts, incidents, users, conversations, system_heartbeats, ensure_indexes
from app.schemas import (
    AskRequest,
    AskResponse,
    ConversationSummary,
    ConversationDetail,
    RenameConversationRequest,
    UpdateIncidentRequest,
    NoteRequest,
    CloseIncidentRequest,
    AWSCredentialsRequest,
    BedrockCredentialsRequest,
    BedrockApiKeyRequest,
    WazuhCredentialsRequest,
    ThreatIntelCredentialsRequest,
    BulkDeleteRequest,
    ExclusionRuleRequest,
    UpdateExclusionRuleRequest,
    EnabledSettingRequest,
    DefaultAiModelRequest,
    BudgetCapRequest,
    EvalRunRequest,
    InitUploadRequest,
    DebugModeRequest,
    WazuhDiagnosticQueryRequest,
)
from app.rag import ask_ai, embed_text, collection, investigate_incident, embed_case_resolution
from app.scheduler import start_scheduler
from app import scheduler as scheduler_module
from app import debug_state, alerting, notifications, ai_usage, asset_cache, pipeline_settings, case_enrichment, eval_harness
from app.health import aggregate_health
from app import aws_session, bedrock_session, bedrock_client, wazuh_session, wazuh_client, manual_agents, threat_intel_session, threat_intel
from app.config import (
    AWS_DEFAULT_REGION,
    BEDROCK_REGION,
    CORRELATION_WINDOW_SECONDS,
    CORRELATION_THRESHOLD,
)
from app.wazuh_manager_client import WazuhManagerNotConfigured, list_agents_with_fallback
from app import wazuh_diagnostics
from app.s3_inventory import S3NotConfigured, S3CredentialsRequired, S3AuthenticationFailed, fetch_latest_inventory
from app.asset_coverage import reconcile as reconcile_assets
from app.risk_score import compute_risk_score
from app.alerts_upload import (
    parse_wazuh_alerts_file,
    LARGE_FILE_THRESHOLD_BYTES,
    sniff_is_json_array_or_object,
    iter_alerts_jsonl_file,
    _meets_min_rule_level,
)
from app import upload_jobs
from app import upload_sessions
from app import live_logs
from app import exclusion_rules as exclusion_rules_module
from app import rule_health
from app.rate_limit import rate_limit
from app import audit
from app import ws_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("soc.main")
live_logs.install()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await ensure_indexes()
    await case_enrichment.backfill_legacy_cases()
    await bootstrap_admin()
    await debug_state.load_debug_mode()
    start_scheduler()
    yield


app = FastAPI(title="SOC-AI Backend", lifespan=lifespan)

# Same-origin in production (nginx proxies /api on the same host/port), so this is
# intentionally permissive only for local `vite dev` usage against a bare backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/system/health")
async def system_health(_user: dict = Depends(require_auth)):
    return await aggregate_health()


@app.websocket("/api/ws/events")
async def ws_events(websocket: WebSocket, token: str = ""):
    # Browsers can't attach an Authorization header to a WebSocket handshake, so the token
    # travels as a query param instead — same JWT, same decode_token() used by every REST route.
    try:
        decode_token(token)
    except Exception:
        await websocket.close(code=4401)
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(websocket)


# ---- Auth & users ----

@app.post(
    "/api/auth/login",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit("login", max_calls=5, window_seconds=300))],
)
async def login(payload: LoginRequest):
    user = await authenticate(payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return TokenResponse(access_token=create_token(user["_id"], user["role"]), role=user["role"])


@app.post("/api/auth/logout")
async def logout(
    user: dict = Depends(require_auth),
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    """Revokes the current token server-side so it can't be used again before its own 12h
    expiry — without this, logging out only ever cleared the token client-side and the same
    token stayed valid if it leaked or was reused."""
    revoke_token(credentials.credentials)
    await audit.log_action(user["username"], "auth.logout")
    return {"logged_out": True}


@app.post("/api/auth/refresh", response_model=TokenResponse)
async def refresh(user: dict = Depends(require_auth)):
    """Mints a fresh 12h token for a still-currently-valid session — called periodically by the
    frontend so an analyst's session doesn't silently expire mid-shift. Requires the same bearer
    auth as any other route, so a token that has already expired is rejected here exactly like
    it would be anywhere else — this only extends a session that hasn't lapsed yet."""
    return TokenResponse(access_token=create_token(user["username"], user["role"]), role=user["role"])


@app.post("/api/users")
async def create_user(payload: CreateUserRequest, admin: dict = Depends(require_admin)):
    if await users.find_one({"_id": payload.username}):
        raise HTTPException(status_code=409, detail="User already exists")
    await users.insert_one({
        "_id": payload.username,
        "password_hash": hash_password(payload.password),
        "role": payload.role,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    await audit.log_action(admin["username"], "user.create", target=payload.username, details={"role": payload.role})
    return {"username": payload.username, "role": payload.role}


@app.get("/api/users")
async def list_users(_admin: dict = Depends(require_admin)):
    cursor = users.find({}, {"password_hash": 0})
    return [doc async for doc in cursor]


@app.delete("/api/users/{username}")
async def delete_user(username: str, current: dict = Depends(require_admin)):
    if username == current["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    target = await users.find_one({"_id": username})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target["role"] == "admin" and await users.count_documents({"role": "admin"}) <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last remaining admin")
    await users.delete_one({"_id": username})
    await audit.log_action(current["username"], "user.delete", target=username)
    return {"deleted": username}


@app.get("/api/audit-log")
async def list_audit_log(limit: int = 100, _admin: dict = Depends(require_admin)):
    cursor = audit.audit_log.find().sort("timestamp", -1).limit(limit)
    return [doc async for doc in cursor]


# ---- Integrations: AWS session + asset coverage ----

@app.post("/api/integrations/aws/credentials")
async def set_aws_credentials(payload: AWSCredentialsRequest, admin: dict = Depends(require_admin)):
    aws_session.set_credentials(
        access_key_id=payload.access_key_id,
        secret_access_key=payload.secret_access_key,
        session_token=payload.session_token,
        region=payload.region or AWS_DEFAULT_REGION,
    )
    await audit.log_action(admin["username"], "aws.credentials.set")
    return aws_session.status()


@app.get("/api/integrations/aws/status")
async def get_aws_status(_user: dict = Depends(require_auth)):
    return aws_session.status()


@app.delete("/api/integrations/aws/credentials")
async def clear_aws_credentials(admin: dict = Depends(require_admin)):
    aws_session.clear_credentials()
    await audit.log_action(admin["username"], "aws.credentials.clear")
    return {"configured": False}


# ---- Integrations: Bedrock session (separate from the AWS/S3 one above — see bedrock_session.py) ----

@app.post("/api/integrations/bedrock/credentials")
async def set_bedrock_credentials(payload: BedrockCredentialsRequest, admin: dict = Depends(require_admin)):
    bedrock_session.set_credentials(
        access_key_id=payload.access_key_id,
        secret_access_key=payload.secret_access_key,
        session_token=payload.session_token,
        region=payload.region or BEDROCK_REGION,
    )
    await audit.log_action(admin["username"], "bedrock.credentials.set")
    return bedrock_session.status()


@app.post("/api/integrations/bedrock/api-key")
async def set_bedrock_api_key(payload: BedrockApiKeyRequest, admin: dict = Depends(require_admin)):
    bedrock_session.set_api_key(api_key=payload.api_key, region=payload.region or BEDROCK_REGION)
    await audit.log_action(admin["username"], "bedrock.api_key.set")
    return bedrock_session.status()


@app.get("/api/integrations/bedrock/status")
async def get_bedrock_status(_user: dict = Depends(require_auth)):
    return bedrock_session.status()


@app.delete("/api/integrations/bedrock/credentials")
async def clear_bedrock_credentials(admin: dict = Depends(require_admin)):
    bedrock_session.clear_credentials()
    await audit.log_action(admin["username"], "bedrock.credentials.clear")
    return {"configured": False}


@app.post("/api/integrations/wazuh/credentials")
async def set_wazuh_credentials(payload: WazuhCredentialsRequest, admin: dict = Depends(require_admin)):
    wazuh_session.set_credentials(
        host=payload.host,
        user=payload.user,
        password=payload.password,
        verify_ssl=payload.verify_ssl,
    )
    await audit.log_action(admin["username"], "wazuh.credentials.set", details={"host": payload.host})
    return wazuh_session.status()


@app.get("/api/integrations/wazuh/status")
async def get_wazuh_status(_user: dict = Depends(require_auth)):
    return wazuh_session.status()


@app.delete("/api/integrations/wazuh/credentials")
async def clear_wazuh_credentials(admin: dict = Depends(require_admin)):
    wazuh_session.clear_credentials()
    await audit.log_action(admin["username"], "wazuh.credentials.clear")
    return {"configured": False}


@app.post("/api/integrations/wazuh/agents-sheet")
async def upload_agent_sheet(user: dict = Depends(require_admin), file: UploadFile = File(...)):
    raw = await file.read()
    agents = manual_agents.parse_csv(raw)
    if not agents:
        raise HTTPException(status_code=400, detail="No data rows found in the uploaded CSV")
    manual_agents.set_agents(agents, uploaded_by=user["username"])
    await audit.log_action(user["username"], "wazuh.agents_sheet.upload", details={"count": len(agents)})
    return manual_agents.status()


@app.get("/api/integrations/wazuh/agents-sheet/status")
async def get_agent_sheet_status(_user: dict = Depends(require_auth)):
    return manual_agents.status()


@app.delete("/api/integrations/wazuh/agents-sheet")
async def clear_agent_sheet(admin: dict = Depends(require_admin)):
    manual_agents.clear_agents()
    await audit.log_action(admin["username"], "wazuh.agents_sheet.clear")
    return {"configured": False}


# ---- Threat Intel (VirusTotal, AbuseIPDB, and abuse.ch each need a free key/account) ----

@app.post("/api/integrations/threat-intel/credentials")
async def set_threat_intel_credentials(payload: ThreatIntelCredentialsRequest, admin: dict = Depends(require_admin)):
    threat_intel_session.set_credentials(
        virustotal_api_key=payload.virustotal_api_key,
        abuseipdb_api_key=payload.abuseipdb_api_key,
        abusech_auth_key=payload.abusech_auth_key,
    )
    # A cached "not_configured" result from before these keys existed would otherwise keep
    # masking real data on repeat lookups until the cache TTL happens to expire.
    threat_intel.clear_cache()
    await audit.log_action(admin["username"], "threat_intel.credentials.set")
    return threat_intel_session.status()


@app.get("/api/integrations/threat-intel/status")
async def get_threat_intel_status(_user: dict = Depends(require_auth)):
    return threat_intel_session.status()


@app.delete("/api/integrations/threat-intel/credentials")
async def clear_threat_intel_credentials(admin: dict = Depends(require_admin)):
    threat_intel_session.clear_credentials()
    threat_intel.clear_cache()
    await audit.log_action(admin["username"], "threat_intel.credentials.clear")
    return {"virustotal_configured": False, "abuseipdb_configured": False, "abusech_configured": False}


@app.get(
    "/api/threat-intel/lookup",
    dependencies=[Depends(rate_limit("threat-intel-lookup", max_calls=20, window_seconds=60))],
)
async def threat_intel_lookup(indicator: str, _user: dict = Depends(require_auth)):
    if not indicator or not indicator.strip():
        raise HTTPException(status_code=422, detail="indicator is required")
    return await threat_intel.lookup_all(indicator.strip())


@app.get("/api/assets/wazuh-agents")
async def get_wazuh_agents(_user: dict = Depends(require_auth)):
    """Raw browse of every agent registered in Wazuh — independent of S3/AWS entirely, so
    this works even when no AWS session is connected. Falls back to a manually-uploaded sheet
    when the live Wazuh Manager API isn't configured or isn't reachable."""
    try:
        agents, source = await list_agents_with_fallback()
    except WazuhManagerNotConfigured:
        raise HTTPException(status_code=409, detail="Wazuh Manager API is not configured")
    except Exception as exc:
        logger.exception("Wazuh agent list fetch failed")
        raise HTTPException(status_code=502, detail=f"Wazuh agent fetch failed: {exc}")
    return {"count": len(agents), "agents": agents, "source": source}


@app.get("/api/wazuh/logs")
async def get_wazuh_logs(
    node_id: str = "", level: str = "", tag: str = "", search: str = "", limit: int = 200,
    _admin: dict = Depends(require_admin),
):
    """Wazuh manager's own ossec.log entries via its REST API — the troubleshooting log viewer,
    never direct file/SSH access. node_id picks a specific cluster node (e.g. the worker)
    instead of whichever node WAZUH_MANAGER_HOST happens to point at."""
    try:
        logs = await wazuh_diagnostics.get_logs(
            node_id=node_id or None, level=level or None, tag=tag or None, search=search or None, limit=limit,
        )
    except WazuhManagerNotConfigured:
        raise HTTPException(status_code=409, detail="Wazuh Manager API is not configured")
    except Exception as exc:
        logger.exception("Wazuh log fetch failed")
        raise HTTPException(status_code=502, detail=f"Wazuh log fetch failed: {exc}")
    return {"count": len(logs), "logs": logs}


@app.post("/api/wazuh/diagnostic-query")
async def post_wazuh_diagnostic_query(payload: WazuhDiagnosticQueryRequest, admin: dict = Depends(require_admin)):
    """Ad-hoc, read-only (GET-only, enforced in wazuh_diagnostics.py) query against the Manager
    or Indexer API for a "problem checkup" — audit-logged here since it's a new, direct
    read surface against production Wazuh infrastructure, even though it can't mutate anything."""
    try:
        result = await wazuh_diagnostics.run_diagnostic_query(payload.target, payload.path)
    except wazuh_diagnostics.DiagnosticQueryRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except WazuhManagerNotConfigured:
        raise HTTPException(status_code=409, detail="Wazuh Manager API is not configured")
    except Exception as exc:
        logger.exception("Wazuh diagnostic query failed")
        raise HTTPException(status_code=502, detail=f"Wazuh diagnostic query failed: {exc}")
    await audit.log_action(admin["username"], "wazuh.diagnostic_query", details={"target": payload.target, "path": payload.path})
    return result


@app.get("/api/assets/s3-inventory")
async def get_s3_inventory(_user: dict = Depends(require_auth)):
    try:
        records = await fetch_latest_inventory()
    except S3CredentialsRequired:
        raise HTTPException(status_code=409, detail="AWS session not connected or expired")
    except S3AuthenticationFailed as exc:
        raise HTTPException(status_code=409, detail=f"AWS session rejected — please reconnect: {exc}")
    except S3NotConfigured:
        raise HTTPException(status_code=409, detail="S3_INVENTORY_BUCKET is not configured")
    except Exception as exc:
        logger.exception("S3 inventory fetch failed")
        raise HTTPException(status_code=502, detail=f"S3 fetch failed: {exc}")
    return {"count": len(records), "records": records}


@app.get("/api/assets/coverage")
async def get_asset_coverage(_user: dict = Depends(require_auth)):
    try:
        return await reconcile_assets()
    except S3CredentialsRequired:
        raise HTTPException(status_code=409, detail="AWS session not connected or expired")
    except S3AuthenticationFailed as exc:
        raise HTTPException(status_code=409, detail=f"AWS session rejected — please reconnect: {exc}")
    except S3NotConfigured:
        raise HTTPException(status_code=409, detail="S3_INVENTORY_BUCKET is not configured")
    except WazuhManagerNotConfigured:
        raise HTTPException(status_code=409, detail="Wazuh Manager API is not configured")
    except Exception as exc:
        logger.exception("Asset coverage reconciliation failed")
        raise HTTPException(status_code=502, detail=f"Reconciliation failed: {exc}")


@app.post("/api/assets/refresh-cache")
async def refresh_asset_cache_endpoint(admin: dict = Depends(require_admin)):
    """Manually re-runs the same cache fill the daily scheduler job does — useful right after
    connecting AWS credentials, instead of waiting up to 24h for the next scheduled refresh.
    New/updated cases still only get enriched going forward (at creation/fold-in time); this
    doesn't retroactively backfill existing incidents."""
    try:
        count = await asset_cache.refresh()
    except S3CredentialsRequired:
        raise HTTPException(status_code=409, detail="AWS session not connected or expired")
    except S3AuthenticationFailed as exc:
        raise HTTPException(status_code=409, detail=f"AWS session rejected — please reconnect: {exc}")
    except S3NotConfigured:
        raise HTTPException(status_code=409, detail="S3_INVENTORY_BUCKET is not configured")
    except Exception as exc:
        logger.exception("Asset inventory cache refresh failed")
        raise HTTPException(status_code=502, detail=f"Cache refresh failed: {exc}")
    await audit.log_action(admin["username"], "assets.refresh_cache", details={"count": count})
    return {"count": count}


@app.get("/api/assets/cache-status")
async def get_asset_cache_status(_user: dict = Depends(require_auth)):
    return await asset_cache.meta()


# ---- Pipeline stage pause switches (raw alert -> case -> AI investigation -> incident) ----

@app.get("/api/settings/alert-ingestion")
async def get_alert_ingestion_setting(_user: dict = Depends(require_auth)):
    return {"enabled": scheduler_module.alert_ingestion_enabled}


@app.post("/api/settings/alert-ingestion")
async def set_alert_ingestion_setting(payload: EnabledSettingRequest, admin: dict = Depends(require_admin)):
    scheduler_module.set_alert_ingestion_enabled(payload.enabled)
    await audit.log_action(admin["username"], "alert_ingestion.set", details={"enabled": payload.enabled})
    return {"enabled": scheduler_module.alert_ingestion_enabled}


@app.get("/api/settings/case-correlation")
async def get_case_correlation_setting(_user: dict = Depends(require_auth)):
    return {"enabled": not await pipeline_settings.is_correlation_paused()}


@app.post("/api/settings/case-correlation")
async def set_case_correlation_setting(payload: EnabledSettingRequest, admin: dict = Depends(require_admin)):
    await pipeline_settings.set_correlation_paused(not payload.enabled)
    await audit.log_action(admin["username"], "case_correlation.set", details={"enabled": payload.enabled})
    return {"enabled": not await pipeline_settings.is_correlation_paused()}


@app.get("/api/settings/auto-investigate")
async def get_auto_investigate_setting(_user: dict = Depends(require_auth)):
    return {"enabled": scheduler_module.auto_investigate_enabled}


@app.post("/api/settings/auto-investigate")
async def set_auto_investigate_setting(payload: EnabledSettingRequest, admin: dict = Depends(require_admin)):
    scheduler_module.set_auto_investigate_enabled(payload.enabled)
    await audit.log_action(admin["username"], "auto_investigate.set", details={"enabled": payload.enabled})
    return {"enabled": scheduler_module.auto_investigate_enabled}


@app.get("/api/settings/case-enrichment")
async def get_case_enrichment_setting(_user: dict = Depends(require_auth)):
    return {"enabled": scheduler_module.enrichment_enabled}


@app.post("/api/settings/case-enrichment")
async def set_case_enrichment_setting(payload: EnabledSettingRequest, admin: dict = Depends(require_admin)):
    scheduler_module.set_enrichment_enabled(payload.enabled)
    await audit.log_action(admin["username"], "case_enrichment.set", details={"enabled": payload.enabled})
    return {"enabled": scheduler_module.enrichment_enabled}


@app.get("/api/settings/campaign-correlation")
async def get_campaign_correlation_setting(_user: dict = Depends(require_auth)):
    return {"enabled": scheduler_module.campaign_correlation_enabled}


@app.post("/api/settings/campaign-correlation")
async def set_campaign_correlation_setting(payload: EnabledSettingRequest, admin: dict = Depends(require_admin)):
    scheduler_module.set_campaign_correlation_enabled(payload.enabled)
    await audit.log_action(admin["username"], "campaign_correlation.set", details={"enabled": payload.enabled})
    return {"enabled": scheduler_module.campaign_correlation_enabled}


# ---- Active scheduler/correlator alerts ----
# Any authenticated user can see these (not just admins) — a Bedrock outage affects every
# analyst trying to use AI features, not just the person who'd fix it.

@app.get("/api/alerts/active")
async def get_active_alerts(_user: dict = Depends(require_auth)):
    return {"items": alerting.active_alerts()}


# ---- Notifications ----
# Case assignment and case-aging alerts. No per-connection WS targeting — every client just
# refetches its own filtered list on a shared "notifications_changed" ping (see notifications.py).

@app.get("/api/notifications")
async def list_notifications(user: dict = Depends(require_auth)):
    items = await notifications.list_for_user(user["username"], user["role"] == "admin")
    unread = await notifications.unread_count(user["username"], user["role"] == "admin")
    return {"items": items, "unread": unread}


@app.post("/api/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, _user: dict = Depends(require_auth)):
    await notifications.mark_read(notification_id)
    return {"ok": True}


@app.post("/api/notifications/read-all")
async def mark_all_notifications_read(user: dict = Depends(require_auth)):
    await notifications.mark_all_read(user["username"], user["role"] == "admin")
    return {"ok": True}


# ---- Debug mode ----
# A runtime-only switch (not persisted to Mongo — it's meant to be flipped on for a
# troubleshooting session, not to survive a backend restart). Turning it on raises backend log
# verbosity and unlocks raw AI prompt/response tracing in the UI; the diagnostics endpoint below
# is always readable by admins regardless of the switch, since it's just a status snapshot.

@app.get("/api/debug/mode")
async def get_debug_mode(_user: dict = Depends(require_auth)):
    return {"enabled": debug_state.get_debug_mode()}


@app.post("/api/debug/mode")
async def set_debug_mode_endpoint(payload: DebugModeRequest, admin: dict = Depends(require_admin)):
    await debug_state.set_debug_mode(payload.enabled)
    await audit.log_action(admin["username"], "debug_mode.set", details={"enabled": payload.enabled})
    return {"enabled": debug_state.get_debug_mode()}


@app.get("/api/debug/logs/all")
async def stream_all_logs(token: str = ""):
    """Real-time plain-text log tail — meant to be opened directly as a URL (linked from the
    Debug tab), not called via fetch, so auth travels as a query param the same way it does for
    the WebSocket endpoint above: a browser navigating straight to a URL can't attach an
    Authorization header. Admin-only, since raw application logs can include internal details
    (request paths, exception messages) that aren't meant for a non-admin's view.
    """
    try:
        user = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    return StreamingResponse(live_logs.stream(), media_type="text/plain")


@app.get("/api/debug/diagnostics")
async def get_debug_diagnostics(_admin: dict = Depends(require_admin)):
    correlator_heartbeat = await system_heartbeats.find_one({"_id": "correlator"}) or {}
    correlator_heartbeat.pop("_id", None)

    return {
        "debug_mode_enabled": debug_state.get_debug_mode(),
        "alert_ingestion_enabled": scheduler_module.alert_ingestion_enabled,
        "case_correlation_enabled": not await pipeline_settings.is_correlation_paused(),
        "enrichment_enabled": scheduler_module.enrichment_enabled,
        "auto_investigate_enabled": scheduler_module.auto_investigate_enabled,
        "campaign_correlation_enabled": scheduler_module.campaign_correlation_enabled,
        "correlation": {
            "window_seconds": CORRELATION_WINDOW_SECONDS,
            "threshold": CORRELATION_THRESHOLD,
        },
        "integrations": {
            "aws": aws_session.status(),
            "bedrock": bedrock_session.status(),
            "wazuh_manager": wazuh_session.status(),
            "threat_intel": threat_intel_session.status(),
            "manual_agents": manual_agents.status(),
        },
        "correlator": correlator_heartbeat,
        "wazuh_ingestion": wazuh_client.last_poll_stats(),
        "recent_errors": debug_state.recent_errors(),
        "active_alerts": alerting.active_alerts(),
        "ai_usage": {**await ai_usage.summary(), "monthly_budget_cap": await pipeline_settings.get_monthly_budget_cap()},
    }


# ---- Alert exclusion rules ----
# An admin describes, in plain language, alerts that should never become incidents. The AI
# structures that description into a fast, deterministic filter ONCE at save time — see
# app/exclusion_rules.py for why this isn't a live per-alert model call. The correlator (a
# separate service) reads this same collection directly to apply the filter to incoming alerts.

@app.post("/api/exclusion-rules")
async def create_exclusion_rule(payload: ExclusionRuleRequest, admin: dict = Depends(require_admin)):
    has_structured_field = any([payload.rule_id, payload.rule_description, payload.ip])
    if not has_structured_field and not (payload.description or "").strip():
        raise HTTPException(status_code=422, detail="Provide a description or at least one of rule ID / rule description / IP")
    doc = await exclusion_rules_module.create_rule(
        payload.description, admin["username"],
        rule_id=payload.rule_id, rule_description=payload.rule_description,
        ip=payload.ip, ip_field=payload.ip_field,
    )
    await audit.log_action(admin["username"], "exclusion_rule.create", target=doc["_id"], details={"description": doc["description"]})
    return doc


@app.get("/api/exclusion-rules")
async def list_exclusion_rules(_user: dict = Depends(require_auth)):
    cursor = exclusion_rules_module.exclusion_rules.find().sort("created_at", -1)
    return [doc async for doc in cursor]


@app.patch("/api/exclusion-rules/{rule_id}")
async def update_exclusion_rule(rule_id: str, payload: UpdateExclusionRuleRequest, admin: dict = Depends(require_admin)):
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    if "description" in updates:
        # Editing the description means the old structured criteria no longer necessarily
        # match what the analyst actually wants — re-run the AI structuring rather than
        # leaving stale criteria in place.
        updates["criteria"] = await exclusion_rules_module.structure_criteria(updates["description"])
    result = await exclusion_rules_module.exclusion_rules.update_one({"_id": rule_id}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Exclusion rule not found")
    await audit.log_action(admin["username"], "exclusion_rule.update", target=rule_id, details=payload.model_dump(exclude_unset=True))
    return await exclusion_rules_module.exclusion_rules.find_one({"_id": rule_id})


@app.delete("/api/exclusion-rules/{rule_id}")
async def delete_exclusion_rule(rule_id: str, admin: dict = Depends(require_admin)):
    result = await exclusion_rules_module.exclusion_rules.delete_one({"_id": rule_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Exclusion rule not found")
    await audit.log_action(admin["username"], "exclusion_rule.delete", target=rule_id)
    return {"deleted": rule_id}


@app.get("/api/rule-health")
async def rule_health_summary(_admin: dict = Depends(require_admin)):
    """Per-rule rollup of HUMAN-CONFIRMED dispositions (see CloseIncidentRequest.disposition) —
    a rule tuning candidate backed by real analyst evidence, not a single unconfirmed AI guess."""
    return await rule_health.get_rule_health_summary()


@app.post("/api/eval/run")
async def start_eval_run(payload: EvalRunRequest, admin: dict = Depends(require_admin)):
    """Kicks off eval_harness.run_eval() as a detached background task — see that module's
    docstring for why (real, billed AI calls, must not block this request). Rejects a second
    run while one is already in progress rather than letting two samples race on the same
    "latest" report doc."""
    existing = await eval_harness.get_latest_report()
    if existing and existing.get("status") == "running":
        raise HTTPException(status_code=409, detail="An eval run is already in progress")

    task = asyncio.create_task(eval_harness.run_eval(payload.sample_size))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    await audit.log_action(admin["username"], "eval.run.start", details={"sample_size": payload.sample_size})
    return {"status": "running", "sample_size_requested": payload.sample_size}


@app.get("/api/eval/latest")
async def get_latest_eval_report(_admin: dict = Depends(require_admin)):
    report = await eval_harness.get_latest_report()
    if not report:
        raise HTTPException(status_code=404, detail="No eval run has ever been started")
    return report


# ---- Alerts & incidents (cases) ----

# A Wazuh rule level of 10+ is the same "high severity" threshold used everywhere else in this
# app (AlertsTable's row highlighting, the correlator's own incident severity bump), so filtering
# alerts by severity here reuses that exact cutoff rather than inventing a second one.
HIGH_SEVERITY_LEVEL = 10


@app.get("/api/alerts")
async def list_alerts(
    limit: int = 100,
    skip: int = 0,
    severity: str = "",
    search: str = "",
    _user: dict = Depends(require_auth),
):
    query: dict = {}
    if severity == "high":
        query["rule.level"] = {"$gte": HIGH_SEVERITY_LEVEL}
    elif severity == "low":
        query["rule.level"] = {"$lt": HIGH_SEVERITY_LEVEL}
    if search:
        pattern = {"$regex": re.escape(search), "$options": "i"}
        query["$or"] = [
            {"rule.description": pattern},
            {"agent.name": pattern},
            {"agent.ip": pattern},
        ]
    total = await raw_alerts.count_documents(query)
    cursor = raw_alerts.find(query).sort("timestamp", -1).skip(skip).limit(limit)
    items = [doc async for doc in cursor]
    return {"items": items, "total": total}


def _pop_alert_id(alert: dict) -> str:
    # Both must always be popped regardless of which wins — a short-circuited `or` would skip
    # popping "_id" whenever "id" is truthy, leaking it into the stored document and letting it
    # silently override the intended _id on upsert (a real alert commonly has both: its own
    # embedded "id" plus an OpenSearch "_id" from being unwrapped out of a hit/search-response).
    own_id = alert.pop("id", None)
    indexer_id = alert.pop("_id", None)
    return str(own_id or indexer_id or uuid.uuid4())


# asyncio only holds a *weak* reference to a task created via create_task — with nothing else
# referencing it, it can be garbage-collected mid-run (silently, with no error) the moment the
# request handler that spawned it returns. This set of strong references is the standard fix,
# with each task removing itself once it's done.
_background_tasks: set[asyncio.Task] = set()


_PARSE_QUEUE_LOOKAHEAD = 4  # batches the parser thread may build before the writers catch up
# Live-measured on a real 1.2M-alert import: raising this from 4 to 8 was NOT a speedup — it was
# ~28% slower end to end (263s vs 206s for the same file), most likely from more concurrent
# upserts contending on Mongo's per-document/index locking under this box's single CPU. 4 is
# both the faster measured setting and comfortably memory-safe under the 256MB container limit.
_MAX_CONCURRENT_WRITES = 4


def _parse_batches_in_background(path: str, batch_size: int, out_queue: "queue.Queue", job_id: str):
    """Runs on its own OS thread (see run_in_executor below), continuously reading and parsing
    `path` and pushing complete batches onto `out_queue` — a `queue.Queue` (the classic
    thread-safe blocking one, not asyncio.Queue, since this function is never itself a
    coroutine and has no event loop to hand back to). This is what lets parsing (CPU-bound,
    single-threaded) happen concurrently with the writer coroutines below actually writing
    previous batches to Mongo (I/O-bound), instead of the two strictly alternating — parsing
    batch N+1 no longer has to wait for batch N's write to finish. Pushes a StopIteration
    sentinel on success, or the exception instance itself if parsing failed, so the consumer
    loop can tell "done" apart from "broken" without a second channel.

    Alerts below MIN_RULE_LEVEL_FOR_UPLOAD are dropped here rather than in
    iter_alerts_jsonl_file itself — that function's job is just unwrapping shapes into flat alert
    dicts; this is the one place that also has a job_id to count the drops against
    (upload_jobs.increment_job is thread-safe, so calling it directly from this background
    thread is fine). Byte-progress tracking is deliberately independent of what got kept: the
    last `consumed` value is flushed unconditionally at the end so a run whose final lines all
    get filtered still reports bytes_processed == total_bytes, rather than plateauing short.
    """
    try:
        batch: list[tuple[dict, int]] = []
        last_consumed = 0
        for alert, consumed in iter_alerts_jsonl_file(path):
            last_consumed = consumed
            if not _meets_min_rule_level(alert):
                upload_jobs.increment_job(job_id, skipped_low_severity=1)
                continue
            batch.append((alert, consumed))
            if len(batch) >= batch_size:
                out_queue.put(batch)
                batch = []
        if batch:
            out_queue.put(batch)
        upload_jobs.bump_bytes_processed(job_id, last_consumed)
        out_queue.put(StopIteration)
    except Exception as exc:
        out_queue.put(exc)


async def _run_large_alert_import(job_id: str, path: str, batch_size: int = 2000):
    """Background task for a large (> LARGE_FILE_THRESHOLD_BYTES) alert-file import: streams
    `path` (already known to be JSON Lines — see sniff_is_json_array_or_object at the call site)
    in bounded-memory batches and bulk-upserts each one, updating upload_jobs as it goes so
    GET /api/alerts/upload/status/{job_id} has something fresh to report. Runs detached from the
    request that started it (fired via asyncio.create_task), so its only way to communicate is
    that shared job record — there's no response object left to return anything to.

    Parsing and writing are pipelined (see _parse_batches_in_background) and up to
    _MAX_CONCURRENT_WRITES batches can be in flight to Mongo at once — each batch's document IDs
    are independent of every other batch's, and every write is its own upsert, so nothing here
    depends on batches landing in any particular order.

    The _MAX_CONCURRENT_WRITES cap has to be enforced at *task creation*, not just inside the
    task body: parsing is CPU-bound and typically much faster than a Mongo bulk_write, so if the
    consume loop below created a task for every batch the moment it was parsed, the backlog of
    already-created-but-still-waiting tasks (each holding a full batch of `batch_size` alert
    dicts in its closure) would grow without bound and OOM the container long before parsing
    ever caught up to what had actually been written — a semaphore acquired *inside* write_batch
    only bounds concurrent execution, not concurrent existence, so it doesn't prevent this.
    """
    parse_queue: "queue.Queue" = queue.Queue(maxsize=_PARSE_QUEUE_LOOKAHEAD)
    loop = asyncio.get_running_loop()
    parse_future = loop.run_in_executor(None, _parse_batches_in_background, path, batch_size, parse_queue, job_id)

    async def write_batch(batch: list[tuple[dict, int]]):
        ops = []
        bytes_at_batch_end = 0
        for alert, consumed in batch:
            alert = dict(alert)
            alert_id = _pop_alert_id(alert)
            alert["correlated"] = False
            ops.append(UpdateOne({"_id": alert_id}, {"$setOnInsert": alert}, upsert=True))
            bytes_at_batch_end = max(bytes_at_batch_end, consumed)

        try:
            result = await raw_alerts.bulk_write(ops, ordered=False)
            inserted = result.upserted_count
            upload_jobs.increment_job(job_id, inserted=inserted, duplicates=len(ops) - inserted)
        except BulkWriteError as exc:
            details = exc.details or {}
            inserted = len(details.get("upserted", []))
            write_errors = len(details.get("writeErrors", []))
            # A write error still leaves the rest of the batch's upserts committed —
            # ordered=False is exactly what makes that true — so only the failed ones count
            # against `failed`, matching the small-file path's "one bad row doesn't sink the
            # batch" behavior.
            upload_jobs.increment_job(
                job_id, inserted=inserted, failed=write_errors,
                duplicates=max(len(ops) - inserted - write_errors, 0),
            )
        except Exception:
            logger.exception("Bulk write failed for a batch during alert import %s", job_id)
            upload_jobs.increment_job(job_id, failed=len(ops))

        # Batches can finish writing out of order (that's the whole point of running them
        # concurrently) — bump_bytes_processed is the monotonic, race-free version of this
        # update; see its docstring for why a plain get-then-set here isn't safe.
        upload_jobs.bump_bytes_processed(job_id, bytes_at_batch_end)

    pending: set[asyncio.Task] = set()
    try:
        while True:
            item = await asyncio.to_thread(parse_queue.get)
            if item is StopIteration:
                break
            if isinstance(item, Exception):
                raise item

            if len(pending) >= _MAX_CONCURRENT_WRITES:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()  # re-raises if write_batch itself raised (not a caught Mongo error)

            pending.add(asyncio.create_task(write_batch(item)))

        if pending:
            await asyncio.gather(*pending)
        await parse_future  # surfaces anything run_in_executor itself raised (e.g. thread setup)

        upload_jobs.update_job(job_id, status="done", finished_at=time.time())
    except Exception as exc:
        logger.exception("Alert import %s failed", job_id)
        for task in pending:
            task.cancel()
        upload_jobs.update_job(job_id, status="error", error=str(exc), finished_at=time.time())
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


@app.post("/api/alerts/upload")
async def upload_alerts(user: dict = Depends(require_admin), file: UploadFile = File(...)):
    """Ingests a file of real Wazuh alert JSON straight into raw_alerts — same document shape and
    same upsert-by-id behavior the live poller (`scheduler.py:poll_wazuh`) uses, so uploaded
    alerts flow through the exact same correlation -> incident -> AI pipeline as ones pulled from
    a live Wazuh Indexer.

    Small files (<= LARGE_FILE_THRESHOLD_BYTES) are handled inline, exactly as before: JSON
    Lines, a JSON array, or a single object (including OpenSearch hit/search-response shapes),
    parsed fully in memory, with the result returned in this same response.

    Larger files skip straight past all of that: this container has a hard memory limit, so
    reading a multi-GB file into one `bytes` object (let alone parsing it into one Python object
    tree) isn't just slow, it's a guaranteed OOM. Anything over the threshold is instead streamed
    to a temp file and handed to a background task (see _run_large_alert_import) that processes
    it in bounded-memory batches — this endpoint returns a job_id immediately so the caller can
    poll /api/alerts/upload/status/{job_id} for real progress instead of holding one HTTP request
    open for however long a multi-GB import takes.
    """
    if file.size is not None and file.size > LARGE_FILE_THRESHOLD_BYTES:
        fd, tmp_path = tempfile.mkstemp(prefix="alert-upload-", suffix=".jsonl")
        try:
            with os.fdopen(fd, "wb") as tmp:
                while True:
                    chunk = await file.read(4 * 1024 * 1024)
                    if not chunk:
                        break
                    tmp.write(chunk)
        except Exception:
            os.remove(tmp_path)
            raise

        if await asyncio.to_thread(sniff_is_json_array_or_object, tmp_path):
            os.remove(tmp_path)
            raise HTTPException(
                status_code=400,
                detail=(
                    "This file looks like a JSON array, not JSON Lines. Files over "
                    f"{LARGE_FILE_THRESHOLD_BYTES // (1024 * 1024)}MB must be JSON Lines — "
                    "Wazuh's native alerts.json format, one alert object per line."
                ),
            )

        job_id = upload_jobs.create_job(file.filename, file.size)
        task = asyncio.create_task(_run_large_alert_import(job_id, tmp_path))
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
        await audit.log_action(
            user["username"], "alerts.upload.start",
            details={"filename": file.filename, "size_bytes": file.size, "job_id": job_id},
        )
        return {"job_id": job_id, "total_bytes": file.size}

    raw = await file.read()
    text = raw.decode("utf-8-sig", errors="replace")

    alerts = parse_wazuh_alerts_file(text)
    if not alerts:
        raise HTTPException(status_code=400, detail="No valid alert JSON objects found in the uploaded file")

    # One bulk_write instead of len(alerts) sequential round-trips — this path can see tens of
    # thousands of alerts in a single <=LARGE_FILE_THRESHOLD_BYTES file, all within one HTTP
    # request. ordered=False preserves the exact same "one bad doc doesn't sink the batch"
    # guarantee the old per-document try/except gave, matching _run_large_alert_import's
    # write_batch (same pattern, same reasoning — see that function's BulkWriteError handling).
    ops = []
    for alert in alerts:
        alert = dict(alert)
        alert_id = _pop_alert_id(alert)
        alert["correlated"] = False
        ops.append(UpdateOne({"_id": alert_id}, {"$setOnInsert": alert}, upsert=True))

    inserted = 0
    failed = 0
    if ops:
        try:
            result = await raw_alerts.bulk_write(ops, ordered=False)
            inserted = result.upserted_count
        except BulkWriteError as exc:
            details = exc.details or {}
            inserted = len(details.get("upserted", []))
            failed = len(details.get("writeErrors", []))
            logger.error("Failed to store %d of %d uploaded alerts", failed, len(ops))
        except Exception:
            logger.exception("Bulk write failed for the uploaded alert batch")
            failed = len(ops)

    duplicates = len(alerts) - inserted - failed
    await audit.log_action(
        user["username"], "alerts.upload",
        details={"inserted": inserted, "skipped_duplicates": duplicates, "failed": failed, "total": len(alerts)},
    )
    return {"inserted": inserted, "skipped_duplicates": duplicates, "failed": failed, "total": len(alerts)}


@app.get("/api/alerts/upload/status/{job_id}")
async def get_alert_upload_status(job_id: str, _user: dict = Depends(require_auth)):
    """Polled by the frontend while a large-file import (see upload_alerts) runs in the
    background — bytes_processed/total_bytes is enough for the caller to compute a percentage,
    throughput, and an ETA on its own from successive polls."""
    job = upload_jobs.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Unknown upload job")
    return job


# ---- Resumable alert-file upload — for files large enough that a single unbroken HTTP request
# is a real reliability risk (a network blip or a laptop sleeping hours into a 100GB transfer
# would otherwise mean starting over from zero). The frontend slices the file into chunks and
# PUTs them sequentially; if a chunk fails, it re-checks /status and resumes from the byte the
# server actually has, instead of restarting. upload_alerts() above still exists unchanged for
# everything else — a single-shot multipart POST, no session to manage — and is what a script or
# curl user hitting the API directly would still reach for. ----

@app.post("/api/alerts/upload/init")
async def init_alert_upload(payload: InitUploadRequest, admin: dict = Depends(require_admin)):
    if payload.total_bytes <= LARGE_FILE_THRESHOLD_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Files under {LARGE_FILE_THRESHOLD_BYTES // (1024 * 1024)}MB should use the regular upload instead of a resumable session.",
        )
    session = upload_sessions.create_session(payload.filename, payload.total_bytes)
    await audit.log_action(
        admin["username"], "alerts.upload.session_start",
        details={"filename": payload.filename, "total_bytes": payload.total_bytes, "session_id": session["session_id"]},
    )
    return session


@app.get("/api/alerts/upload/session/{session_id}/status")
async def get_alert_upload_session_status(session_id: str, _admin: dict = Depends(require_admin)):
    session = upload_sessions.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Unknown upload session — it may have expired or already completed")
    return {"bytes_received": session["bytes_received"], "total_bytes": session["total_bytes"]}


@app.put("/api/alerts/upload/session/{session_id}/chunk")
async def upload_alert_chunk(session_id: str, request: Request, _admin: dict = Depends(require_admin)):
    lock = upload_sessions.get_lock(session_id)
    if lock is None:
        raise HTTPException(status_code=404, detail="Unknown upload session — it may have expired or already completed")

    try:
        claimed_offset = int(request.headers.get("x-upload-offset", ""))
    except ValueError:
        raise HTTPException(status_code=400, detail="Missing or invalid X-Upload-Offset header")

    async with lock:
        # Re-read under the lock — another chunk request for this session could have landed
        # while this one was waiting for it.
        session = upload_sessions.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Unknown upload session — it may have expired or already completed")
        if claimed_offset != session["bytes_received"]:
            # The client's own retry/resume logic is expected to hit this occasionally (e.g. a
            # chunk that landed but whose response was lost) — it's told exactly where the
            # server actually is, not just "no", so it can realign instead of getting stuck.
            raise HTTPException(
                status_code=409,
                detail=f"Offset mismatch: server has {session['bytes_received']} bytes, client sent offset {claimed_offset}",
            )

        written = 0
        with open(session["path"], "ab") as f:
            async for data in request.stream():
                f.write(data)
                written += len(data)
        upload_sessions.record_chunk(session_id, written)
        updated = upload_sessions.get_session(session_id)

    return {"bytes_received": updated["bytes_received"], "total_bytes": updated["total_bytes"]}


@app.post("/api/alerts/upload/session/{session_id}/complete")
async def complete_alert_upload(session_id: str, admin: dict = Depends(require_admin)):
    session = upload_sessions.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Unknown upload session — it may have expired or already completed")
    if session["bytes_received"] != session["total_bytes"]:
        raise HTTPException(
            status_code=409,
            detail=f"Upload incomplete: {session['bytes_received']}/{session['total_bytes']} bytes received",
        )

    path = session["path"]
    if await asyncio.to_thread(sniff_is_json_array_or_object, path):
        upload_sessions.discard_session(session_id)
        raise HTTPException(
            status_code=400,
            detail=(
                "This file looks like a JSON array, not JSON Lines. Large uploads must be "
                "JSON Lines — Wazuh's native alerts.json format, one alert object per line."
            ),
        )

    job_id = upload_jobs.create_job(session["filename"], session["total_bytes"])
    task = asyncio.create_task(_run_large_alert_import(job_id, path))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    # Not discard_session — that deletes the temp file too, and the job above owns it now.
    upload_sessions.forget_session(session_id)

    await audit.log_action(
        admin["username"], "alerts.upload.start",
        details={"filename": session["filename"], "size_bytes": session["total_bytes"], "job_id": job_id},
    )
    return {"job_id": job_id, "total_bytes": session["total_bytes"]}


@app.delete("/api/alerts/{alert_id}")
async def delete_alert(alert_id: str, admin: dict = Depends(require_admin)):
    result = await raw_alerts.delete_one({"_id": alert_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Alert not found")
    await audit.log_action(admin["username"], "alert.delete", target=alert_id)
    return {"deleted": alert_id}


@app.post("/api/alerts/delete-bulk")
async def delete_alerts_bulk(payload: BulkDeleteRequest, admin: dict = Depends(require_admin)):
    result = await raw_alerts.delete_many({"_id": {"$in": payload.ids}})
    await audit.log_action(
        admin["username"], "alerts.delete_bulk",
        details={"deleted": result.deleted_count, "requested": len(payload.ids)},
    )
    return {"deleted": result.deleted_count}


@app.post("/api/admin/wipe-alert-data")
async def wipe_alert_data(admin: dict = Depends(require_admin)):
    """Deletes every raw alert and every case/incident in one go — the two collections that make
    up the correlator -> AI pipeline's own data. Deliberately scoped to just those: audit logs,
    AI usage stats, notifications, and the asset-inventory cache are left alone, since none of
    them are "cases, raw alerts, incidents" and wiping the audit log in particular would destroy
    the very record of this action having happened.
    """
    raw_result = await raw_alerts.delete_many({})
    incidents_result = await incidents.delete_many({})
    await audit.log_action(
        admin["username"], "admin.wipe_alert_data",
        details={"raw_alerts_deleted": raw_result.deleted_count, "incidents_deleted": incidents_result.deleted_count},
    )
    await ws_manager.broadcast({"type": "alerts_changed"})
    await ws_manager.broadcast({"type": "incidents_changed"})
    return {"raw_alerts_deleted": raw_result.deleted_count, "incidents_deleted": incidents_result.deleted_count}


def _extract_source_ip(alert: dict) -> str:
    """Mirrors correlator.py's extract_source_ip — always the Wazuh agent's own IP, never
    `data.srcip`, so a manual promotion groups into the same case the correlator itself would
    use for this alert."""
    return alert.get("agent", {}).get("ip") or "unknown"


def _extract_mitre(alert: dict) -> dict:
    mitre = (alert.get("rule", {}) or {}).get("mitre", {}) or {}
    return {"ids": mitre.get("id", []) or [], "tactics": mitre.get("tactic", []) or []}


# Mirrors correlator.py's flatten_alert_values/merge_unique_values exactly — kept as its own
# copy for the same reason _rule_key/_alert_time above are: this module and the correlator
# container share no dependency on each other by design.
_EXCLUDED_TOP_LEVEL_KEYS = {"_id", "correlated", "timestamp"}
_MAX_FULL_LOG_VALUES = 10
_MAX_VALUES_PER_FIELD = 50


def _flatten_alert_values(alert: dict) -> dict:
    out: dict = {}

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                if not path and key in _EXCLUDED_TOP_LEVEL_KEYS:
                    continue
                walk(value, f"{path}.{key}" if path else key)
        elif isinstance(node, list):
            for item in node:
                walk(item, path)
        elif node not in (None, ""):
            out.setdefault(path, set()).add(str(node))

    walk(alert, "")
    return out


def _merge_unique_values(existing, new_values: dict) -> dict:
    merged = {path: set(values) for path, values in (existing or {}).items()}
    for path, values in new_values.items():
        cap = _MAX_FULL_LOG_VALUES if path == "full_log" else _MAX_VALUES_PER_FIELD
        bucket = merged.setdefault(path, set())
        for value in values:
            if len(bucket) >= cap:
                break
            bucket.add(value)
    return {path: sorted(values) for path, values in merged.items()}


def _alert_time(alert: dict, fallback: datetime) -> datetime:
    """Mirrors correlator.py's _alert_time — uses the alert's OWN timestamp, not wall-clock
    processing time, so promoting an alert from an uploaded historical file windows/dates the
    resulting incident the same way the correlator itself would."""
    ts = alert.get("timestamp")
    if ts:
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            logger.warning("Alert %s has an unparseable timestamp %r; using processing time instead", alert.get("_id"), ts)
    return fallback


def _rule_key(alert: dict) -> str:
    """Mirrors correlator.py's _rule_key — cases group by (source_ip, rule), not source_ip
    alone, so two different attack types against the same host become two separate cases
    instead of one bucket. Prefers Wazuh's own stable rule id; falls back to the description
    only when a rule has no id at all."""
    rule = alert.get("rule", {}) or {}
    return str(rule.get("id") or rule.get("description") or "")


def _is_vulnerability_alert(alert: dict) -> bool:
    """Mirrors correlator.py's is_vulnerability_alert — see that function for why."""
    groups = (alert.get("rule", {}) or {}).get("groups") or []
    return any("vulnerability" in str(g).lower() for g in groups)


@app.post("/api/alerts/{alert_id}/promote")
async def promote_alert(alert_id: str, user: dict = Depends(require_auth)):
    """Lets an analyst manually fold a raw alert into a case instead of waiting on the
    correlator's own alert-volume threshold. Reuses the correlator's exact source-IP/rule/MITRE
    extraction and open-incident dedupe window (CORRELATION_WINDOW_SECONDS) so a manual
    promotion is indistinguishable from one the correlator would have produced itself — it
    either folds into an already-open case for this (IP, rule) pair or creates a new one with
    the same field shape `correlator.py` inserts.
    """
    alert = await raw_alerts.find_one({"_id": alert_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    # An excluded alert is also marked correlated=True (so the correlator stops retrying it),
    # but it was never actually folded into a case — an analyst overriding an exclusion rule
    # for one specific alert must still be able to promote it.
    if alert.get("correlated") and not alert.get("excluded"):
        raise HTTPException(status_code=409, detail="This alert is already part of a case")

    source_ip = _extract_source_ip(alert)
    rule = alert.get("rule", {}) or {}
    level = rule.get("level", 0)
    rule_key = _rule_key(alert)
    mitre = _extract_mitre(alert)
    now = datetime.now(timezone.utc)
    alert_time = _alert_time(alert, now)

    # Symmetric range (not just "$gte") — see correlator.py's process_alert for why: uploaded
    # historical data can be processed in any order, and a one-sided check would let a
    # much-later alert's incident swallow a much-earlier one processed afterward.
    open_incident = await incidents.find_one({
        "source_ip": source_ip,
        "rule_key": rule_key,
        "case_status": {"$ne": "closed"},
        "last_seen": {
            "$gte": alert_time.timestamp() - CORRELATION_WINDOW_SECONDS,
            "$lte": alert_time.timestamp() + CORRELATION_WINDOW_SECONDS,
        },
    })

    description = rule.get("description", "")
    asset = await asset_cache.get_for_ip(source_ip)
    alert_values = _flatten_alert_values(alert)

    if open_incident:
        incident_id = open_incident["_id"]
        new_last_seen = max(open_incident.get("last_seen", 0), alert_time.timestamp())
        new_first_seen = min(open_incident.get("first_seen", alert_time.timestamp()), alert_time.timestamp())
        await incidents.update_one(
            {"_id": incident_id},
            {
                "$push": {"alert_ids": alert_id},
                "$inc": {"alert_count": 1},
                "$max": {"max_level": level},
                "$addToSet": {
                    "mitre_ids": {"$each": mitre["ids"]},
                    "mitre_tactics": {"$each": mitre["tactics"]},
                },
                "$set": {
                    "first_seen": new_first_seen,
                    "first_seen_iso": datetime.fromtimestamp(new_first_seen, tz=timezone.utc).isoformat(),
                    "last_seen": new_last_seen,
                    "last_seen_iso": datetime.fromtimestamp(new_last_seen, tz=timezone.utc).isoformat(),
                    # Refreshed on every fold-in too, not just at creation — keeps it current as
                    # the cache itself gets refreshed, at near-zero extra cost (already reading it).
                    "asset": asset,
                    "unique_values": _merge_unique_values(open_incident.get("unique_values"), alert_values),
                },
            },
        )
        if open_incident["alert_count"] + 1 >= CORRELATION_THRESHOLD:
            await incidents.update_one({"_id": incident_id}, {"$set": {"severity": "high"}})
    else:
        incident_id = str(uuid.uuid4())
        await incidents.insert_one({
            "_id": incident_id,
            "source_ip": source_ip,
            "rule_key": rule_key,
            "case_status": "open",
            "assigned_to": None,
            "notes": [],
            "severity": "low",
            "alert_ids": [alert_id],
            "alert_count": 1,
            "max_level": level,
            "mitre_ids": mitre["ids"],
            "mitre_tactics": mitre["tactics"],
            "first_seen": alert_time.timestamp(),
            "first_seen_iso": alert_time.isoformat(),
            "last_seen": alert_time.timestamp(),
            "last_seen_iso": alert_time.isoformat(),
            "rule_description": description,
            "asset": asset,
            "priority": 0,
            "unique_values": _merge_unique_values(None, alert_values),
            "is_vulnerability_alert": _is_vulnerability_alert(alert),
        })

    await raw_alerts.update_one(
        {"_id": alert_id},
        {"$set": {"correlated": True}, "$unset": {"excluded": "", "excluded_by_rule": ""}},
    )
    await audit.log_action(user["username"], "alert.promote", target=alert_id, details={"incident_id": incident_id})

    doc = await incidents.find_one({"_id": incident_id})
    doc["risk"] = compute_risk_score(doc)
    return doc


@app.get("/api/incidents")
async def list_incidents(
    limit: int = 100,
    skip: int = 0,
    severity: str = "",
    case_status: str = "",
    search: str = "",
    reviewed: str = "",
    campaign_id: str = "",
    _user: dict = Depends(require_auth),
):
    query: dict = {}
    if severity:
        query["severity"] = severity
    if case_status:
        query["case_status"] = case_status
    if campaign_id:
        query["campaign_id"] = campaign_id
    # "Cases" (reviewed=false) are correlator output the AI hasn't looked at yet; once
    # auto_investigate_cases (or a manual "Investigate with AI" click) attaches a report, the
    # same document becomes an "Incident" (reviewed=true) — same collection, no separate stage.
    if reviewed == "false":
        query["investigation"] = {"$exists": False}
    elif reviewed == "true":
        query["investigation"] = {"$exists": True}
    if search:
        pattern = {"$regex": re.escape(search), "$options": "i"}
        query["$or"] = [
            {"source_ip": pattern},
            {"rule_description": pattern},
            {"assigned_to": pattern},
        ]
    total = await incidents.count_documents(query)
    cursor = incidents.find(query).sort("last_seen", -1).skip(skip).limit(limit)
    items = [doc async for doc in cursor]
    for doc in items:
        doc["risk"] = compute_risk_score(doc)
    return {"items": items, "total": total}


@app.get("/api/incidents/queue")
async def get_investigation_queue(_user: dict = Depends(require_auth)):
    # Same ordering auto_investigate_cases actually processes in — priority desc, then oldest
    # first — so this panel shows the real queue, not just an arbitrary case listing. Route
    # must be declared before the "/{incident_id}" route below or FastAPI would treat "queue"
    # as an incident_id path parameter.
    cursor = incidents.find({"investigation": {"$exists": False}}).sort([("priority", -1), ("first_seen", 1)])
    items = [doc async for doc in cursor]
    for doc in items:
        doc["risk"] = compute_risk_score(doc)
    return {"items": items, "total": len(items)}


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str, _user: dict = Depends(require_auth)):
    doc = await incidents.find_one({"_id": incident_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Incident not found")
    doc["risk"] = compute_risk_score(doc)
    # Every distinct raw log line seen across all alerts folded into this case (correlator.py /
    # promote_alert's unique_values) — no live alert lookup needed, it's already on the case.
    doc["full_logs"] = (doc.get("unique_values") or {}).get("full_log", [])
    # The IP the frontend should run its own threat-intel lookup against — the external caller
    # when the case had exactly one, else the host's own IP. See threat_intel.resolve_target_ip.
    doc["threat_intel_ip"] = threat_intel.resolve_target_ip(doc)

    return doc


@app.get("/api/incidents/{incident_id}/related")
async def get_related_incidents(incident_id: str, _user: dict = Depends(require_auth)):
    incident = await incidents.find_one({"_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    cursor = incidents.find({
        "source_ip": incident["source_ip"],
        "_id": {"$ne": incident_id},
    }).sort("last_seen", -1).limit(10)
    return [doc async for doc in cursor]


@app.delete("/api/incidents/{incident_id}")
async def delete_incident(incident_id: str, admin: dict = Depends(require_admin)):
    result = await incidents.delete_one({"_id": incident_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")
    await audit.log_action(admin["username"], "incident.delete", target=incident_id)
    return {"deleted": incident_id}


@app.post("/api/incidents/delete-bulk")
async def delete_incidents_bulk(payload: BulkDeleteRequest, admin: dict = Depends(require_admin)):
    result = await incidents.delete_many({"_id": {"$in": payload.ids}})
    await audit.log_action(
        admin["username"], "incidents.delete_bulk",
        details={"deleted": result.deleted_count, "requested": len(payload.ids)},
    )
    return {"deleted": result.deleted_count}


@app.patch("/api/incidents/{incident_id}")
async def update_incident(incident_id: str, payload: UpdateIncidentRequest, user: dict = Depends(require_auth)):
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    if updates.get("case_status") == "closed":
        # Closing a case here would skip the required disposition (and the resolution text) that
        # POST /close enforces — the only path allowed to actually close a case.
        raise HTTPException(status_code=400, detail="Use POST /api/incidents/{id}/close to close a case")
    result = await incidents.update_one({"_id": incident_id}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")
    await audit.log_action(user["username"], "incident.update", target=incident_id, details=updates)
    doc = await incidents.find_one({"_id": incident_id})
    doc["risk"] = compute_risk_score(doc)

    assignee = updates.get("assigned_to")
    if assignee and assignee != user["username"]:
        await notifications.create(
            f"{user['username']} assigned you a case: {doc.get('source_ip')} ({doc.get('rule_description')})",
            "case_assigned", user=assignee, incident_id=incident_id,
        )
        await ws_manager.broadcast({"type": "notifications_changed"})

    return doc


@app.post("/api/incidents/{incident_id}/notes")
async def add_note(incident_id: str, payload: NoteRequest, user: dict = Depends(require_auth)):
    note = {
        "author": user["username"],
        "text": payload.text,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    result = await incidents.update_one({"_id": incident_id}, {"$push": {"notes": note}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")
    await audit.log_action(user["username"], "incident.note", target=incident_id)
    return note


@app.post("/api/incidents/{incident_id}/close")
async def close_incident(incident_id: str, payload: CloseIncidentRequest, user: dict = Depends(require_auth)):
    incident = await incidents.find_one({"_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.now(timezone.utc)
    await incidents.update_one(
        {"_id": incident_id},
        {"$set": {
            "case_status": "closed",
            "resolution": payload.resolution,
            "disposition": payload.disposition,
            "closed_at": now.isoformat(),
            "closed_by": user["username"],
        }},
    )
    await audit.log_action(
        user["username"], "incident.close", target=incident_id,
        details={"resolution": payload.resolution, "disposition": payload.disposition},
    )

    knowledge_embedded = False
    try:
        await embed_case_resolution(incident, payload.resolution, payload.disposition)
        knowledge_embedded = True
    except Exception:
        logger.exception("Failed to embed case resolution for incident %s", incident_id)

    if payload.disposition == "false_positive":
        try:
            notified = await rule_health.check_fp_threshold(
                incident.get("rule_key"), incident.get("rule_description"), incident_id,
            )
            if notified:
                await ws_manager.broadcast({"type": "notifications_changed"})
        except Exception:
            logger.exception("Failed to check FP threshold for rule_key=%s", incident.get("rule_key"))

    return {"case_status": "closed", "knowledge_embedded": knowledge_embedded}


@app.post("/api/incidents/{incident_id}/investigate")
async def investigate(incident_id: str, _user: dict = Depends(require_auth)):
    incident = await incidents.find_one({"_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    ti_result = None
    ti_target = threat_intel.resolve_target_ip(incident)
    if ti_target:
        try:
            ti_result = await threat_intel.lookup_all(ti_target)
        except Exception:
            logger.exception("Threat intel lookup failed while investigating incident %s", incident_id)

    # Stored on the incident at creation time (correlator.py / main.py's promote_alert) from
    # the cached S3 inventory — no live S3 call needed here anymore, see asset_cache.py.
    asset = incident.get("asset")

    risk = compute_risk_score(incident)

    # Stored on the incident at correlation time (correlator.py / promote_alert) — every
    # distinct value seen across all of this case's alerts, not just the most recent one.
    unique_values = incident.get("unique_values")

    report = await investigate_incident(incident, threat_intel=ti_result, asset=asset, risk=risk, unique_values=unique_values)
    await ai_usage.record(
        "investigate", report.get("model_used", ""), report.get("prompt_tokens", 0),
        report.get("completion_tokens", 0), parse_ok=report.get("parse_ok"),
    )
    await incidents.update_one({"_id": incident_id}, {"$set": {"investigation": report}})
    return report


@app.post("/api/incidents/{incident_id}/requeue")
async def requeue_incident(incident_id: str, user: dict = Depends(require_auth)):
    """Puts an already-reviewed incident back into the pending AI queue for re-investigation —
    the "add to queue" action in the AI Queue panel. Dropping the `investigation` field is what
    makes a document a "case" again (see list_incidents' reviewed filter), so auto_investigate_cases
    picks it up on its next tick same as any other pending case."""
    result = await incidents.update_one({"_id": incident_id}, {"$unset": {"investigation": ""}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")
    await audit.log_action(user["username"], "incident.requeue", target=incident_id)
    await ws_manager.broadcast({"type": "incidents_changed"})
    doc = await incidents.find_one({"_id": incident_id})
    doc["risk"] = compute_risk_score(doc)
    return doc


# ---- AI chat & knowledge ingestion ----

@app.get("/api/ai/models")
async def ai_models(_user: dict = Depends(require_auth)):
    """Every model an analyst can pick for a single Ask AI query — only attempted when a Bedrock
    session is actually connected, so an unconnected Bedrock never triggers a live AWS call just
    from opening this page. Each entry has {"name", "label", "provider"} — "label" is a
    human-readable name since real Bedrock model ids are long.
    """
    if bedrock_session.get_credentials() is None:
        raise HTTPException(status_code=503, detail="No AI models available (Bedrock not connected)")

    try:
        models = [
            {"name": f"bedrock:{m['model_id']}", "label": m["label"], "provider": "bedrock"}
            for m in await bedrock_client.list_models()
        ]
    except Exception as exc:
        logger.warning("Failed to list Bedrock models: %s", exc)
        raise HTTPException(status_code=503, detail=f"No AI models available (Bedrock list failed: {exc})")

    if not models:
        raise HTTPException(status_code=503, detail="No AI models available (Bedrock not connected)")
    return models


@app.get("/api/settings/default-ai-model")
async def get_default_ai_model_setting(_user: dict = Depends(require_auth)):
    return {"model_id": await pipeline_settings.get_default_ai_model()}


@app.post("/api/settings/default-ai-model")
async def set_default_ai_model_setting(payload: DefaultAiModelRequest, admin: dict = Depends(require_admin)):
    await pipeline_settings.set_default_ai_model(payload.model_id)
    await audit.log_action(admin["username"], "default_ai_model.set", details={"model_id": payload.model_id})
    return {"model_id": payload.model_id}


@app.get("/api/settings/fallback-ai-model")
async def get_fallback_ai_model_setting(_user: dict = Depends(require_auth)):
    return {"model_id": await pipeline_settings.get_fallback_ai_model()}


@app.post("/api/settings/fallback-ai-model")
async def set_fallback_ai_model_setting(payload: DefaultAiModelRequest, admin: dict = Depends(require_admin)):
    """A second model _generate() crosses over to when the default's own provider is
    unreachable outright (not just a bad answer) — see rag.py's _generate() docstring. Reuses
    DefaultAiModelRequest since the shape (just a model_id string) is identical."""
    await pipeline_settings.set_fallback_ai_model(payload.model_id)
    await audit.log_action(admin["username"], "fallback_ai_model.set", details={"model_id": payload.model_id})
    return {"model_id": payload.model_id}


@app.get("/api/settings/multi-agent-investigation")
async def get_multi_agent_investigation_setting(_user: dict = Depends(require_auth)):
    return {"enabled": await pipeline_settings.is_multi_agent_investigation_enabled()}


@app.post("/api/settings/multi-agent-investigation")
async def set_multi_agent_investigation_setting(payload: EnabledSettingRequest, admin: dict = Depends(require_admin)):
    """Routes investigate_incident() through app/investigation_pipeline.py's staged rule-health
    + verdict agents instead of one prompt — roughly doubles AI-generation cost/latency per
    incident, so this is an explicit admin opt-in rather than a silent default change."""
    await pipeline_settings.set_multi_agent_investigation_enabled(payload.enabled)
    await audit.log_action(admin["username"], "multi_agent_investigation.set", details={"enabled": payload.enabled})
    return {"enabled": payload.enabled}


@app.get("/api/settings/structured-output")
async def get_structured_output_setting(_user: dict = Depends(require_auth)):
    return {"enabled": await pipeline_settings.is_structured_output_enabled()}


@app.post("/api/settings/structured-output")
async def set_structured_output_setting(payload: EnabledSettingRequest, admin: dict = Depends(require_admin)):
    """Routes investigate_incident()'s single-prompt path through Bedrock's schema-constrained
    tool-use instead of freeform-text + regex parsing, when the resolved model is Claude-on-
    Bedrock — an explicit admin opt-in since it touches the already-tested core investigation
    prompt; validate with the eval harness before relying on it."""
    await pipeline_settings.set_structured_output_enabled(payload.enabled)
    await audit.log_action(admin["username"], "structured_output.set", details={"enabled": payload.enabled})
    return {"enabled": payload.enabled}


@app.get("/api/settings/cheap-ai-model")
async def get_cheap_ai_model_setting(_user: dict = Depends(require_auth)):
    return {"model_id": await pipeline_settings.get_cheap_ai_model()}


@app.post("/api/settings/cheap-ai-model")
async def set_cheap_ai_model_setting(payload: DefaultAiModelRequest, admin: dict = Depends(require_admin)):
    """The model investigate_incident() routes a mechanically-simple case to (a vulnerability
    alert, or one with a close confirmed-disposition precedent) instead of the default model —
    see rag.py's investigate_incident(). Reuses DefaultAiModelRequest, same shape."""
    model_id = payload.model_id or None
    await pipeline_settings.set_cheap_ai_model(model_id)
    await audit.log_action(admin["username"], "cheap_ai_model.set", details={"model_id": model_id})
    return {"model_id": model_id}


@app.get("/api/settings/monthly-budget-cap")
async def get_monthly_budget_cap_setting(_user: dict = Depends(require_auth)):
    return {"amount": await pipeline_settings.get_monthly_budget_cap()}


@app.post("/api/settings/monthly-budget-cap")
async def set_monthly_budget_cap_setting(payload: BudgetCapRequest, admin: dict = Depends(require_admin)):
    """Checked by scheduler.py's auto_investigate_cases before each tick — crossing it pauses
    only the automatic path; a human-initiated "Investigate with AI" click still goes through."""
    await pipeline_settings.set_monthly_budget_cap(payload.amount)
    await audit.log_action(admin["username"], "monthly_budget_cap.set", details={"amount": payload.amount})
    return {"amount": payload.amount}


@app.get("/api/ai/embedding-models")
async def ai_embedding_models(_user: dict = Depends(require_auth)):
    """Unlike /api/ai/models, this isn't a per-query picker — every embed_text() call has to use
    the same source (RAG retrieval into one ChromaDB collection needs one consistent embedding
    space), so this just lists what's available for the admin-only default-embedding-model
    setting below, not a dropdown next to a chat box.
    """
    models = []

    if bedrock_session.get_credentials() is not None:
        try:
            for m in await bedrock_client.list_embedding_models():
                models.append({"name": f"bedrock:{m['model_id']}", "label": m["label"], "provider": "bedrock"})
        except Exception as exc:
            logger.warning("Failed to list Bedrock embedding models: %s", exc)

    return models


@app.get("/api/settings/default-embedding-model")
async def get_default_embedding_model_setting(_user: dict = Depends(require_auth)):
    return {"model_id": await pipeline_settings.get_default_embedding_model()}


@app.post("/api/settings/default-embedding-model")
async def set_default_embedding_model_setting(payload: DefaultAiModelRequest, admin: dict = Depends(require_admin)):
    await pipeline_settings.set_default_embedding_model(payload.model_id)
    await audit.log_action(admin["username"], "default_embedding_model.set", details={"model_id": payload.model_id})
    return {"model_id": payload.model_id}


def _conversation_title(question: str) -> str:
    q = question.strip()
    return q if len(q) <= 60 else q[:60] + "…"


@app.post("/api/ask", response_model=AskResponse)
async def ask(payload: AskRequest, user: dict = Depends(require_auth)):
    now = datetime.now(timezone.utc).isoformat()
    history = None

    if payload.conversation_id:
        convo = await conversations.find_one({"_id": payload.conversation_id})
        if not convo:
            raise HTTPException(status_code=404, detail="Conversation not found")
        conversation_id = payload.conversation_id
        history = [{"role": m["role"], "content": m["content"]} for m in convo.get("messages", [])]
    else:
        conversation_id = str(uuid.uuid4())
        await conversations.insert_one({
            "_id": conversation_id,
            "author": user["username"],
            "title": _conversation_title(payload.question),
            "message_count": 0,
            "messages": [],
            "created_at": now,
            "updated_at": now,
        })

    result = await ask_ai(payload.question, model=payload.model, history=history)
    await ai_usage.record(
        "ask_ai", result["model"], result.get("prompt_tokens", 0), result.get("completion_tokens", 0),
        cache_read_tokens=result.get("cache_read_tokens", 0), cache_write_tokens=result.get("cache_write_tokens", 0),
    )

    user_msg = {"role": "user", "content": payload.question, "author": user["username"], "created_at": now}
    assistant_msg = {
        "role": "assistant",
        "content": result["answer"],
        "model": result["model"],
        "elapsed_seconds": result["elapsed_seconds"],
        "context_chunks": result["context_chunks"],
        "prompt": result.get("prompt"),
        "prompt_tokens": result.get("prompt_tokens"),
        "completion_tokens": result.get("completion_tokens"),
        "estimated_cost": result.get("estimated_cost"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await conversations.update_one(
        {"_id": conversation_id},
        {
            "$push": {"messages": {"$each": [user_msg, assistant_msg]}},
            "$inc": {"message_count": 2},
            "$set": {"updated_at": assistant_msg["created_at"]},
        },
    )

    result["conversation_id"] = conversation_id
    return result


@app.get("/api/conversations", response_model=list[ConversationSummary])
async def list_conversations(_user: dict = Depends(require_auth)):
    cursor = conversations.find({}, {"messages": 0}).sort("updated_at", -1)
    return [
        {
            "id": doc["_id"],
            "title": doc["title"],
            "author": doc["author"],
            "updated_at": doc["updated_at"],
            "message_count": doc.get("message_count", 0),
        }
        async for doc in cursor
    ]


@app.get("/api/conversations/{conversation_id}", response_model=ConversationDetail)
async def get_conversation(conversation_id: str, _user: dict = Depends(require_auth)):
    doc = await conversations.find_one({"_id": conversation_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {
        "id": doc["_id"],
        "title": doc["title"],
        "author": doc["author"],
        "created_at": doc["created_at"],
        "updated_at": doc["updated_at"],
        "messages": doc.get("messages", []),
    }


@app.patch("/api/conversations/{conversation_id}")
async def rename_conversation(conversation_id: str, payload: RenameConversationRequest, _user: dict = Depends(require_auth)):
    result = await conversations.update_one({"_id": conversation_id}, {"$set": {"title": payload.title}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"id": conversation_id, "title": payload.title}


@app.delete("/api/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str, _user: dict = Depends(require_auth)):
    result = await conversations.delete_one({"_id": conversation_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"deleted": True}


@app.post("/api/ingest")
async def ingest(filename: str, text: str, _user: dict = Depends(require_auth)):
    """Used by the console to push org-specific documents into the vector DB."""
    chunks = [text[i:i + 800] for i in range(0, len(text), 800)]
    for idx, chunk in enumerate(chunks):
        embedding = await embed_text(chunk)
        # upsert, not add: re-ingesting an edited file reuses the same chunk ids, and
        # collection.add() on a duplicate id silently keeps the old chunk text instead of
        # updating it (same chromadb behavior fixed in rag.py's embed_case_resolution).
        collection.upsert(
            ids=[f"{filename}-{idx}"],
            embeddings=[embedding],
            documents=[chunk],
            metadatas=[{"source": filename}],
        )
    return {"ingested_chunks": len(chunks)}

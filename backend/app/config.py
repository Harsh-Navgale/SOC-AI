import os

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongodb:27017")
MONGO_DB = os.getenv("MONGO_DB", "soc_ai")

CHROMA_HOST = os.getenv("CHROMA_HOST", "chromadb")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))

# Zero-config fallback-of-last-resort when an admin hasn't configured a default model in
# Settings yet — used only when pipeline_settings.get_default_ai_model()/
# get_default_embedding_model() both return None. Bedrock still needs a connected session to
# actually serve a request; these just guarantee there's always a sane model id to try once one
# is connected, rather than failing with "no model configured" on top of "no session connected."
DEFAULT_BEDROCK_CHAT_MODEL = os.getenv("DEFAULT_BEDROCK_CHAT_MODEL", "anthropic.claude-haiku-4-5-v1:0")
DEFAULT_BEDROCK_EMBED_MODEL = os.getenv("DEFAULT_BEDROCK_EMBED_MODEL", "amazon.titan-embed-text-v2:0")

# Purely informational — lets the Debug tab show "what this would have cost on Bedrock" next to
# real local token counts, without actually billing anything. Defaults match Claude Haiku 4.5.
AI_COST_PER_1M_INPUT = float(os.getenv("AI_COST_PER_1M_INPUT", "1.0"))
AI_COST_PER_1M_OUTPUT = float(os.getenv("AI_COST_PER_1M_OUTPUT", "5.0"))

WAZUH_INDEXER_HOST = os.getenv("WAZUH_INDEXER_HOST", "https://your-wazuh-indexer:9200")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")
WAZUH_INDEX_PATTERN = os.getenv("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")
WAZUH_INDEXER_VERIFY_SSL = os.getenv("WAZUH_INDEXER_VERIFY_SSL", "true").lower() == "true"
WAZUH_CA_BUNDLE = os.getenv("WAZUH_CA_BUNDLE", "") or None

WAZUH_MANAGER_HOST = os.getenv("WAZUH_MANAGER_HOST", "https://your-wazuh-manager:55000")
WAZUH_MANAGER_USER = os.getenv("WAZUH_MANAGER_USER", "wazuh-wui")
WAZUH_MANAGER_PASSWORD = os.getenv("WAZUH_MANAGER_PASSWORD", "")
WAZUH_MANAGER_VERIFY_SSL = os.getenv("WAZUH_MANAGER_VERIFY_SSL", "true").lower() == "true"

CORRELATION_WINDOW_SECONDS = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))
CORRELATION_THRESHOLD = int(os.getenv("CORRELATION_THRESHOLD", "5"))

RAW_ALERT_RETENTION_DAYS = int(os.getenv("RAW_ALERT_RETENTION_DAYS", "30"))

AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
# Bedrock is its own connection (see bedrock_session.py), independent of the S3/AWS one above —
# a different AWS account/role, and Bedrock model availability varies by region regardless of
# wherever the S3 inventory bucket happens to live.
BEDROCK_REGION = os.getenv("BEDROCK_REGION", "us-east-1")
# Optional: point at a self-hosted S3-compatible endpoint (MinIO, etc.) instead of real AWS.
# Leave unset for real AWS S3 — this only matters for non-AWS or local S3-compatible setups.
AWS_S3_ENDPOINT_URL = os.getenv("AWS_S3_ENDPOINT_URL", "") or None
S3_INVENTORY_BUCKET = os.getenv("S3_INVENTORY_BUCKET", "")
S3_INVENTORY_PREFIX = os.getenv("S3_INVENTORY_PREFIX", "")
S3_INVENTORY_KEY = os.getenv("S3_INVENTORY_KEY", "")
S3_INVENTORY_FORMAT = os.getenv("S3_INVENTORY_FORMAT", "json")
S3_INVENTORY_HOSTNAME_FIELD = os.getenv("S3_INVENTORY_HOSTNAME_FIELD", "hostname")
S3_INVENTORY_IP_FIELD = os.getenv("S3_INVENTORY_IP_FIELD", "ip")

# Threat Intel tab — VirusTotal, AbuseIPDB, and abuse.ch (URLhaus + ThreatFox share one
# "Auth-Key") each need a free API key. Usually entered at runtime from the Threat Intel page
# (admin only, held in memory for 12h, same as AWS/Wazuh), but can be set here instead for a
# permanent lab/server key.
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "") or None
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "") or None
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "") or None


# Generic alert webhook — POSTed as {"text": "..."} on scheduler/correlator failure states, which
# Slack's Incoming Webhooks (and most chat-ops tools) accept as-is. Empty (the default) means
# alerts only ever show up in-app; nothing external to configure to get that much.
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "") or None
ALERT_FAILURE_THRESHOLD = int(os.getenv("ALERT_FAILURE_THRESHOLD", "3"))
CORRELATOR_STALE_SECONDS = int(os.getenv("CORRELATOR_STALE_SECONDS", "120"))

# A case open this long without being closed gets an aging notification (once).
CASE_AGING_HOURS = int(os.getenv("CASE_AGING_HOURS", "48"))

# A rule with at least this many confirmed-false-positive closures gets a one-time admin
# notification suggesting it needs tuning or an exclusion rule (app/rule_health.py).
RULE_FP_NOTIFY_THRESHOLD = int(os.getenv("RULE_FP_NOTIFY_THRESHOLD", "3"))

JWT_SECRET = os.getenv("JWT_SECRET", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET must be set (run scripts/setup.sh to generate one).")
if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD must be set (run scripts/setup.sh to generate one).")

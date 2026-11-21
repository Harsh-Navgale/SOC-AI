import logging

from motor.motor_asyncio import AsyncIOMotorClient
from app.config import MONGO_URI, MONGO_DB, RAW_ALERT_RETENTION_DAYS

logger = logging.getLogger("soc.db")

client = AsyncIOMotorClient(MONGO_URI)
db = client[MONGO_DB]

raw_alerts = db["raw_alerts"]
incidents = db["incidents"]
users = db["users"]
system_heartbeats = db["system_heartbeats"]
conversations = db["conversations"]
notifications = db["notifications"]
ai_usage = db["ai_usage"]
system_settings = db["system_settings"]


async def ensure_indexes():
    await raw_alerts.create_index("timestamp")
    await raw_alerts.create_index("correlated")
    await raw_alerts.create_index(
        "ingested_at",
        expireAfterSeconds=RAW_ALERT_RETENTION_DAYS * 24 * 60 * 60,
    )
    await incidents.create_index([("source_ip", 1), ("case_status", 1)])
    await incidents.create_index("last_seen")
    await conversations.create_index("updated_at")
    await db["audit_log"].create_index("timestamp")
    await db["exclusion_rules"].create_index("active")
    await notifications.create_index([("user", 1), ("read", 1)])
    await notifications.create_index("created_at")
    await ai_usage.create_index("created_at")
    logger.info("Mongo indexes ensured (retention=%sd)", RAW_ALERT_RETENTION_DAYS)

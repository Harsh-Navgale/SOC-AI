"""Seeds a handful of synthetic, Wazuh-alert-shaped documents into raw_alerts so the
correlation -> MongoDB -> AI -> dashboard pipeline can be exercised end-to-end before a
real Wazuh manager connection is configured. Data is entirely made up (fake IP, fake
agent) — nothing derived from any real environment.
"""
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

from pymongo import MongoClient

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongodb:27017")
MONGO_DB = os.getenv("MONGO_DB", "soc_ai")

FAKE_SRC_IP = "198.51.100.23"  # TEST-NET-2, RFC 5737 — reserved for documentation/examples
AGENT = {"id": "001", "name": "demo-web-01", "ip": "10.0.0.15"}


def make_alert(offset_seconds: int) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
    return {
        "_id": f"synthetic-{uuid.uuid4()}",
        "timestamp": ts.isoformat(),
        "correlated": False,
        "agent": AGENT,
        "rule": {
            "id": "5710",
            "level": random.choice([5, 7, 10]),
            "description": "sshd: Attempt to login using a non-existent user",
            "groups": ["authentication_failed", "syslog", "sshd"],
            "mitre": {
                "id": ["T1110"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"],
            },
        },
        "data": {"srcip": FAKE_SRC_IP, "srcuser": "root"},
        "full_log": (
            f"sshd[1234]: Failed password for invalid user root from "
            f"{FAKE_SRC_IP} port 51515 ssh2"
        ),
    }


def main():
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[MONGO_DB]

    alerts = [make_alert(offset) for offset in range(60, 0, -10)]
    result = db["raw_alerts"].insert_many(alerts)

    print(f"Inserted {len(result.inserted_ids)} synthetic alerts from {FAKE_SRC_IP} into raw_alerts.")
    print("The correlator polls every ~10s and will group these into a high-severity incident shortly.")


if __name__ == "__main__":
    main()

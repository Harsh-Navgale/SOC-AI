import asyncio
import json
import logging
import re

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app import aws_session
from app.csv_utils import parse_csv_rows, find_field
from app.config import (
    S3_INVENTORY_BUCKET,
    S3_INVENTORY_PREFIX,
    S3_INVENTORY_KEY,
    S3_INVENTORY_FORMAT,
    S3_INVENTORY_HOSTNAME_FIELD,
    S3_INVENTORY_IP_FIELD,
    AWS_DEFAULT_REGION,
    AWS_S3_ENDPOINT_URL,
)

logger = logging.getLogger("soc.s3_inventory")

# find_field() matches these case/separator-insensitively (see csv_utils.find_field), so a
# single canonical spelling per concept is enough to also match "Hostname", "instance_name",
# "PrivateIpAddress", "private ip address", etc. without enumerating every casing variant.
_HOSTNAME_FALLBACK_FIELDS = [S3_INVENTORY_HOSTNAME_FIELD, "hostname", "host name", "instance name"]

_IP_FALLBACK_FIELDS = [
    S3_INVENTORY_IP_FIELD, "ip", "ip address", "private ip address", "public ip address",
]

# AWS auto-generates EC2 private DNS hostnames in this exact form, embedding the private IP
# directly: "ip-10-10-13-64.ap-south-1.compute.internal" -> "10.10.13.64" (also covers the
# us-east-1-style "...ec2.internal" suffix, which uses the same "ip-a-b-c-d." prefix).
_AWS_INTERNAL_HOSTNAME_RE = re.compile(r"^ip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\.")


_AUTH_ERROR_CODES = {
    "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId",
    "SignatureDoesNotMatch", "UnrecognizedClientException", "AccessDenied",
    "InvalidAccessKeyId", "AuthFailure", "InvalidToken",
}


class S3NotConfigured(Exception):
    pass


class S3CredentialsRequired(Exception):
    """No AWS session is set (or SOC-AI's own 12h tracking already expired it)."""
    pass


class S3AuthenticationFailed(Exception):
    """AWS itself rejected the credentials (expired/invalid) — distinct from
    S3CredentialsRequired so the caller knows to prompt for fresh ones, not just "connect"."""
    pass


def _client():
    creds = aws_session.get_credentials()
    if creds is None:
        raise S3CredentialsRequired("AWS session not connected or expired")

    region = creds.get("region") or AWS_DEFAULT_REGION
    kwargs = {
        "aws_access_key_id": creds["access_key_id"],
        "aws_secret_access_key": creds["secret_access_key"],
        "region_name": region,
    }
    if AWS_S3_ENDPOINT_URL:
        kwargs["endpoint_url"] = AWS_S3_ENDPOINT_URL
        # Non-AWS S3-compatible endpoints (MinIO, this test server) don't resolve
        # virtual-hosted-style URLs (bucket-name.endpoint) — path style always works.
        kwargs["config"] = Config(s3={"addressing_style": "path"})
    if creds.get("session_token"):
        kwargs["aws_session_token"] = creds["session_token"]
    return boto3.client("s3", **kwargs)


def _pick_latest_key(s3, bucket: str, prefix: str) -> str:
    """Same "most-recently-modified, non-empty object" logic as the existing
    ~/Automations/S3/s3_daily_digest.py — proven against the real inventory bucket, so this
    stays consistent with it rather than reinventing the picking rule.
    """
    paginator = s3.get_paginator("list_objects_v2")
    latest = None
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["Size"] == 0:
                continue
            if latest is None or obj["LastModified"] > latest["LastModified"]:
                latest = obj
    if latest is None:
        raise FileNotFoundError(f"No objects found under s3://{bucket}/{prefix}")
    return latest["Key"]


def _parse_body(raw: bytes, fmt: str) -> list[dict]:
    # utf-8-sig strips a leading UTF-8 BOM if present (behaves identically to plain utf-8
    # otherwise). Exports from PowerShell's Export-Csv and Excel commonly include a BOM,
    # which otherwise glues itself onto the first column name (e.g. "﻿hostname") and
    # silently breaks hostname detection even when the column is named correctly.
    text = raw.decode("utf-8-sig", errors="replace")
    if fmt == "ndjson":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if fmt == "csv":
        return parse_csv_rows(text)
    # default: json array
    data = json.loads(text)
    if isinstance(data, dict):
        # tolerate a top-level {"instances": [...]}-style wrapper
        for value in data.values():
            if isinstance(value, list):
                return value
        return [data]
    return data


def _extract_hostname(record: dict) -> str | None:
    return find_field(record, [f for f in _HOSTNAME_FALLBACK_FIELDS if f])


def _derive_ip_from_aws_hostname(hostname: str | None) -> str | None:
    if not hostname:
        return None
    match = _AWS_INTERNAL_HOSTNAME_RE.match(hostname)
    if not match:
        return None
    return ".".join(match.groups())


def _extract_ip(record: dict) -> str | None:
    direct = find_field(record, [f for f in _IP_FALLBACK_FIELDS if f])
    if direct:
        return direct
    # Last resort: no explicit IP column matched (missing, blank, or unrecognized field
    # name) — if the hostname follows AWS's auto-generated EC2 DNS naming convention, the
    # private IP is embedded right in it and can be derived deterministically rather than
    # giving up and reporting a real, active asset as "missing coverage".
    return _derive_ip_from_aws_hostname(_extract_hostname(record))


def _fetch_sync() -> list[dict]:
    if not S3_INVENTORY_BUCKET:
        raise S3NotConfigured("S3_INVENTORY_BUCKET is not set")

    s3 = _client()
    try:
        key = S3_INVENTORY_KEY or _pick_latest_key(s3, S3_INVENTORY_BUCKET, S3_INVENTORY_PREFIX)
        obj = s3.get_object(Bucket=S3_INVENTORY_BUCKET, Key=key)
        raw = obj["Body"].read()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _AUTH_ERROR_CODES:
            # The stored credentials are proven bad — clear them now so the next status
            # check (and the frontend's "reconnect" prompt) reflects reality immediately,
            # rather than waiting out the rest of the 12h window on a dead session.
            aws_session.clear_credentials()
            logger.warning("AWS rejected the stored credentials (%s); session cleared", code)
            raise S3AuthenticationFailed(f"AWS rejected the credentials: {code}") from exc
        logger.warning("S3 inventory fetch failed: %s", exc)
        raise
    except BotoCoreError as exc:
        logger.warning("S3 inventory fetch failed: %s", exc)
        raise

    records = _parse_body(raw, S3_INVENTORY_FORMAT)

    # Every row from the bucket is returned, verbatim, no matter what — a row is never
    # dropped just because we couldn't guess which column holds the hostname/IP. `ip` is the
    # actual match key used by asset_coverage.reconcile(); `hostname` is best-effort, kept
    # only for display. `raw` always carries the complete original record so nothing is lost
    # and the real column names are visible for debugging S3_INVENTORY_IP_FIELD /
    # S3_INVENTORY_HOSTNAME_FIELD via the S3 Inventory tab.
    return [
        {"hostname": _extract_hostname(record), "ip": _extract_ip(record), "raw": record}
        for record in records
    ]


async def fetch_latest_inventory() -> list[dict]:
    """Fetches and parses the latest S3 inventory object.

    Raises S3NotConfigured (bucket unset), S3CredentialsRequired (no/expired AWS session),
    S3AuthenticationFailed (AWS itself rejected the stored credentials — already cleared by
    the time this is raised), or the underlying boto3 exception for any other AWS error
    (missing bucket, etc.) — callers use these to show a distinct, actionable message per
    failure mode.
    """
    return await asyncio.to_thread(_fetch_sync)

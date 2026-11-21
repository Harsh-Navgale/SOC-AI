"""Shared CSV parsing used by both s3_inventory.py and manual_agents.py.

Deliberately does NOT use csv.DictReader, which loses data in two common real-world cases:
  - Duplicate column headers: DictReader silently keeps only the last column's value for a
    repeated name and drops the earlier ones.
  - Ragged rows: a row with fewer fields than the header gets a `None` value for the missing
    trailing columns (usually fine), but a row with MORE fields than the header gets those
    extra values silently bucketed under a `None` key and dropped by dict conversion.
This parser disambiguates duplicate headers (col, col_2, col_3, ...) and keeps every value
from over-long rows under generated extra_N keys, instead of losing either.
"""
import csv
import io


def _normalize_key(key: str) -> str:
    return "".join(c for c in key.lower() if c.isalnum())


def find_field(row: dict, candidates: list[str]) -> str | None:
    """Case- and separator-insensitive lookup for one of several possible column names.

    Real-world CSV exports (Wazuh's own agent export, AWS console exports, PowerShell,
    hand-edited sheets) vary in header spelling in ways a bare case-sensitive dict lookup
    misses entirely — e.g. Wazuh's actual export uses "IP address", not "ip"/"IP"/"Ip". A
    single miss here doesn't degrade gracefully: every row silently gets no IP, so nothing
    can ever match on the other side of a reconciliation and everything looks "missing"
    even though the data was right there under a slightly different header. Normalizing
    both the row's keys and the candidate names (lowercase, strip all non-alphanumerics)
    means "IP address", "ip_address", "IP-Address", and "ip address" are all the same key.
    """
    normalized = {_normalize_key(k): v for k, v in row.items()}
    for candidate in candidates:
        value = normalized.get(_normalize_key(candidate))
        if value:
            return str(value).strip()
    return None


def parse_csv_rows(text: str) -> list[dict]:
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        return []

    seen: dict[str, int] = {}
    deduped_header = []
    for col in header:
        if col in seen:
            seen[col] += 1
            deduped_header.append(f"{col}_{seen[col]}")
        else:
            seen[col] = 0
            deduped_header.append(col)

    rows = []
    for values in reader:
        if not values:
            continue
        row = {}
        for i, value in enumerate(values):
            key = deduped_header[i] if i < len(deduped_header) else f"extra_{i - len(deduped_header) + 1}"
            row[key] = value
        for j in range(len(values), len(deduped_header)):
            row[deduped_header[j]] = ""
        rows.append(row)
    return rows

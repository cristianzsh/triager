"""
Detects timestamp columns in forensic CSVs by heuristic (name match, then
value sampling), since tools use inconsistent naming/formats for the same
concept.
"""
import re
from datetime import datetime, timezone
from typing import Optional

from dateutil import parser as dateutil_parser

# Substrings checked against the lowercased column name.
NAME_HINTS = (
    "time", "date", "timestamp", "created", "modified", "modification",
    "accessed", "access", "written", "changed", "boundary", "install",
    "logon", "executed", "execution", "run", "seen", "start", "end",
    "expir", "deleted", "recordmodification",
)

# Matches a NAME_HINTS substring but is rarely an actual timestamp.
NAME_EXCLUDE = (
    "timezone", "runcount", "runasuser", "username", "filename",
    "sourcefile", "runlevel", "enabled",
)


def looks_like_timestamp_name(column: str) -> bool:
    lower = column.lower()
    if any(x in lower for x in NAME_EXCLUDE):
        return False
    return any(h in lower for h in NAME_HINTS)


# Formats dateutil sometimes mishandles or is slow to try; checked first.
_EXPLICIT_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%Y%m%d%H%M%S",
)

_FILETIME_RE = re.compile(r"^\d{17,19}$")  # raw Windows FILETIME
_BARE_NUMBER_RE = re.compile(r"^-?\d{1,7}$")  # e.g. an enum/ID/count, not a date
_MIN_YEAR, _MAX_YEAR = 1990, 2100  # sanity range; outside this, the heuristic misfired


def try_parse_datetime(value: str) -> Optional[datetime]:
    """Best-effort parse into a UTC datetime, or None if it doesn't look
    like a real date. Callers use the None rate to decide whether a
    column is a genuine timestamp source."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if not v or v in ("0", "-", "N/A", "null", "None"):
        return None

    if _FILETIME_RE.match(v):
        try:
            ft = int(v)
            unix_seconds = (ft - 116444736000000000) / 10_000_000
            if 0 <= unix_seconds <= 4102444800:
                return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        except Exception:
            pass
        return None

    # Bare short numbers (enum/ID/count values) aren't dates, but dateutil
    # will still "parse" them by defaulting missing fields to today.
    if _BARE_NUMBER_RE.match(v):
        return None

    parsed = None
    for fmt in _EXPLICIT_FORMATS:
        try:
            dt = datetime.strptime(v, fmt)
            parsed = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
            break
        except ValueError:
            continue

    if parsed is None:
        try:
            dt = dateutil_parser.parse(v, fuzzy=False)
            parsed = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        except (ValueError, OverflowError, TypeError):
            return None

    if parsed is not None and not (_MIN_YEAR <= parsed.year <= _MAX_YEAR):
        return None
    return parsed


def sample_parse_rate(values: list[str]) -> float:
    """Fraction of non-empty sampled values that parse as a datetime."""
    non_empty = [v for v in values if v and v.strip()]
    if not non_empty:
        return 0.0
    hits = sum(1 for v in non_empty if try_parse_datetime(v) is not None)
    return hits / len(non_empty)

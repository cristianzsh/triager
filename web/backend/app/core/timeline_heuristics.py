"""
Forensic tool CSVs use wildly inconsistent column names and timestamp
formats for what's conceptually the same thing (an event time). There's no
shared schema to rely on, so timeline support works by heuristic:

  1. Name check: does the column name look like it holds a timestamp?
  2. Value check: do enough sampled values actually parse as a date/time?

Only columns that pass both become timeline sources. This trades some
recall (a genuinely useful but oddly-named timestamp column might be missed)
for precision (we'd rather miss a column than pollute the unified timeline
with a numeric ID column that happened to be named "RunCount" or similar).
"""
import re
from datetime import datetime, timezone
from typing import Optional

from dateutil import parser as dateutil_parser

# Substrings checked against the lowercased column name. Deliberately
# broad, Triager's underlying tools (PECmd, EvtxECmd, MFTECmd,
# AmcacheParser, SrumECmd, RBCmd, JLECmd, LECmd, SBECmd, WxTCmd, ...) each
# have their own naming conventions for the same concept.
NAME_HINTS = (
    "time", "date", "timestamp", "created", "modified", "modification",
    "accessed", "access", "written", "changed", "boundary", "install",
    "logon", "executed", "execution", "run", "seen", "start", "end",
    "expir", "deleted", "recordmodification",
)

# Columns that match a NAME_HINTS substring but are almost never actually a
# timestamp in these tools' output, excluded to cut down on false
# positives from the deliberately-broad name list above.
NAME_EXCLUDE = (
    "timezone", "runcount", "runasuser", "username", "filename",
    "sourcefile", "runlevel", "enabled",
)


def looks_like_timestamp_name(column: str) -> bool:
    lower = column.lower()
    if any(x in lower for x in NAME_EXCLUDE):
        return False
    return any(h in lower for h in NAME_HINTS)


# A handful of exact formats seen in these tools' output that dateutil's
# general parser sometimes mishandles or is slower to try first; checked
# before falling back to dateutil.parser.parse for everything else.
_EXPLICIT_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%Y%m%d%H%M%S",
)

_FILETIME_RE = re.compile(r"^\d{17,19}$")  # raw Windows FILETIME, occasionally left unconverted


_BARE_NUMBER_RE = re.compile(r"^-?\d{1,7}$")  # short digit-only string, no date-like structure at all
# Triager collects evidence from real machines, not time travelers or sci-fi
# props -- any parsed date outside this range almost certainly means the
# heuristic misfired on a non-timestamp value, not a genuine old/future date.
_MIN_YEAR, _MAX_YEAR = 1990, 2100


def try_parse_datetime(value: str) -> Optional[datetime]:
    """Best-effort parse of one cell's value into a timezone-aware UTC
    datetime. Returns None (not an exception) on anything that doesn't
    look like a real date, callers use the None rate to decide whether a
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
            if 0 <= unix_seconds <= 4102444800:  # sanity range: 1970..2100
                return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        except Exception:
            pass
        return None

    # A bare short number (e.g. a LogonType/EventID/RunCount-style enum or
    # code value, "5", "284"...) has none of the structure a real date
    # string would (no separators, no month name, not a long enough digit
    # run to be a known numeric timestamp format like epoch/FILETIME
    # above). dateutil.parser will still happily "parse" it below by
    # treating it as a day-of-month or year and silently defaulting every
    # other field to today's date -- exactly how a non-timestamp column
    # produces a nonsense date like year 284. Reject it before that ever
    # gets a chance to run.
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

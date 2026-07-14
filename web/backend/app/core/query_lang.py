import re
from dataclasses import dataclass
from typing import Optional

OPERATORS = ("contains", "not_contains", "startswith", "endswith", "=", "!=", "regex")


@dataclass
class Condition:
    table: Optional[str]
    column: Optional[str]
    op: str
    value: str


@dataclass
class ParsedQuery:
    conditions: list[Condition]
    logic: str
    structured: bool


_COND_RE = re.compile(
    r"^\s*([A-Za-z0-9_.]+)\s+"
    r"(contains|not_?contains|startswith|endswith|equals|regex|=|!=)\s+"
    r"(.+?)\s*$",
    re.IGNORECASE,
)


def parse_query(text: str) -> ParsedQuery:
    text = (text or "").strip()
    if not text:
        return ParsedQuery([], "and", False)

    parts, connectors = _split_on_logic(text)
    conditions = [_parse_condition(p) for p in parts]
    structured = len(conditions) > 1 or any(c.column for c in conditions)
    logic = connectors[0] if connectors else "and"
    return ParsedQuery(conditions, logic, structured)


def _split_on_logic(text: str) -> tuple[list[str], list[str]]:
    parts: list[str] = []
    connectors: list[str] = []
    buf: list[str] = []
    in_quote = None
    i, n = 0, len(text)

    while i < n:
        c = text[i]
        if in_quote:
            buf.append(c)
            if c == in_quote:
                in_quote = None
            i += 1
            continue
        if c in ('"', "'"):
            in_quote = c
            buf.append(c)
            i += 1
            continue

        matched_kw = None
        for kw in ("AND", "OR"):
            length = len(kw)
            if text[i:i + length].upper() == kw:
                before_ok = i == 0 or text[i - 1].isspace()
                after_ok = i + length == n or text[i + length].isspace()
                if before_ok and after_ok:
                    matched_kw = kw
                    break
        if matched_kw:
            parts.append("".join(buf).strip())
            connectors.append(matched_kw.lower())
            buf = []
            i += len(matched_kw)
            continue

        buf.append(c)
        i += 1

    parts.append("".join(buf).strip())
    return [p for p in parts if p], connectors


def _parse_condition(segment: str) -> Condition:
    m = _COND_RE.match(segment)
    if not m:
        return Condition(table=None, column=None, op="contains", value=_unquote(segment))

    field, op, value = m.groups()
    op = op.lower().replace("_", "")
    if op == "notcontains":
        op = "not_contains"
    elif op == "equals":
        op = "="
    value = _unquote(value.strip())

    if "." in field:
        table, column = field.split(".", 1)
    else:
        table, column = None, field

    return Condition(table=table or None, column=column or None, op=op, value=value)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def normalize_label(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def condition_sql(op: str, column: str, value: str) -> tuple[str, list]:
    quoted = f'"{column}"'
    if op == "contains":
        return f"{quoted} LIKE ?", [f"%{value}%"]
    if op == "not_contains":
        return f"{quoted} NOT LIKE ?", [f"%{value}%"]
    if op == "startswith":
        return f"{quoted} LIKE ?", [f"{value}%"]
    if op == "endswith":
        return f"{quoted} LIKE ?", [f"%{value}"]
    if op == "=":
        return f"{quoted} = ?", [value]
    if op == "!=":
        return f"{quoted} != ?", [value]
    if op == "regex":
        return f"{quoted} REGEXP ?", [value]
    return f"{quoted} LIKE ?", [f"%{value}%"]

"""
A triage config's paths get resolved by Triager as (root / value).resolve()
against wherever that machine's evidence was extracted on the server (see
triager.py's build_paths()). An uploaded config with a path like
"../../../../etc/passwd" or an absolute path would make Triager read and
copy in files from anywhere on disk it has permission to reach, not just
the intended evidence, since Triager itself does no sandboxing. Since a
web upload is fully untrusted input, this module is the boundary that
keeps every path in an uploaded config confined to the triage root before
it's ever handed to Triager.
"""
import re

import yaml

MAX_CONFIG_BYTES = 100_000
_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]|^[\\/]")


class ConfigValidationError(ValueError):
    pass


def validate_triage_config(raw_bytes: bytes) -> str:
    """Returns the decoded, validated YAML text, or raises ConfigValidationError."""
    if len(raw_bytes) > MAX_CONFIG_BYTES:
        raise ConfigValidationError(f"Config file is too large (max {MAX_CONFIG_BYTES // 1000} KB)")

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigValidationError("Config file must be UTF-8 text")

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as ex:
        raise ConfigValidationError(f"Invalid YAML: {ex}")

    if not isinstance(data, dict):
        raise ConfigValidationError("Config must be a YAML mapping (key: value pairs)")

    for key, value in data.items():
        if key == "root":
            continue  # always overwritten with the real extraction path at ingest time
        _check_value(value, str(key))

    return text


def _check_value(value, where: str) -> None:
    if isinstance(value, str):
        _check_path(value, where)
    elif isinstance(value, dict):
        for subkey, subval in value.items():
            _check_value(subval, f"{where}.{subkey}")


def _check_path(value: str, where: str) -> None:
    normalized = value.replace("/", "\\")
    parts = [p for p in normalized.split("\\") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ConfigValidationError(f"Path traversal ('..') isn't allowed in {where}: {value!r}")
    if _ABSOLUTE_RE.match(value):
        raise ConfigValidationError(
            f"Absolute paths aren't allowed in {where} (must be relative to the triage root): {value!r}"
        )

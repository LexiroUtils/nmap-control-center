from __future__ import annotations

import ipaddress
import re
from pathlib import Path

PORT_TOKEN_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_*-]{1,63}\.)*[a-zA-Z0-9_*-]{1,63}\.?$")
IP_RANGE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}-\d{1,3}(?:\.\d{1,3}){0,3}$")
TIME_RE = re.compile(r"^\d+(ms|s|m|h)?$")


class ValidationError(ValueError):
    pass


def validate_target(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValidationError("Target cannot be empty.")
    if value.lower() == "me":
        raise ValidationError("Use an explicit IP, hostname, range, or CIDR target.")
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
    if IP_RANGE_RE.match(value):
        return value
    if HOSTNAME_RE.match(value):
        return value
    raise ValidationError(f"Invalid target: {value}")


def validate_port_spec(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValidationError("Port expression cannot be empty.")
    for token in value.split(","):
        token = token.strip()
        if not PORT_TOKEN_RE.match(token):
            raise ValidationError(f"Invalid port token: {token}")
        parts = [int(part) for part in token.split("-")]
        if any(part < 0 or part > 65535 for part in parts):
            raise ValidationError("Ports must be between 0 and 65535.")
        if len(parts) == 2 and parts[0] > parts[1]:
            raise ValidationError(f"Invalid descending port range: {token}")
    return value


def validate_int_range(value: int, low: int, high: int, label: str) -> int:
    if value < low or value > high:
        raise ValidationError(f"{label} must be between {low} and {high}.")
    return value


def validate_time_value(value: str) -> str:
    value = value.strip()
    if not TIME_RE.match(value):
        raise ValidationError("Time values must look like 500ms, 30s, 5m, 1h, or a bare number.")
    return value


def validate_existing_file(value: str) -> str:
    path = Path(value).expanduser()
    if not path.exists() or not path.is_file():
        raise ValidationError(f"File does not exist: {value}")
    return str(path)


def safe_profile_name(value: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-")
    if not name:
        raise ValidationError("Profile name cannot be empty.")
    return name[:80]

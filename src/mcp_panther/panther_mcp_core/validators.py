"""
Shared validation functions for MCP tools.

This module provides reusable Pydantic validators that can be used across
multiple tool modules to ensure consistent parameter validation.
"""

import re
from datetime import datetime

# Alert IDs are opaque identifiers (e.g. "df1eb66cede030f1a6d29362ba437178").
_ALERT_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,255}")


def _validate_severities(v: list[str]) -> list[str]:
    """Validate severities are valid."""
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    for severity in v:
        if severity not in valid_severities:
            raise ValueError(
                f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(valid_severities))}"
            )
    return v


def _validate_statuses(v: list[str]) -> list[str]:
    """Validate alert statuses are valid."""
    valid_statuses = {"OPEN", "TRIAGED", "RESOLVED", "CLOSED"}
    for status in v:
        if status not in valid_statuses:
            raise ValueError(
                f"Invalid status '{status}'. Must be one of: {', '.join(sorted(valid_statuses))}"
            )
    return v


def _validate_alert_types(v: list[str]) -> list[str]:
    """Validate alert types are valid (for metrics)."""
    valid_types = {"Rule", "Policy"}
    for alert_type in v:
        if alert_type not in valid_types:
            raise ValueError(
                f"Invalid alert type '{alert_type}'. Must be one of: {', '.join(sorted(valid_types))}"
            )
    return v


def _validate_alert_api_types(v: str) -> str:
    """Validate alert API types are valid (for alerts API)."""
    valid_types = {"ALERT", "DETECTION_ERROR", "SYSTEM_ERROR"}
    if v not in valid_types:
        raise ValueError(
            f"Invalid alert_type '{v}'. Must be one of: {', '.join(sorted(valid_types))}"
        )
    return v


def _validate_subtypes(v: list[str]) -> list[str]:
    """Validate alert subtypes are valid."""
    valid_subtypes = {
        "POLICY",
        "RULE",
        "SCHEDULED_RULE",
        "RULE_ERROR",
        "SCHEDULED_RULE_ERROR",
    }
    for subtype in v:
        if subtype not in valid_subtypes:
            raise ValueError(
                f"Invalid subtype '{subtype}'. Must be one of: {', '.join(sorted(valid_subtypes))}"
            )
    return v


def _validate_interval(v: int) -> int:
    """Validate interval is one of the supported values."""
    valid_intervals = {15, 30, 60, 180, 360, 720, 1440}
    if v not in valid_intervals:
        raise ValueError(
            f"Invalid interval '{v}'. Must be one of: {', '.join(map(str, sorted(valid_intervals)))}"
        )
    return v


def _validate_rule_ids(v: list[str]) -> list[str]:
    """Validate rule IDs don't contain problematic characters."""
    problematic_chars = re.compile(r"[@\s#]")
    for rule_id in v:
        if problematic_chars.search(rule_id):
            raise ValueError(
                f"Invalid rule ID '{rule_id}'. Rule IDs cannot contain '@', spaces, or '#' characters"
            )
    return v


def _validate_alert_ids(v: list[str]) -> list[str]:
    """Validate alert IDs only contain opaque identifier characters.

    Alert IDs are interpolated into data lake SQL as string literals, so they must
    not be able to carry quotes, whitespace, or any other character that could alter
    the grammar of the surrounding query.
    """
    if isinstance(v, str) or not isinstance(v, (list, tuple)):
        raise ValueError("Alert IDs must be provided as a list of strings")

    validated = []
    for alert_id in v:
        if not isinstance(alert_id, str):
            raise ValueError(
                f"Alert ID must be a string, got {type(alert_id).__name__}"
            )
        if not _ALERT_ID_PATTERN.fullmatch(alert_id):
            # Truncate the echoed value: a rejected ID has no length bound, and the
            # message is returned to the caller's context.
            raise ValueError(
                f"Invalid alert ID '{alert_id[:64]}'. Alert IDs may only contain "
                "letters, digits, hyphens, and underscores (1-255 characters)"
            )
        validated.append(alert_id)
    return validated


def _validate_iso_date(v: str | None) -> str | None:
    """Validate that the date string is in valid ISO-8601 format."""
    if v is None:
        return v

    if not isinstance(v, str):
        raise ValueError(f"Date must be a string, got {type(v).__name__}")

    if not v.strip():
        raise ValueError("Date cannot be empty")

    # Try to parse the ISO-8601 date
    try:
        # This will validate the format and raise ValueError if invalid
        datetime.fromisoformat(v.replace("Z", "+00:00"))  # Handle 'Z' suffix
        return v
    except ValueError:
        raise ValueError(
            f"Invalid date format '{v}'. Must be in ISO-8601 format (e.g., '2024-03-20T00:00:00Z')"
        )


def _validate_alert_status(v: str) -> str:
    """Validate alert status is valid."""
    valid_statuses = {"OPEN", "TRIAGED", "RESOLVED", "CLOSED"}
    if v not in valid_statuses:
        raise ValueError(
            f"Invalid status '{v}'. Must be one of: {', '.join(sorted(valid_statuses))}"
        )
    return v

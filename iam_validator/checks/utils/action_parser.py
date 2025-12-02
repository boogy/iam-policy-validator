"""Action parsing utility for IAM policy validation.

This module provides a consistent way to parse AWS IAM action names
(format: service:ActionName) across all validation checks.
"""

from dataclasses import dataclass
from typing import TypeVar

# Type variable for generic dictionary value lookup
T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ParsedAction:
    """Represents a parsed AWS IAM action.

    Attributes:
        service: The AWS service prefix (e.g., "s3", "ec2", "iam")
        action_name: The action name (e.g., "GetObject", "DescribeInstances")
        has_wildcard: True if the service or action contains "*"
        original: The original action string as provided
    """

    service: str
    action_name: str
    has_wildcard: bool
    original: str


def parse_action(action: str) -> ParsedAction | None:
    """Parse an AWS IAM action string into its components.

    AWS IAM actions follow the format "service:ActionName" where:
    - service is the AWS service prefix (case-insensitive, typically lowercase)
    - ActionName is the specific API action (PascalCase or camelCase)

    Args:
        action: The action string to parse (e.g., "s3:GetObject", "ec2:*")

    Returns:
        ParsedAction if the action is valid, None if malformed.

    Examples:
        >>> parse_action("s3:GetObject")
        ParsedAction(service="s3", action_name="GetObject", has_wildcard=False, original="s3:GetObject")

        >>> parse_action("ec2:Describe*")
        ParsedAction(service="ec2", action_name="Describe*", has_wildcard=True, original="ec2:Describe*")

        >>> parse_action("InvalidAction")
        None

        >>> parse_action("*")
        None
    """
    # Handle full wildcard - not a parseable service:action
    if action == "*":
        return None

    # Must contain exactly one colon separating service and action
    if ":" not in action:
        return None

    # Split on first colon only (action names can theoretically contain colons)
    parts = action.split(":", 1)
    if len(parts) != 2:
        return None

    service, action_name = parts

    # Both service and action name must be non-empty
    if not service or not action_name:
        return None

    return ParsedAction(
        service=service,
        action_name=action_name,
        has_wildcard="*" in service or "*" in action_name,
        original=action,
    )


def is_wildcard_action(action: str) -> bool:
    """Check if an action contains a wildcard.

    Args:
        action: The action string to check

    Returns:
        True if the action is "*" or contains "*" in service or action name
    """
    if action == "*":
        return True

    parsed = parse_action(action)
    return parsed.has_wildcard if parsed else False


def extract_service(action: str) -> str | None:
    """Extract the service prefix from an action string.

    Args:
        action: The action string (e.g., "s3:GetObject")

    Returns:
        The service prefix (e.g., "s3") or None if the action is malformed
    """
    if action == "*":
        return None

    parsed = parse_action(action)
    return parsed.service if parsed else None


def get_action_case_insensitive(actions_dict: dict[str, T], action_name: str) -> T | None:
    """Look up an action in a dictionary using case-insensitive matching.

    AWS action names are case-insensitive, but our service definitions may have
    canonical casing. This function tries exact match first, then falls back
    to case-insensitive lookup.

    Args:
        actions_dict: Dictionary mapping action names to values (e.g., ActionDetail)
        action_name: The action name to look up

    Returns:
        The value if found, None otherwise

    Examples:
        >>> actions = {"GetObject": detail, "PutObject": detail2}
        >>> get_action_case_insensitive(actions, "GetObject")  # Exact match
        detail
        >>> get_action_case_insensitive(actions, "getobject")  # Case-insensitive
        detail
        >>> get_action_case_insensitive(actions, "Unknown")
        None
    """
    # Try exact match first (most common case)
    if action_name in actions_dict:
        return actions_dict[action_name]

    # Fall back to case-insensitive lookup
    action_name_lower = action_name.lower()
    for key, value in actions_dict.items():
        if key.lower() == action_name_lower:
            return value

    return None

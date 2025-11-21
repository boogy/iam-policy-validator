"""Query utilities for AWS service definitions.

This module provides utilities for querying AWS IAM service metadata including
actions, ARN formats, and condition keys. These utilities are inspired by and
compatible with policy_sentry's query functionality.

Example:
    Query actions for a service:
    >>> async with AWSServiceFetcher() as fetcher:
    ...     actions = await query_actions(fetcher, "s3")
    ...     write_actions = await query_actions(fetcher, "s3", access_level="write")
    ...
    Query ARN formats:
    >>> async with AWSServiceFetcher() as fetcher:
    ...     arns = await query_arn_formats(fetcher, "s3")
    ...     bucket_arn = await query_arn_format(fetcher, "s3", "bucket")
    ...
    Query condition keys:
    >>> async with AWSServiceFetcher() as fetcher:
    ...     keys = await query_condition_keys(fetcher, "s3")
    ...     prefix_key = await query_condition_key(fetcher, "s3", "s3:prefix")
"""

from typing import Any, Literal

from iam_validator.core.aws_service.fetcher import AWSServiceFetcher

AccessLevel = Literal["read", "write", "list", "tagging", "permissions-management"]


def _get_access_level(action_detail: Any) -> str:
    """Derive access level from action annotations.

    AWS API provides Properties dict with boolean flags instead of AccessLevel string.
    We derive the access level from these flags.

    Args:
        action_detail: Action detail object with annotations

    Returns:
        Access level string: "permissions-management", "tagging", "write", "list", or "read"
    """
    if not action_detail.annotations:
        return "Unknown"

    props = action_detail.annotations.get("Properties", {})
    if not props:
        return "Unknown"

    # Check flags in priority order
    if props.get("IsPermissionManagement"):
        return "permissions-management"
    if props.get("IsTaggingOnly"):
        return "tagging"
    if props.get("IsWrite"):
        return "write"
    if props.get("IsList"):
        return "list"

    # Default to read if none of the above
    return "read"


async def query_actions(
    fetcher: AWSServiceFetcher,
    service: str,
    access_level: AccessLevel | None = None,
    resource_type: str | None = None,
    condition: str | None = None,
) -> list[dict[str, Any]]:
    """Query IAM actions for a service with optional filtering.

    Args:
        fetcher: AWSServiceFetcher instance
        service: AWS service prefix (e.g., "s3", "iam", "ec2")
        access_level: Optional filter by access level
        resource_type: Optional filter by resource type. Use "*" for wildcard-only actions
        condition: Optional filter by condition key support

    Returns:
        List of action dictionaries with keys: action, access_level, description

    Example:
        >>> async with AWSServiceFetcher() as fetcher:
        ...     # Get all S3 actions
        ...     all_actions = await query_actions(fetcher, "s3")
        ...
        ...     # Get only write-level S3 actions
        ...     write_actions = await query_actions(fetcher, "s3", access_level="write")
        ...
        ...     # Get wildcard-only actions (no resource constraint)
        ...     wildcard_actions = await query_actions(fetcher, "iam", resource_type="*")
        ...
        ...     # Get actions supporting specific condition key
        ...     mfa_actions = await query_actions(fetcher, "iam", condition="aws:MultiFactorAuthPresent")
    """
    service_detail = await fetcher.fetch_service_by_name(service)

    filtered_actions = []
    for action_name, action_detail in service_detail.actions.items():
        access_lv = _get_access_level(action_detail)

        # Apply filters
        if access_level and access_lv.lower() != access_level.lower():
            continue

        if resource_type:
            resources = action_detail.resources or []

            # If filtering for wildcard-only actions (actions with no required resources)
            if resource_type == "*":
                # Actions with empty resources list are wildcard-only
                if resources:
                    continue
            else:
                # Filter by specific resource type name
                resource_names = [r.get("Name", "") for r in resources]
                if resource_type not in resource_names:
                    continue

        if condition:
            condition_keys = action_detail.action_condition_keys or []
            if condition not in condition_keys:
                continue

        description = (
            action_detail.annotations.get("Description", "N/A")
            if action_detail.annotations
            else "N/A"
        )

        filtered_actions.append(
            {
                "action": f"{service}:{action_name}",
                "access_level": access_lv,
                "description": description,
            }
        )

    return filtered_actions


async def query_action_details(
    fetcher: AWSServiceFetcher,
    service: str,
    action_name: str,
) -> dict[str, Any]:
    """Get detailed information about a specific action.

    Args:
        fetcher: AWSServiceFetcher instance
        service: AWS service prefix (e.g., "s3", "iam")
        action_name: Action name (e.g., "GetObject", "CreateUser")

    Returns:
        Dictionary with action details including resource types and condition keys

    Raises:
        ValueError: If action is not found

    Example:
        >>> async with AWSServiceFetcher() as fetcher:
        ...     details = await query_action_details(fetcher, "s3", "GetObject")
        ...     print(f"Access level: {details['access_level']}")
        ...     print(f"Resource types: {details['resource_types']}")
    """
    service_detail = await fetcher.fetch_service_by_name(service)

    # Try case-insensitive lookup
    action_detail = None
    for key, detail in service_detail.actions.items():
        if key.lower() == action_name.lower():
            action_detail = detail
            break

    if not action_detail:
        raise ValueError(f"Action '{action_name}' not found in service '{service}'")

    access_level = _get_access_level(action_detail)
    description = (
        action_detail.annotations.get("Description", "N/A") if action_detail.annotations else "N/A"
    )

    return {
        "service": service,
        "action": action_detail.name,
        "description": description,
        "access_level": access_level,
        "resource_types": [r.get("Name", "*") for r in (action_detail.resources or [])],
        "condition_keys": action_detail.action_condition_keys or [],
    }


async def query_arn_formats(
    fetcher: AWSServiceFetcher,
    service: str,
) -> list[str]:
    """Query all ARN formats for a service.

    Args:
        fetcher: AWSServiceFetcher instance
        service: AWS service prefix (e.g., "s3", "iam")

    Returns:
        List of unique ARN format strings

    Example:
        >>> async with AWSServiceFetcher() as fetcher:
        ...     arns = await query_arn_formats(fetcher, "s3")
        ...     for arn in arns:
        ...         print(arn)
    """
    service_detail = await fetcher.fetch_service_by_name(service)

    all_arns = []
    for resource_type in service_detail.resources.values():
        if resource_type.arn_formats:
            all_arns.extend(resource_type.arn_formats)

    return list(set(all_arns))  # Remove duplicates


async def query_arn_types(
    fetcher: AWSServiceFetcher,
    service: str,
) -> list[dict[str, Any]]:
    """Query all ARN resource types with their formats.

    Args:
        fetcher: AWSServiceFetcher instance
        service: AWS service prefix (e.g., "s3", "iam")

    Returns:
        List of dictionaries with resource_type and arn_formats keys

    Example:
        >>> async with AWSServiceFetcher() as fetcher:
        ...     types = await query_arn_types(fetcher, "s3")
        ...     for rt in types:
        ...         print(f"{rt['resource_type']}: {rt['arn_formats']}")
    """
    service_detail = await fetcher.fetch_service_by_name(service)

    return [
        {
            "resource_type": rt.name,
            "arn_formats": rt.arn_formats or [],
        }
        for rt in service_detail.resources.values()
    ]


async def query_arn_format(
    fetcher: AWSServiceFetcher,
    service: str,
    resource_type_name: str,
) -> dict[str, Any]:
    """Get ARN format details for a specific resource type.

    Args:
        fetcher: AWSServiceFetcher instance
        service: AWS service prefix (e.g., "s3", "iam")
        resource_type_name: Resource type name (e.g., "bucket", "role")

    Returns:
        Dictionary with resource type details including ARN formats and condition keys

    Raises:
        ValueError: If resource type is not found

    Example:
        >>> async with AWSServiceFetcher() as fetcher:
        ...     details = await query_arn_format(fetcher, "s3", "bucket")
        ...     print(f"ARN formats: {details['arn_formats']}")
    """
    service_detail = await fetcher.fetch_service_by_name(service)

    resource_type = None
    for key, rt in service_detail.resources.items():
        if key.lower() == resource_type_name.lower():
            resource_type = rt
            break

    if not resource_type:
        raise ValueError(
            f"ARN resource type '{resource_type_name}' not found in service '{service}'"
        )

    return {
        "service": service,
        "resource_type": resource_type.name,
        "arn_formats": resource_type.arn_formats or [],
        "condition_keys": resource_type.condition_keys or [],
    }


async def query_condition_keys(
    fetcher: AWSServiceFetcher,
    service: str,
) -> list[dict[str, Any]]:
    """Query all condition keys for a service.

    Args:
        fetcher: AWSServiceFetcher instance
        service: AWS service prefix (e.g., "s3", "iam")

    Returns:
        List of dictionaries with condition_key, description, and types keys

    Example:
        >>> async with AWSServiceFetcher() as fetcher:
        ...     keys = await query_condition_keys(fetcher, "s3")
        ...     for key in keys:
        ...         print(f"{key['condition_key']}: {key['description']}")
    """
    service_detail = await fetcher.fetch_service_by_name(service)

    return [
        {
            "condition_key": ck.name,
            "description": ck.description or "N/A",
            "types": ck.types or [],
        }
        for ck in service_detail.condition_keys.values()
    ]


async def query_condition_key(
    fetcher: AWSServiceFetcher,
    service: str,
    condition_key_name: str,
) -> dict[str, Any]:
    """Get details for a specific condition key.

    Args:
        fetcher: AWSServiceFetcher instance
        service: AWS service prefix (e.g., "s3", "iam")
        condition_key_name: Condition key name (e.g., "s3:prefix", "iam:PolicyArn")

    Returns:
        Dictionary with condition key details

    Raises:
        ValueError: If condition key is not found

    Example:
        >>> async with AWSServiceFetcher() as fetcher:
        ...     details = await query_condition_key(fetcher, "s3", "s3:prefix")
        ...     print(f"Types: {details['types']}")
    """
    service_detail = await fetcher.fetch_service_by_name(service)

    condition_key = None
    for key, ck in service_detail.condition_keys.items():
        if key.lower() == condition_key_name.lower():
            condition_key = ck
            break

    if not condition_key:
        raise ValueError(f"Condition key '{condition_key_name}' not found in service '{service}'")

    return {
        "service": service,
        "condition_key": condition_key.name,
        "description": condition_key.description or "N/A",
        "types": condition_key.types or [],
    }


async def get_actions_by_access_level(
    fetcher: AWSServiceFetcher,
    service: str,
    access_level: AccessLevel,
) -> list[str]:
    """Get action names filtered by access level.

    Convenience function that returns just the action names (not full details).

    Args:
        fetcher: AWSServiceFetcher instance
        service: AWS service prefix
        access_level: Access level to filter by

    Returns:
        List of action names (with service prefix)

    Example:
        >>> async with AWSServiceFetcher() as fetcher:
        ...     write_actions = await get_actions_by_access_level(fetcher, "s3", "write")
        ...     print(f"Found {len(write_actions)} write actions")
    """
    actions = await query_actions(fetcher, service, access_level=access_level)
    return [action["action"] for action in actions]


async def get_wildcard_only_actions(
    fetcher: AWSServiceFetcher,
    service: str,
) -> list[str]:
    """Get actions that only support wildcard resources (no specific resource types).

    Args:
        fetcher: AWSServiceFetcher instance
        service: AWS service prefix

    Returns:
        List of action names that don't require specific resource ARNs

    Example:
        >>> async with AWSServiceFetcher() as fetcher:
        ...     wildcard_actions = await get_wildcard_only_actions(fetcher, "iam")
        ...     print(f"IAM has {len(wildcard_actions)} wildcard-only actions")
    """
    actions = await query_actions(fetcher, service, resource_type="*")
    return [action["action"] for action in actions]


async def get_actions_supporting_condition(
    fetcher: AWSServiceFetcher,
    service: str,
    condition_key: str,
) -> list[str]:
    """Get actions that support a specific condition key.

    Args:
        fetcher: AWSServiceFetcher instance
        service: AWS service prefix
        condition_key: Condition key to search for

    Returns:
        List of action names that support the condition key

    Example:
        >>> async with AWSServiceFetcher() as fetcher:
        ...     mfa_actions = await get_actions_supporting_condition(
        ...         fetcher, "iam", "aws:MultiFactorAuthPresent"
        ...     )
    """
    actions = await query_actions(fetcher, service, condition=condition_key)
    return [action["action"] for action in actions]


__all__ = [
    "query_actions",
    "query_action_details",
    "query_arn_formats",
    "query_arn_types",
    "query_arn_format",
    "query_condition_keys",
    "query_condition_key",
    "get_actions_by_access_level",
    "get_wildcard_only_actions",
    "get_actions_supporting_condition",
]

"""
Utilities for working with IAM policies.

This module provides functions for parsing, manipulating, and inspecting
IAM policy documents programmatically.
"""

import json
from typing import Any

from iam_validator.core.models import IAMPolicy, Statement


def parse_policy(policy: str | dict) -> IAMPolicy:
    """
    Parse a policy from JSON string or dict.

    Args:
        policy: IAM policy as JSON string or Python dict

    Returns:
        Parsed IAMPolicy object

    Raises:
        ValueError: If policy is invalid JSON or missing required fields

    Example:
        >>> policy_str = '{"Version": "2012-10-17", "Statement": [...]}'
        >>> policy = parse_policy(policy_str)
        >>> print(f"Version: {policy.version}")
    """
    if isinstance(policy, str):
        try:
            policy_dict = json.loads(policy)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}") from e
    else:
        policy_dict = policy

    try:
        return IAMPolicy(**policy_dict)
    except Exception as e:
        raise ValueError(f"Invalid IAM policy format: {e}") from e


def normalize_policy(policy: IAMPolicy) -> IAMPolicy:
    """
    Normalize policy format (ensure statements are in list format).

    AWS allows Statement to be a single object or an array. This function
    ensures it's always an array for consistent processing.

    Args:
        policy: IAMPolicy to normalize

    Returns:
        Normalized IAMPolicy with Statement as list

    Example:
        >>> policy = parse_policy(policy_json)
        >>> normalized = normalize_policy(policy)
        >>> assert isinstance(normalized.statement, list)
    """
    # Pydantic model already handles this via Field(alias="Statement")
    # which expects a list, but we can ensure it's always a list
    if policy.statement is None:
        statements: list[Statement] = []
    elif isinstance(policy.statement, list):
        statements = policy.statement
    else:
        # Single statement - wrap in list
        statements = [policy.statement]

    # Normalize actions and resources in each statement
    normalized_statements: list[Statement] = []
    for stmt in statements:
        action = [stmt.action] if isinstance(stmt.action, str) else stmt.action
        resource = [stmt.resource] if isinstance(stmt.resource, str) else stmt.resource
        not_action = [stmt.not_action] if isinstance(stmt.not_action, str) else stmt.not_action
        not_resource = (
            [stmt.not_resource] if isinstance(stmt.not_resource, str) else stmt.not_resource
        )

        # Create a new statement with normalized fields
        # Use capitalized field names (aliases) for Pydantic model construction
        normalized_stmt = Statement(
            Sid=stmt.sid,
            Effect=stmt.effect,
            Action=action,
            NotAction=not_action,
            Resource=resource,
            NotResource=not_resource,
            Condition=stmt.condition,
            Principal=stmt.principal,
            NotPrincipal=stmt.not_principal,
        )
        normalized_statements.append(normalized_stmt)

    # Return a new policy with normalized statements
    # Use capitalized field names (aliases) for Pydantic model construction
    return IAMPolicy(
        Version=policy.version,
        Statement=normalized_statements,
        Id=policy.id,
    )


def extract_actions(policy: IAMPolicy) -> list[str]:
    """
    Extract all actions from a policy.

    Args:
        policy: IAMPolicy to extract actions from

    Returns:
        List of all unique actions in the policy

    Example:
        >>> policy = parse_policy(policy_json)
        >>> actions = extract_actions(policy)
        >>> print(f"Policy uses {len(actions)} actions")
    """
    actions = set()

    if policy.statement is None:
        return []

    for stmt in policy.statement:
        # Handle Action field
        if stmt.action:
            stmt_actions = [stmt.action] if isinstance(stmt.action, str) else stmt.action
            actions.update(stmt_actions)

        # Handle NotAction field
        if stmt.not_action:
            not_actions = [stmt.not_action] if isinstance(stmt.not_action, str) else stmt.not_action
            actions.update(not_actions)

    return sorted(actions)


def extract_resources(policy: IAMPolicy) -> list[str]:
    """
    Extract all resources from a policy.

    Args:
        policy: IAMPolicy to extract resources from

    Returns:
        List of all unique resources in the policy

    Example:
        >>> policy = parse_policy(policy_json)
        >>> resources = extract_resources(policy)
        >>> for arn in resources:
        ...     print(f"Resource: {arn}")
    """
    resources = set()

    if policy.statement is None:
        return []

    for stmt in policy.statement:
        # Handle Resource field
        if stmt.resource:
            stmt_resources = [stmt.resource] if isinstance(stmt.resource, str) else stmt.resource
            resources.update(stmt_resources)

        # Handle NotResource field
        if stmt.not_resource:
            not_resources = (
                [stmt.not_resource] if isinstance(stmt.not_resource, str) else stmt.not_resource
            )
            resources.update(not_resources)

    return sorted(resources)


def extract_condition_keys_from_statement(statement: Statement) -> set[str]:
    """
    Extract all condition keys from a single statement.

    Args:
        statement: Statement to extract condition keys from

    Returns:
        Set of condition key names (e.g., {"aws:ResourceAccount", "aws:SourceIp"})

    Example:
        >>> stmt = Statement(
        ...     Effect="Allow",
        ...     Action=["s3:GetObject"],
        ...     Resource=["*"],
        ...     Condition={"StringEquals": {"aws:ResourceAccount": "123456789012"}}
        ... )
        >>> keys = extract_condition_keys_from_statement(stmt)
        >>> print(keys)  # {"aws:ResourceAccount"}
    """
    if not statement.condition:
        return set()

    keys: set[str] = set()
    for operator_block in statement.condition.values():
        if isinstance(operator_block, dict):
            keys.update(operator_block.keys())
    return keys


def extract_condition_keys(policy: IAMPolicy) -> list[str]:
    """
    Extract all condition keys used in a policy.

    Args:
        policy: IAMPolicy to extract condition keys from

    Returns:
        List of all unique condition keys in the policy

    Example:
        >>> policy = parse_policy(policy_json)
        >>> keys = extract_condition_keys(policy)
        >>> print(f"Policy uses condition keys: {', '.join(keys)}")
    """
    condition_keys: set[str] = set()

    if policy.statement is None:
        return []

    for stmt in policy.statement:
        condition_keys.update(extract_condition_keys_from_statement(stmt))

    return sorted(condition_keys)


def find_statements_with_action(policy: IAMPolicy, action: str) -> list[Statement]:
    """
    Find all statements containing a specific action.

    Supports exact match and wildcard patterns.

    Args:
        policy: IAMPolicy to search
        action: Action to search for (e.g., "s3:GetObject" or "s3:*")

    Returns:
        List of Statement objects containing the action

    Example:
        >>> policy = parse_policy(policy_json)
        >>> stmts = find_statements_with_action(policy, "s3:GetObject")
        >>> for stmt in stmts:
        ...     print(f"Statement {stmt.sid} allows s3:GetObject")
    """
    import fnmatch  # pylint: disable=import-outside-toplevel

    matching_statements = []

    if policy.statement is None:
        return []

    for stmt in policy.statement:
        stmt_actions = stmt.get_actions()

        # Check if action matches any statement action (with wildcard support)
        for stmt_action in stmt_actions:
            if fnmatch.fnmatch(action, stmt_action) or fnmatch.fnmatch(stmt_action, action):
                matching_statements.append(stmt)
                break

    return matching_statements


def find_statements_with_resource(policy: IAMPolicy, resource: str) -> list[Statement]:
    """
    Find all statements containing a specific resource.

    Supports exact match and wildcard patterns.

    Args:
        policy: IAMPolicy to search
        resource: Resource ARN to search for

    Returns:
        List of Statement objects containing the resource

    Example:
        >>> policy = parse_policy(policy_json)
        >>> stmts = find_statements_with_resource(policy, "arn:aws:s3:::my-bucket/*")
        >>> print(f"Found {len(stmts)} statements with this resource")
    """
    import fnmatch  # pylint: disable=import-outside-toplevel

    matching_statements = []

    if policy.statement is None:
        return []

    for stmt in policy.statement:
        stmt_resources = stmt.get_resources()

        # Check if resource matches any statement resource (with wildcard support)
        for stmt_resource in stmt_resources:
            if fnmatch.fnmatch(resource, stmt_resource) or fnmatch.fnmatch(stmt_resource, resource):
                matching_statements.append(stmt)
                break

    return matching_statements


def merge_policies(*policies: IAMPolicy) -> IAMPolicy:
    """
    Merge multiple policies into one.

    Combines all statements from multiple policies into a single policy document.
    Uses the version from the first policy.

    Args:
        *policies: IAMPolicy objects to merge

    Returns:
        New IAMPolicy with all statements combined

    Example:
        >>> policy1 = parse_policy(json1)
        >>> policy2 = parse_policy(json2)
        >>> merged = merge_policies(policy1, policy2)
        >>> print(f"Merged policy has {len(merged.statement)} statements")
    """
    if not policies:
        raise ValueError("At least one policy must be provided")

    all_statements: list[Statement] = []
    for policy in policies:
        if policy.statement is not None:
            all_statements.extend(policy.statement)

    # Use capitalized field names (aliases) for Pydantic model construction
    return IAMPolicy(
        Version=policies[0].version,
        Statement=all_statements,
        Id=None,  # Clear ID when merging
    )


def get_policy_summary(policy: IAMPolicy) -> dict[str, Any]:
    """
    Get a summary of policy contents.

    Args:
        policy: IAMPolicy to summarize

    Returns:
        Dictionary with summary statistics

    Example:
        >>> policy = parse_policy(policy_json)
        >>> summary = get_policy_summary(policy)
        >>> print(f"Statements: {summary['statement_count']}")
        >>> print(f"Actions: {summary['action_count']}")
        >>> print(f"Resources: {summary['resource_count']}")
    """
    actions = extract_actions(policy)
    resources = extract_resources(policy)
    condition_keys = extract_condition_keys(policy)

    # Count allow vs deny statements
    statements = policy.statement or []
    allow_count = sum(1 for s in statements if s.effect and s.effect.lower() == "allow")
    deny_count = sum(1 for s in statements if s.effect and s.effect.lower() == "deny")

    # Check for wildcards
    has_wildcard_actions = any("*" in action for action in actions)
    has_wildcard_resources = any("*" in resource for resource in resources)

    return {
        "version": policy.version,
        "statement_count": len(statements),
        "allow_statements": allow_count,
        "deny_statements": deny_count,
        "action_count": len(actions),
        "resource_count": len(resources),
        "condition_key_count": len(condition_keys),
        "has_wildcard_actions": has_wildcard_actions,
        "has_wildcard_resources": has_wildcard_resources,
        "actions": actions,
        "resources": resources,
        "condition_keys": condition_keys,
    }


def policy_to_json(policy: IAMPolicy, indent: int = 2) -> str:
    """
    Convert IAMPolicy to formatted JSON string.

    Args:
        policy: IAMPolicy to convert
        indent: Number of spaces for indentation (default: 2)

    Returns:
        Formatted JSON string

    Example:
        >>> policy = parse_policy(policy_dict)
        >>> json_str = policy_to_json(policy)
        >>> print(json_str)
    """
    policy_dict = policy.model_dump(by_alias=True, exclude_none=True)
    return json.dumps(policy_dict, indent=indent)


def policy_to_dict(policy: IAMPolicy) -> dict[str, Any]:
    """
    Convert IAMPolicy to Python dictionary.

    Args:
        policy: IAMPolicy to convert

    Returns:
        Policy as Python dict with AWS field names (Version, Statement, etc.)

    Example:
        >>> policy = parse_policy(policy_json)
        >>> policy_dict = policy_to_dict(policy)
        >>> print(policy_dict["Version"])
    """
    return policy.model_dump(by_alias=True, exclude_none=True)


def is_resource_policy(policy: IAMPolicy) -> bool:
    """
    Check if policy appears to be a resource policy (vs identity policy).

    Resource policies have a Principal field, identity policies don't.

    Args:
        policy: IAMPolicy to check

    Returns:
        True if policy appears to be a resource policy

    Example:
        >>> policy = parse_policy(bucket_policy_json)
        >>> if is_resource_policy(policy):
        ...     print("This is an S3 bucket policy or similar")
    """
    if policy.statement is None:
        return False
    return any(stmt.principal is not None for stmt in policy.statement)


def has_public_access(policy: IAMPolicy) -> bool:
    """
    Check if policy grants public access (Principal: "*").

    Args:
        policy: IAMPolicy to check

    Returns:
        True if any statement has Principal set to "*"

    Example:
        >>> policy = parse_policy(policy_json)
        >>> if has_public_access(policy):
        ...     print("WARNING: This policy allows public access!")
    """
    if policy.statement is None:
        return False

    for stmt in policy.statement:
        if stmt.principal == "*":
            return True
        if isinstance(stmt.principal, dict):
            # Check for {"AWS": "*"} or {"Service": "*"}
            for value in stmt.principal.values():
                if value == "*" or (isinstance(value, list) and "*" in value):
                    return True
    return False

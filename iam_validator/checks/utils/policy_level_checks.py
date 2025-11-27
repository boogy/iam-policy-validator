"""Policy-level privilege escalation detection for IAM policy checks.

This module provides functionality to detect privilege escalation patterns
that span multiple statements in a policy.
"""

import re

from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import ValidationIssue


def check_policy_level_actions(
    all_actions: list[str],
    statement_map: dict[str, list[tuple[int, str | None]]],
    config,
    check_config: CheckConfig,
    check_type: str,
    get_severity_func,
) -> list[ValidationIssue]:
    """
    Check for policy-level privilege escalation patterns.

    This function detects when a policy grants a dangerous combination of
    permissions across multiple statements (e.g., iam:CreateUser + iam:AttachUserPolicy).

    Args:
        all_actions: All actions across the entire policy
        statement_map: Mapping of action -> [(statement_idx, sid), ...]
        config: The sensitive_actions or sensitive_action_patterns configuration
        check_config: Full check configuration
        check_type: Either "actions" (exact match) or "patterns" (regex match)
        get_severity_func: Function to get severity for the check

    Returns:
        List of ValidationIssue objects
    """
    issues = []

    if not config:
        return issues

    # Handle list of items (could be simple strings or dicts with all_of/any_of)
    if isinstance(config, list):
        for item in config:
            if isinstance(item, dict) and "all_of" in item:
                # This is a privilege escalation pattern - all actions must be present
                issue = _check_all_of_pattern(
                    all_actions,
                    statement_map,
                    item["all_of"],
                    item,  # Pass the entire item config (includes severity, message, suggestion)
                    check_config,
                    check_type,
                    get_severity_func,
                )
                if issue:
                    issues.append(issue)

    # Handle dict with all_of at the top level
    elif isinstance(config, dict) and "all_of" in config:
        issue = _check_all_of_pattern(
            all_actions,
            statement_map,
            config["all_of"],
            config,  # Pass the entire config dict (includes severity, message, suggestion)
            check_config,
            check_type,
            get_severity_func,
        )
        if issue:
            issues.append(issue)

    return issues


def _check_all_of_pattern(
    all_actions: list[str],
    statement_map: dict[str, list[tuple[int, str | None]]],
    required_actions: list[str],
    item_config: dict,
    check_config: CheckConfig,
    check_type: str,
    get_severity_func,
) -> ValidationIssue | None:
    """
    Check if all required actions/patterns are present in the policy.

    Args:
        all_actions: All actions across the entire policy
        statement_map: Mapping of action -> [(statement_idx, sid), ...]
        required_actions: List of required actions or patterns
        item_config: Configuration for this specific pattern (includes severity, message, suggestion)
        check_config: Full check configuration
        check_type: Either "actions" (exact match) or "patterns" (regex match)
        get_severity_func: Function to get severity for the check

    Returns:
        ValidationIssue if privilege escalation detected, None otherwise
    """
    # Filter out actions that match ignore_patterns BEFORE checking for privilege escalation
    # This allows users to exclude specific actions from privilege escalation detection
    # by adding them to ignore_patterns in sensitive_action config
    filtered_actions = check_config.filter_actions(frozenset(all_actions))
    all_actions_filtered = list(filtered_actions)

    matched_actions = []

    if check_type == "actions":
        # Exact matching
        matched_actions = [a for a in all_actions_filtered if a in required_actions]
    else:
        # Pattern matching - for each pattern, find actions that match
        for pattern in required_actions:
            for action in all_actions_filtered:
                try:
                    if re.match(pattern, action):
                        matched_actions.append(action)
                        break  # Found at least one match for this pattern
                except re.error:
                    continue

    # Check if ALL required actions/patterns are present
    if len(matched_actions) >= len(required_actions):
        # Privilege escalation detected!
        # Use severity from item_config if available, otherwise use default from check
        severity = item_config.get("severity") or get_severity_func(check_config)

        # Collect which statements these actions appear in
        statement_refs = []
        action_to_statements = {}  # Map action -> list of statement references

        for action in matched_actions:
            action_to_statements[action] = []
            if action in statement_map:
                for stmt_idx, sid in statement_map[action]:
                    # Use index notation instead of # to avoid GitHub PR link interpretation
                    sid_str = f"'{sid}'" if sid else f"[{stmt_idx}]"
                    statement_refs.append(f"Statement {sid_str}: {action}")
                    action_to_statements[action].append(f"Statement {sid_str}")

        # Format actions with backticks and statement references
        action_list = "`, `".join(matched_actions)
        stmt_details = "\n  - ".join(statement_refs)

        # Build a compact statement summary for the message
        action_stmt_summary = []
        for action in matched_actions:
            stmts = action_to_statements.get(action, [])
            if stmts:
                action_stmt_summary.append(f"`{action}` in {', '.join(stmts)}")

        stmt_summary = "; ".join(action_stmt_summary)

        # Use custom message if provided in item_config, otherwise use default
        # Support {actions} and {statements} placeholders in custom messages
        message_template = item_config.get(
            "message",
            f"Policy grants [`{action_list}`] across statements - enables privilege escalation. Found: {stmt_summary}",
        )
        # Replace placeholders if present in custom message
        message = message_template.replace("{actions}", f"`{action_list}`").replace(
            "{statements}", stmt_summary
        )

        # Use custom suggestion if provided in item_config, otherwise use default
        suggestion = item_config.get(
            "suggestion",
            f"These actions combined allow privilege escalation. Consider:\n"
            f"  1. Splitting into separate policies for different users/roles\n"
            f"  2. Adding strict conditions to limit when these actions can be used together\n"
            f"  3. Reviewing if all these permissions are truly necessary\n\n"
            f"Actions found in:\n  - {stmt_details}",
        )

        # Use custom example if provided in item_config
        example = item_config.get("example")

        return ValidationIssue(
            severity=severity,
            statement_sid=None,  # Policy-level issue
            statement_index=-1,  # -1 indicates policy-level issue
            issue_type="privilege_escalation",
            message=message,
            suggestion=suggestion,
            example=example,
            line_number=1,  # Policy-level issues point to line 1 (top of policy)
        )

    return None

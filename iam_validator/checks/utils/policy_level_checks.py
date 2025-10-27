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
        check_config: Full check configuration
        check_type: Either "actions" (exact match) or "patterns" (regex match)
        get_severity_func: Function to get severity for the check

    Returns:
        ValidationIssue if privilege escalation detected, None otherwise
    """
    matched_actions = []

    if check_type == "actions":
        # Exact matching
        matched_actions = [a for a in all_actions if a in required_actions]
    else:
        # Pattern matching - for each pattern, find actions that match
        for pattern in required_actions:
            for action in all_actions:
                try:
                    if re.match(pattern, action):
                        matched_actions.append(action)
                        break  # Found at least one match for this pattern
                except re.error:
                    continue

    # Check if ALL required actions/patterns are present
    if len(matched_actions) >= len(required_actions):
        # Privilege escalation detected!
        severity = get_severity_func(check_config, "sensitive_action_check", "error")

        # Collect which statements these actions appear in
        statement_refs = []
        for action in matched_actions:
            if action in statement_map:
                for stmt_idx, sid in statement_map[action]:
                    sid_str = f"'{sid}'" if sid else f"#{stmt_idx}"
                    statement_refs.append(f"Statement {sid_str}: {action}")

        action_list = "', '".join(matched_actions)
        stmt_details = "\n  - ".join(statement_refs)

        return ValidationIssue(
            severity=severity,
            statement_sid=None,  # Policy-level issue
            statement_index=-1,  # -1 indicates policy-level issue
            issue_type="privilege_escalation",
            message=f"Policy-level privilege escalation detected: grants all of ['{action_list}'] across multiple statements",
            suggestion=f"These actions combined allow privilege escalation. Consider:\n"
            f"  1. Splitting into separate policies for different users/roles\n"
            f"  2. Adding strict conditions to limit when these actions can be used together\n"
            f"  3. Reviewing if all these permissions are truly necessary\n\n"
            f"Actions found in:\n  - {stmt_details}",
            line_number=None,
        )

    return None

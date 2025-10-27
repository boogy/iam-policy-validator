"""Sensitive action matching utilities for IAM policy checks.

This module provides functionality to match actions against sensitive action
configurations, supporting exact matches, regex patterns, and any_of/all_of logic.
"""

import re
from functools import lru_cache
from re import Pattern

from iam_validator.core.check_registry import CheckConfig

# Default set of sensitive actions for backward compatibility
# Using frozenset for O(1) lookups and immutability
DEFAULT_SENSITIVE_ACTIONS = frozenset(
    {
        "ec2:DeleteVolume",
        "ec2:TerminateInstances",
        "eks:DeleteCluster",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey",
        "iam:CreateRole",
        "iam:CreateUser",
        "iam:DeleteRole",
        "iam:DeleteUser",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy",
        "lambda:DeleteFunction",
        "rds:DeleteDBInstance",
        "s3:DeleteBucket",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketPolicy",
    }
)


# Global regex pattern cache for performance
@lru_cache(maxsize=256)
def compile_pattern(pattern: str) -> Pattern[str] | None:
    """Compile and cache regex patterns.

    Args:
        pattern: Regex pattern string

    Returns:
        Compiled pattern or None if invalid
    """
    try:
        return re.compile(pattern)
    except re.error:
        return None


def check_sensitive_actions(
    actions: list[str], config: CheckConfig, default_actions: frozenset[str] | None = None
) -> tuple[bool, list[str]]:
    """
    Check if actions match sensitive action criteria with any_of/all_of support.

    Args:
        actions: List of actions to check
        config: Check configuration
        default_actions: Default sensitive actions to use if no config (defaults to DEFAULT_SENSITIVE_ACTIONS)

    Returns:
        tuple[bool, list[str]]: (is_sensitive, matched_actions)
            - is_sensitive: True if the actions match the sensitive criteria
            - matched_actions: List of actions that matched the criteria
    """
    if default_actions is None:
        default_actions = DEFAULT_SENSITIVE_ACTIONS

    # Filter out wildcards
    filtered_actions = [a for a in actions if a != "*"]
    if not filtered_actions:
        return False, []

    # Get configuration for both sensitive_actions and sensitive_action_patterns
    sub_check_config = config.config.get("sensitive_action_check", {})
    if not isinstance(sub_check_config, dict):
        return False, []

    sensitive_actions_config = sub_check_config.get("sensitive_actions")
    sensitive_patterns_config = sub_check_config.get("sensitive_action_patterns")

    # Check sensitive_actions (exact matches)
    actions_match, actions_matched = check_actions_config(
        filtered_actions, sensitive_actions_config, default_actions
    )

    # Check sensitive_action_patterns (regex patterns)
    patterns_match, patterns_matched = check_patterns_config(
        filtered_actions, sensitive_patterns_config
    )

    # Combine results - if either matched, we consider it sensitive
    is_sensitive = actions_match or patterns_match
    # Use set operations for efficient deduplication
    matched_set = set(actions_matched) | set(patterns_matched)
    matched_actions = list(matched_set)

    return is_sensitive, matched_actions


def check_actions_config(
    actions: list[str], config, default_actions: frozenset[str]
) -> tuple[bool, list[str]]:
    """
    Check actions against sensitive_actions configuration.

    Supports:
    - Simple list: ["action1", "action2"] (backward compatible, any_of logic)
    - any_of: {"any_of": ["action1", "action2"]}
    - all_of: {"all_of": ["action1", "action2"]}
    - Multiple groups: [{"all_of": [...]}, {"all_of": [...]}, "action3"]

    Args:
        actions: List of actions to check
        config: Sensitive actions configuration
        default_actions: Default sensitive actions to use if no config

    Returns:
        tuple[bool, list[str]]: (matches, matched_actions)
    """
    if not config:
        # If no config, fall back to defaults with any_of logic
        # default_actions is already a frozenset for O(1) lookups
        matched = [a for a in actions if a in default_actions]
        return len(matched) > 0, matched

    # Handle simple list with potential mixed items
    if isinstance(config, list):
        # Use set for O(1) membership checks
        all_matched = set()
        actions_set = set(actions)  # Convert once for O(1) lookups

        for item in config:
            # Each item can be a string, or a dict with any_of/all_of
            if isinstance(item, str):
                # Simple string - check if action matches (O(1) lookup)
                if item in actions_set:
                    all_matched.add(item)
            elif isinstance(item, dict):
                # Recurse for dict items
                matches, matched = check_actions_config(actions, item, default_actions)
                if matches:
                    all_matched.update(matched)

        return len(all_matched) > 0, list(all_matched)

    # Handle dict with any_of/all_of
    if isinstance(config, dict):
        # any_of: at least one action must match
        if "any_of" in config:
            # Convert once for O(1) intersection
            any_of_set = set(config["any_of"])
            actions_set = set(actions)
            matched = list(any_of_set & actions_set)
            return len(matched) > 0, matched

        # all_of: all specified actions must be present in the statement
        if "all_of" in config:
            all_of_set = set(config["all_of"])
            actions_set = set(actions)
            matched = list(all_of_set & actions_set)
            # All required actions must be present
            return all_of_set.issubset(actions_set), matched

    return False, []


def check_patterns_config(actions: list[str], config) -> tuple[bool, list[str]]:
    """
    Check actions against sensitive_action_patterns configuration.

    Supports:
    - Simple list: ["^pattern1.*", "^pattern2.*"] (backward compatible, any_of logic)
    - any_of: {"any_of": ["^pattern1.*", "^pattern2.*"]}
    - all_of: {"all_of": ["^pattern1.*", "^pattern2.*"]}
    - Multiple groups: [{"all_of": [...]}, {"any_of": [...]}, "^pattern.*"]

    Args:
        actions: List of actions to check
        config: Sensitive action patterns configuration

    Returns:
        tuple[bool, list[str]]: (matches, matched_actions)

    Performance:
        Uses cached compiled regex patterns for 10-50x speedup
    """
    if not config:
        return False, []

    # Handle simple list with potential mixed items
    if isinstance(config, list):
        # Use set for O(1) membership checks instead of list
        all_matched = set()

        for item in config:
            # Each item can be a string pattern, or a dict with any_of/all_of
            if isinstance(item, str):
                # Simple string pattern - check if any action matches
                # Use cached compiled pattern
                compiled = compile_pattern(item)
                if compiled:
                    for action in actions:
                        if compiled.match(action):
                            all_matched.add(action)
            elif isinstance(item, dict):
                # Recurse for dict items
                matches, matched = check_patterns_config(actions, item)
                if matches:
                    all_matched.update(matched)

        return len(all_matched) > 0, list(all_matched)

    # Handle dict with any_of/all_of
    if isinstance(config, dict):
        # any_of: at least one action must match at least one pattern
        if "any_of" in config:
            matched = set()
            # Pre-compile all patterns
            compiled_patterns = [compile_pattern(p) for p in config["any_of"]]

            for action in actions:
                for compiled in compiled_patterns:
                    if compiled and compiled.match(action):
                        matched.add(action)
                        break
            return len(matched) > 0, list(matched)

        # all_of: at least one action must match ALL patterns
        if "all_of" in config:
            # Pre-compile all patterns
            compiled_patterns = [compile_pattern(p) for p in config["all_of"]]
            # Filter out invalid patterns
            compiled_patterns = [p for p in compiled_patterns if p]

            if not compiled_patterns:
                return False, []

            matched = set()
            for action in actions:
                # Check if this action matches ALL patterns
                if all(compiled.match(action) for compiled in compiled_patterns):
                    matched.add(action)

            return len(matched) > 0, list(matched)

    return False, []

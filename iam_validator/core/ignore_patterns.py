"""
Centralized ignore patterns utility with caching and performance optimization.

This module provides high-performance pattern matching for ignore_patterns across
all checks. Uses LRU caching and compiled regex patterns for optimal performance.
"""

import re
from functools import lru_cache
from typing import Any

from iam_validator.core.models import ValidationIssue


# Global regex pattern cache (shared across all checks for maximum efficiency)
@lru_cache(maxsize=512)
def compile_pattern(pattern: str) -> re.Pattern[str] | None:
    """
    Compile and cache regex patterns.

    Uses LRU cache to avoid recompiling the same patterns across multiple calls.
    This is critical for performance when the same patterns are used repeatedly.

    This is a public API function used across multiple modules for consistent
    regex caching.

    Args:
        pattern: Regex pattern string

    Returns:
        Compiled pattern or None if invalid

    Performance:
        - First call: O(n) compile time
        - Cached calls: O(1) lookup
    """
    try:
        return re.compile(str(pattern), re.IGNORECASE)
    except re.error:
        return None


class IgnorePatternMatcher:
    """
    High-performance pattern matcher for ignore_patterns.

    Features:
    - Cached compiled regex patterns (LRU cache)
    - Support for new (simple) and old (verbose) field names
    - Efficient filtering with early exit optimization
    - Field-specific validation logic

    Thread-safe: Yes (regex compilation is cached globally)
    """

    # Supported field name mappings (new -> old for backward compatibility)
    FIELD_ALIASES = {
        "filepath": "filepath_regex",
        "action": "action_matches",
        "resource": "resource_matches",
        "sid": "statement_sid",
        "condition_key": "condition_key_matches",
    }

    @staticmethod
    def should_ignore_issue(
        issue: ValidationIssue,
        filepath: str,
        ignore_patterns: list[dict[str, Any]],
    ) -> bool:
        """
        Check if a ValidationIssue should be ignored based on patterns.

        Pattern Matching Logic:
        - Multiple fields in ONE pattern = AND logic (all must match)
        - Multiple patterns = OR logic (any pattern matches → ignore)

        Args:
            issue: The validation issue to check
            filepath: Path to the policy file
            ignore_patterns: List of pattern dictionaries

        Returns:
            True if the issue should be ignored

        Performance:
            - Early exit on first match (OR logic)
            - Cached regex compilation
            - O(p * f) where p=patterns, f=fields per pattern
        """
        if not ignore_patterns:
            return False

        for pattern in ignore_patterns:
            if IgnorePatternMatcher._matches_pattern(pattern, issue, filepath):
                return True  # Early exit on first match

        return False

    @staticmethod
    def filter_actions(
        actions: frozenset[str],
        ignore_patterns: list[dict[str, Any]],
    ) -> frozenset[str]:
        """
        Filter actions based on action ignore patterns.

        Only considers patterns that contain an "action" or "action_matches" field.
        This is optimized for the sensitive_action check which needs to filter
        actions before creating ValidationIssues.

        Supports both single action patterns and lists:
        - action: "s3:.*"  # Single regex pattern
        - action: ["s3:GetObject", "s3:PutObject"]  # List of patterns

        Args:
            actions: Set of actions to filter
            ignore_patterns: List of pattern dictionaries

        Returns:
            Filtered set of actions (actions matching patterns removed)

        Performance:
            - Extracts action patterns once: O(p) where p=patterns
            - Filters with cached regex: O(a * p) where a=actions, p=patterns
            - Early exit per action when match found
        """
        if not ignore_patterns:
            return actions

        # Extract action patterns once (cache-friendly)
        action_patterns = []
        for pattern in ignore_patterns:
            # Support both new and old field names
            action_regex = pattern.get("action") or pattern.get("action_matches")
            if action_regex:
                # Support both single string and list of strings
                if isinstance(action_regex, list):
                    action_patterns.extend(action_regex)
                else:
                    action_patterns.append(action_regex)

        if not action_patterns:
            return actions

        # Filter actions with compiled patterns (cached)
        filtered = set()
        for action in actions:
            should_keep = True
            for pattern_str in action_patterns:
                compiled = compile_pattern(pattern_str)
                if compiled and compiled.search(str(action)):
                    should_keep = False
                    break  # Early exit on first match

            if should_keep:
                filtered.add(action)

        return frozenset(filtered)

    @staticmethod
    def _matches_pattern(
        pattern: dict[str, Any],
        issue: ValidationIssue,
        filepath: str,
    ) -> bool:
        """
        Check if issue matches a single ignore pattern.

        All fields in pattern must match (AND logic).
        For list-based fields (like action), ANY match from the list counts (OR logic).

        Args:
            pattern: Pattern dict with optional fields
            issue: ValidationIssue to check
            filepath: Path to policy file

        Returns:
            True if all fields in pattern match the issue

        Performance:
            - Early exit on first non-match (AND logic)
            - Uses cached compiled patterns
        """
        for field_name, regex_pattern in pattern.items():
            # Get actual value from issue based on field name
            actual_value = IgnorePatternMatcher._get_field_value(field_name, issue, filepath)

            # Handle special case: SID with exact match (no regex)
            if field_name in ("sid", "statement_sid"):
                # Support both single string and list of strings
                if isinstance(regex_pattern, list):
                    # List of SIDs - exact match or regex
                    matched = False
                    for single_sid in regex_pattern:
                        if isinstance(single_sid, str) and "*" not in single_sid:
                            # Exact match
                            if issue.statement_sid == single_sid:
                                matched = True
                                break
                        else:
                            # Regex match
                            compiled = compile_pattern(str(single_sid))
                            if compiled and compiled.search(str(issue.statement_sid or "")):
                                matched = True
                                break
                    if not matched:
                        return False
                    continue
                elif isinstance(regex_pattern, str) and "*" not in regex_pattern:
                    # Single SID - exact match (not a regex)
                    if issue.statement_sid != regex_pattern:
                        return False  # Early exit on non-match
                    continue

            # Regex match for all other cases
            if actual_value is None:
                return False  # Early exit on missing value

            # Support list of patterns (OR logic - any match succeeds)
            if isinstance(regex_pattern, list):
                matched = False
                for single_pattern in regex_pattern:
                    compiled = compile_pattern(str(single_pattern))
                    if compiled and compiled.search(str(actual_value)):
                        matched = True
                        break  # Found a match in the list
                if not matched:
                    return False  # None of the patterns matched
            else:
                # Single pattern
                compiled = compile_pattern(str(regex_pattern))
                if not compiled or not compiled.search(str(actual_value)):
                    return False  # Early exit on non-match

        return True  # All fields matched

    @staticmethod
    def _get_field_value(
        field_name: str,
        issue: ValidationIssue,
        filepath: str,
    ) -> str | None:
        """
        Extract field value from issue or filepath.

        Supports both new (simple) and old (verbose) field names for
        backward compatibility.

        Args:
            field_name: Name of the field to extract
            issue: ValidationIssue to extract from
            filepath: Policy file path

        Returns:
            Field value as string, or None if field not recognized
        """
        # Normalize field name (support both old and new names)
        if field_name in ("filepath", "filepath_regex"):
            return filepath
        elif field_name in ("action", "action_matches"):
            return issue.action or ""
        elif field_name in ("resource", "resource_matches"):
            return issue.resource or ""
        elif field_name in ("sid", "statement_sid"):
            return issue.statement_sid or ""
        elif field_name in ("condition_key", "condition_key_matches"):
            return issue.condition_key or ""
        else:
            # Unknown field - skip (don't fail)
            return None


# Convenience functions for backward compatibility
def should_ignore_issue(
    issue: ValidationIssue,
    filepath: str,
    ignore_patterns: list[dict[str, Any]],
) -> bool:
    """
    Convenience function for checking if an issue should be ignored.

    See IgnorePatternMatcher.should_ignore_issue() for details.
    """
    return IgnorePatternMatcher.should_ignore_issue(issue, filepath, ignore_patterns)


def filter_actions(
    actions: frozenset[str],
    ignore_patterns: list[dict[str, Any]],
) -> frozenset[str]:
    """
    Convenience function for filtering actions.

    See IgnorePatternMatcher.filter_actions() for details.
    """
    return IgnorePatternMatcher.filter_actions(actions, ignore_patterns)

"""Security best practices check - validates security anti-patterns."""

import re
from functools import lru_cache
from re import Pattern
from typing import TYPE_CHECKING

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue

if TYPE_CHECKING:
    from iam_validator.core.models import IAMPolicy


# Global regex pattern cache for performance
@lru_cache(maxsize=256)
def _compile_pattern(pattern: str) -> Pattern[str] | None:
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


class SecurityBestPracticesCheck(PolicyCheck):
    """Checks for common security anti-patterns and best practices violations."""

    # Default set of sensitive actions that should have conditions
    # Using frozenset for O(1) lookups and immutability
    DEFAULT_SENSITIVE_ACTIONS = frozenset(
        {
            "iam:CreateUser",
            "iam:CreateRole",
            "iam:PutUserPolicy",
            "iam:PutRolePolicy",
            "iam:AttachUserPolicy",
            "iam:AttachRolePolicy",
            "iam:CreateAccessKey",
            "iam:DeleteUser",
            "iam:DeleteRole",
            "s3:DeleteBucket",
            "s3:PutBucketPolicy",
            "s3:DeleteBucketPolicy",
            "ec2:TerminateInstances",
            "ec2:DeleteVolume",
            "rds:DeleteDBInstance",
            "lambda:DeleteFunction",
        }
    )

    @property
    def check_id(self) -> str:
        return "security_best_practices"

    @property
    def description(self) -> str:
        return "Checks for common security anti-patterns"

    @property
    def default_severity(self) -> str:
        return "warning"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute security best practices checks on a statement."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        statement_sid = statement.sid
        line_number = statement.line_number
        actions = statement.get_actions()
        resources = statement.get_resources()

        # Check 1: Wildcard action check
        if self._is_sub_check_enabled(config, "wildcard_action_check"):
            if "*" in actions:
                severity = self._get_sub_check_severity(
                    config, "wildcard_action_check", "warning"
                )
                issues.append(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="overly_permissive",
                        message="Statement allows all actions (*)",
                        suggestion="Consider limiting to specific actions needed",
                        line_number=line_number,
                    )
                )

        # Check 2: Wildcard resource check
        if self._is_sub_check_enabled(config, "wildcard_resource_check"):
            if "*" in resources:
                severity = self._get_sub_check_severity(
                    config, "wildcard_resource_check", "warning"
                )
                issues.append(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="overly_permissive",
                        message="Statement applies to all resources (*)",
                        suggestion="Consider limiting to specific resources",
                        line_number=line_number,
                    )
                )

        # Check 3: Critical - both wildcards together
        if self._is_sub_check_enabled(config, "full_wildcard_check"):
            if "*" in actions and "*" in resources:
                severity = self._get_sub_check_severity(
                    config, "full_wildcard_check", "error"
                )
                issues.append(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="security_risk",
                        message="Statement allows all actions on all resources - CRITICAL SECURITY RISK",
                        suggestion="This grants full administrative access. Restrict to specific actions and resources.",
                        line_number=line_number,
                    )
                )

        # Check 4: Service-level wildcards (e.g., "iam:*", "s3:*")
        if self._is_sub_check_enabled(config, "service_wildcard_check"):
            allowed_services = self._get_allowed_service_wildcards(config)

            for action in actions:
                # Skip full wildcard (covered by wildcard_action_check)
                if action == "*":
                    continue

                # Check if it's a service-level wildcard (e.g., "iam:*", "s3:*")
                if ":" in action and action.endswith(":*"):
                    service = action.split(":")[0]

                    # Check if this service is in the allowed list
                    if service not in allowed_services:
                        severity = self._get_sub_check_severity(
                            config, "service_wildcard_check", "warning"
                        )
                        issues.append(
                            ValidationIssue(
                                severity=severity,
                                statement_sid=statement_sid,
                                statement_index=statement_idx,
                                issue_type="overly_permissive",
                                message=f"Service-level wildcard '{action}' grants all permissions for {service} service",
                                action=action,
                                suggestion=f"Consider specifying explicit actions instead of '{action}'. If you need multiple actions, list them individually or use more specific wildcards like '{service}:Get*' or '{service}:List*'.",
                                line_number=line_number,
                            )
                        )

        # Check 5: Sensitive actions without conditions
        if self._is_sub_check_enabled(config, "sensitive_action_check"):
            has_conditions = (
                statement.condition is not None and len(statement.condition) > 0
            )

            # Check if sensitive actions match using any_of/all_of logic
            is_sensitive, matched_actions = self._check_sensitive_actions(
                actions, config
            )

            if is_sensitive and not has_conditions:
                severity = self._get_sub_check_severity(
                    config, "sensitive_action_check", "warning"
                )

                # Create appropriate message based on matched actions
                if len(matched_actions) == 1:
                    message = f"Sensitive action '{matched_actions[0]}' should have conditions to limit when it can be used"
                else:
                    action_list = "', '".join(matched_actions)
                    message = f"Sensitive actions '{action_list}' should have conditions to limit when they can be used"

                issues.append(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="missing_condition",
                        message=message,
                        action=(
                            matched_actions[0] if len(matched_actions) == 1 else None
                        ),
                        suggestion="Add conditions like 'aws:Resource/owner must match aws:Principal/owner', IP restrictions, MFA requirements, or time-based restrictions",
                        line_number=line_number,
                    )
                )

        return issues

    async def execute_policy(
        self,
        policy: "IAMPolicy",
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """
        Execute policy-level security checks.

        This method examines the entire policy to detect privilege escalation patterns
        and other security issues that span multiple statements.

        Args:
            policy: The complete IAM policy to check
            policy_file: Path to the policy file (for context/reporting)
            fetcher: AWS service fetcher for validation against AWS APIs
            config: Configuration for this check instance

        Returns:
            List of ValidationIssue objects found by this check
        """
        del policy_file, fetcher  # Not used in current implementation
        issues = []

        # Only check if sensitive_action_check is enabled
        if not self._is_sub_check_enabled(config, "sensitive_action_check"):
            return issues

        # Collect all actions from all Allow statements across the entire policy
        all_actions: set[str] = set()
        statement_map: dict[str, list[tuple[int, str | None]]] = (
            {}
        )  # action -> [(stmt_idx, sid), ...]

        for idx, statement in enumerate(policy.statement):
            if statement.effect == "Allow":
                actions = statement.get_actions()
                # Filter out wildcards for privilege escalation detection
                filtered_actions = [a for a in actions if a != "*"]

                for action in filtered_actions:
                    all_actions.add(action)
                    if action not in statement_map:
                        statement_map[action] = []
                    statement_map[action].append((idx, statement.sid))

        # Get configuration for sensitive actions
        sub_check_config = config.config.get("sensitive_action_check", {})
        if not isinstance(sub_check_config, dict):
            return issues

        sensitive_actions_config = sub_check_config.get("sensitive_actions")
        sensitive_patterns_config = sub_check_config.get("sensitive_action_patterns")

        # Check for privilege escalation patterns using all_of logic
        # We need to check both exact actions and patterns
        policy_issues = []

        # Check sensitive_actions configuration
        if sensitive_actions_config:
            policy_issues.extend(
                self._check_policy_level_actions(
                    list(all_actions),
                    statement_map,
                    sensitive_actions_config,
                    config,
                    "actions",
                )
            )

        # Check sensitive_action_patterns configuration
        if sensitive_patterns_config:
            policy_issues.extend(
                self._check_policy_level_actions(
                    list(all_actions),
                    statement_map,
                    sensitive_patterns_config,
                    config,
                    "patterns",
                )
            )

        issues.extend(policy_issues)
        return issues

    def _check_policy_level_actions(
        self,
        all_actions: list[str],
        statement_map: dict[str, list[tuple[int, str | None]]],
        config,
        check_config: CheckConfig,
        check_type: str,
    ) -> list[ValidationIssue]:
        """
        Check for policy-level privilege escalation patterns.

        Args:
            all_actions: All actions across the entire policy
            statement_map: Mapping of action -> [(statement_idx, sid), ...]
            config: The sensitive_actions or sensitive_action_patterns configuration
            check_config: Full check configuration
            check_type: Either "actions" (exact match) or "patterns" (regex match)

        Returns:
            List of ValidationIssue objects
        """
        import re

        issues = []

        if not config:
            return issues

        # Handle list of items (could be simple strings or dicts with all_of/any_of)
        if isinstance(config, list):
            for item in config:
                if isinstance(item, dict) and "all_of" in item:
                    # This is a privilege escalation pattern - all actions must be present
                    required_actions = item["all_of"]
                    matched_actions = []

                    if check_type == "actions":
                        # Exact matching
                        matched_actions = [
                            a for a in all_actions if a in required_actions
                        ]
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
                        severity = self._get_sub_check_severity(
                            check_config, "sensitive_action_check", "error"
                        )

                        # Collect which statements these actions appear in
                        statement_refs = []
                        for action in matched_actions:
                            if action in statement_map:
                                for stmt_idx, sid in statement_map[action]:
                                    sid_str = f"'{sid}'" if sid else f"#{stmt_idx}"
                                    statement_refs.append(
                                        f"Statement {sid_str}: {action}"
                                    )

                        action_list = "', '".join(matched_actions)
                        stmt_details = "\n  - ".join(statement_refs)

                        issues.append(
                            ValidationIssue(
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
                        )

        # Handle dict with all_of at the top level
        elif isinstance(config, dict) and "all_of" in config:
            required_actions = config["all_of"]
            matched_actions = []

            if check_type == "actions":
                matched_actions = [a for a in all_actions if a in required_actions]
            else:
                for pattern in required_actions:
                    for action in all_actions:
                        try:
                            if re.match(pattern, action):
                                matched_actions.append(action)
                                break
                        except re.error:
                            continue

            if len(matched_actions) >= len(required_actions):
                severity = self._get_sub_check_severity(
                    check_config, "sensitive_action_check", "error"
                )

                statement_refs = []
                for action in matched_actions:
                    if action in statement_map:
                        for stmt_idx, sid in statement_map[action]:
                            sid_str = f"'{sid}'" if sid else f"#{stmt_idx}"
                            statement_refs.append(f"Statement {sid_str}: {action}")

                action_list = "', '".join(matched_actions)
                stmt_details = "\n  - ".join(statement_refs)

                issues.append(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=None,
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
                )

        return issues

    def _is_sub_check_enabled(self, config: CheckConfig, sub_check_name: str) -> bool:
        """Check if a sub-check is enabled in the configuration."""
        if sub_check_name not in config.config:
            return True  # Enabled by default

        sub_check_config = config.config.get(sub_check_name, {})
        if isinstance(sub_check_config, dict):
            return sub_check_config.get("enabled", True)
        return True

    def _get_sub_check_severity(
        self, config: CheckConfig, sub_check_name: str, default: str
    ) -> str:
        """Get severity for a sub-check."""
        if sub_check_name not in config.config:
            return default

        sub_check_config = config.config.get(sub_check_name, {})
        if isinstance(sub_check_config, dict):
            return sub_check_config.get("severity", default)
        return default

    def _get_allowed_service_wildcards(self, config: CheckConfig) -> set[str]:
        """
        Get list of services that are allowed to use service-level wildcards.

        This allows configuration like:
          service_wildcard_check:
            allowed_services:
              - "logs"        # Allow "logs:*"
              - "cloudwatch"  # Allow "cloudwatch:*"

        Returns empty set if no exceptions are configured.
        """
        sub_check_config = config.config.get("service_wildcard_check", {})

        if isinstance(sub_check_config, dict):
            allowed = sub_check_config.get("allowed_services", [])
            if allowed and isinstance(allowed, list):
                return set(allowed)

        return set()

    def _check_sensitive_actions(
        self, actions: list[str], config: CheckConfig
    ) -> tuple[bool, list[str]]:
        """
        Check if actions match sensitive action criteria with any_of/all_of support.

        Returns:
            tuple[bool, list[str]]: (is_sensitive, matched_actions)
                - is_sensitive: True if the actions match the sensitive criteria
                - matched_actions: List of actions that matched the criteria
        """
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
        actions_match, actions_matched = self._check_actions_config(
            filtered_actions, sensitive_actions_config
        )

        # Check sensitive_action_patterns (regex patterns)
        patterns_match, patterns_matched = self._check_patterns_config(
            filtered_actions, sensitive_patterns_config
        )

        # Combine results - if either matched, we consider it sensitive
        is_sensitive = actions_match or patterns_match
        # Use set operations for efficient deduplication
        matched_set = set(actions_matched) | set(patterns_matched)
        matched_actions = list(matched_set)

        return is_sensitive, matched_actions

    def _check_actions_config(
        self, actions: list[str], config
    ) -> tuple[bool, list[str]]:
        """
        Check actions against sensitive_actions configuration.

        Supports:
        - Simple list: ["action1", "action2"] (backward compatible, any_of logic)
        - any_of: {"any_of": ["action1", "action2"]}
        - all_of: {"all_of": ["action1", "action2"]}
        - Multiple groups: [{"all_of": [...]}, {"all_of": [...]}, "action3"]

        Returns:
            tuple[bool, list[str]]: (matches, matched_actions)
        """
        if not config:
            # If no config, fall back to defaults with any_of logic
            # DEFAULT_SENSITIVE_ACTIONS is already a frozenset for O(1) lookups
            matched = [a for a in actions if a in self.DEFAULT_SENSITIVE_ACTIONS]
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
                    matches, matched = self._check_actions_config(actions, item)
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

    def _check_patterns_config(
        self, actions: list[str], config
    ) -> tuple[bool, list[str]]:
        """
        Check actions against sensitive_action_patterns configuration.

        Supports:
        - Simple list: ["^pattern1.*", "^pattern2.*"] (backward compatible, any_of logic)
        - any_of: {"any_of": ["^pattern1.*", "^pattern2.*"]}
        - all_of: {"all_of": ["^pattern1.*", "^pattern2.*"]}
        - Multiple groups: [{"all_of": [...]}, {"any_of": [...]}, "^pattern.*"]

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
                    compiled = _compile_pattern(item)
                    if compiled:
                        for action in actions:
                            if compiled.match(action):
                                all_matched.add(action)
                elif isinstance(item, dict):
                    # Recurse for dict items
                    matches, matched = self._check_patterns_config(actions, item)
                    if matches:
                        all_matched.update(matched)

            return len(all_matched) > 0, list(all_matched)

        # Handle dict with any_of/all_of
        if isinstance(config, dict):
            # any_of: at least one action must match at least one pattern
            if "any_of" in config:
                matched = set()
                # Pre-compile all patterns
                compiled_patterns = [_compile_pattern(p) for p in config["any_of"]]

                for action in actions:
                    for compiled in compiled_patterns:
                        if compiled and compiled.match(action):
                            matched.add(action)
                            break
                return len(matched) > 0, list(matched)

            # all_of: at least one action must match ALL patterns
            if "all_of" in config:
                # Pre-compile all patterns
                compiled_patterns = [_compile_pattern(p) for p in config["all_of"]]
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

    def _matches_sensitive_pattern(self, action: str, config: CheckConfig) -> bool:
        """
        DEPRECATED: Use _check_sensitive_actions instead.

        Check if action matches any sensitive action pattern (supports regex).

        This allows configuration like:
          sensitive_action_patterns:
            - "^iam:.*"          # All IAM actions
            - ".*:Delete.*"      # Any delete action
            - "s3:PutBucket.*"   # S3 bucket modification actions
        """
        import re

        sub_check_config = config.config.get("sensitive_action_check", {})
        if not isinstance(sub_check_config, dict):
            return False

        patterns = sub_check_config.get("sensitive_action_patterns", [])
        if not patterns:
            return False

        for pattern in patterns:
            try:
                if re.match(pattern, action):
                    return True
            except re.error:
                # Invalid regex pattern, skip it
                continue

        return False

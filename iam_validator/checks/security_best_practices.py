"""Security best practices check - validates security anti-patterns."""

from typing import TYPE_CHECKING

from iam_validator.checks.utils.policy_level_checks import check_policy_level_actions
from iam_validator.checks.utils.sensitive_action_matcher import (
    DEFAULT_SENSITIVE_ACTIONS,
    check_sensitive_actions,
)
from iam_validator.checks.utils.wildcard_expansion import expand_wildcard_actions
from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue

if TYPE_CHECKING:
    from iam_validator.core.models import IAMPolicy


class SecurityBestPracticesCheck(PolicyCheck):
    """Checks for common security anti-patterns and best practices violations."""

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
                severity = self._get_sub_check_severity(config, "wildcard_action_check", "warning")
                sub_check_config = config.config.get("wildcard_action_check", {})

                message = sub_check_config.get("message", "Statement allows all actions (*)")
                suggestion_text = sub_check_config.get(
                    "suggestion", "Consider limiting to specific actions needed"
                )
                example = sub_check_config.get("example", "")

                # Combine suggestion + example like action_condition_enforcement does
                suggestion = (
                    f"{suggestion_text}\nExample:\n{example}" if example else suggestion_text
                )

                issues.append(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="overly_permissive",
                        message=message,
                        suggestion=suggestion,
                        line_number=line_number,
                    )
                )

        # Check 2: Wildcard resource check
        if self._is_sub_check_enabled(config, "wildcard_resource_check"):
            if "*" in resources:
                # Check if all actions are in the allowed_wildcards list
                # allowed_wildcards works by expanding wildcard patterns (like "ec2:Describe*")
                # to all matching AWS actions using the AWS API, then checking if the policy's
                # actions are in that expanded list. This ensures only validated AWS actions
                # are allowed with Resource: "*".
                allowed_wildcards_expanded = await self._get_expanded_allowed_wildcards(
                    config, fetcher
                )

                # Check if ALL actions (excluding full wildcard "*") are in the expanded list
                non_wildcard_actions = [a for a in actions if a != "*"]

                if allowed_wildcards_expanded and non_wildcard_actions:
                    # Check if all actions are in the expanded allowed list (exact match)
                    all_actions_allowed = all(
                        action in allowed_wildcards_expanded for action in non_wildcard_actions
                    )

                    # If all actions are in the expanded list, skip the wildcard resource warning
                    if all_actions_allowed:
                        # All actions are safe, Resource: "*" is acceptable
                        pass
                    else:
                        # Some actions are not in allowed list, flag the issue
                        self._add_wildcard_resource_issue(
                            issues,
                            config,
                            statement_sid,
                            statement_idx,
                            line_number,
                        )
                else:
                    # No allowed_wildcards configured OR only has "*" action
                    # Always flag wildcard resources in these cases
                    self._add_wildcard_resource_issue(
                        issues, config, statement_sid, statement_idx, line_number
                    )

        # Check 3: Critical - both wildcards together
        if self._is_sub_check_enabled(config, "full_wildcard_check"):
            if "*" in actions and "*" in resources:
                severity = self._get_sub_check_severity(config, "full_wildcard_check", "error")
                sub_check_config = config.config.get("full_wildcard_check", {})

                message = sub_check_config.get(
                    "message",
                    "Statement allows all actions on all resources - CRITICAL SECURITY RISK",
                )
                suggestion_text = sub_check_config.get(
                    "suggestion",
                    "This grants full administrative access. Restrict to specific actions and resources.",
                )
                example = sub_check_config.get("example", "")

                # Combine suggestion + example
                suggestion = (
                    f"{suggestion_text}\nExample:\n{example}" if example else suggestion_text
                )

                issues.append(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="security_risk",
                        message=message,
                        suggestion=suggestion,
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
                        sub_check_config = config.config.get("service_wildcard_check", {})

                        # Get message template and replace placeholders
                        message_template = sub_check_config.get(
                            "message",
                            "Service-level wildcard '{action}' grants all permissions for {service} service",
                        )
                        suggestion_template = sub_check_config.get(
                            "suggestion",
                            "Consider specifying explicit actions instead of '{action}'. If you need multiple actions, list them individually or use more specific wildcards like '{service}:Get*' or '{service}:List*'.",
                        )
                        example_template = sub_check_config.get("example", "")

                        message = message_template.format(action=action, service=service)
                        suggestion_text = suggestion_template.format(action=action, service=service)
                        example = (
                            example_template.format(action=action, service=service)
                            if example_template
                            else ""
                        )

                        # Combine suggestion + example
                        suggestion = (
                            f"{suggestion_text}\nExample:\n{example}"
                            if example
                            else suggestion_text
                        )

                        issues.append(
                            ValidationIssue(
                                severity=severity,
                                statement_sid=statement_sid,
                                statement_index=statement_idx,
                                issue_type="overly_permissive",
                                message=message,
                                action=action,
                                suggestion=suggestion,
                                line_number=line_number,
                            )
                        )

        # Check 5: Sensitive actions without conditions
        if self._is_sub_check_enabled(config, "sensitive_action_check"):
            has_conditions = statement.condition is not None and len(statement.condition) > 0

            # Expand wildcards to actual actions using AWS API
            expanded_actions = await expand_wildcard_actions(actions, fetcher)

            # Check if sensitive actions match using any_of/all_of logic
            is_sensitive, matched_actions = check_sensitive_actions(
                expanded_actions, config, DEFAULT_SENSITIVE_ACTIONS
            )

            if is_sensitive and not has_conditions:
                severity = self._get_sub_check_severity(config, "sensitive_action_check", "warning")
                sub_check_config = config.config.get("sensitive_action_check", {})

                # Create appropriate message based on matched actions using configurable templates
                if len(matched_actions) == 1:
                    message_template = sub_check_config.get(
                        "message_single",
                        "Sensitive action '{action}' should have conditions to limit when it can be used",
                    )
                    message = message_template.format(action=matched_actions[0])
                else:
                    action_list = "', '".join(matched_actions)
                    message_template = sub_check_config.get(
                        "message_multiple",
                        "Sensitive actions '{actions}' should have conditions to limit when they can be used",
                    )
                    message = message_template.format(actions=action_list)

                suggestion_text = sub_check_config.get(
                    "suggestion",
                    "Add conditions like 'aws:Resource/owner must match aws:Principal/owner', IP restrictions, MFA requirements, or time-based restrictions",
                )
                example = sub_check_config.get("example", "")

                # Combine suggestion + example
                suggestion = (
                    f"{suggestion_text}\nExample:\n{example}" if example else suggestion_text
                )

                issues.append(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="missing_condition",
                        message=message,
                        action=(matched_actions[0] if len(matched_actions) == 1 else None),
                        suggestion=suggestion,
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
        **kwargs,
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
        statement_map: dict[
            str, list[tuple[int, str | None]]
        ] = {}  # action -> [(stmt_idx, sid), ...]

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
                check_policy_level_actions(
                    list(all_actions),
                    statement_map,
                    sensitive_actions_config,
                    config,
                    "actions",
                    self._get_sub_check_severity,
                )
            )

        # Check sensitive_action_patterns configuration
        if sensitive_patterns_config:
            policy_issues.extend(
                check_policy_level_actions(
                    list(all_actions),
                    statement_map,
                    sensitive_patterns_config,
                    config,
                    "patterns",
                    self._get_sub_check_severity,
                )
            )

        issues.extend(policy_issues)
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

    def _add_wildcard_resource_issue(
        self,
        issues: list[ValidationIssue],
        config: CheckConfig,
        statement_sid: str | None,
        statement_idx: int,
        line_number: int | None,
    ) -> None:
        """Add a wildcard resource issue to the issues list.

        This is a helper method to avoid code duplication when adding
        wildcard resource warnings.

        Args:
            issues: List to append the issue to
            config: Check configuration
            statement_sid: Statement ID
            statement_idx: Statement index
            line_number: Line number in the policy file
        """
        severity = self._get_sub_check_severity(config, "wildcard_resource_check", "warning")
        sub_check_config = config.config.get("wildcard_resource_check", {})

        message = sub_check_config.get("message", "Statement applies to all resources (*)")
        suggestion_text = sub_check_config.get(
            "suggestion", "Consider limiting to specific resources"
        )
        example = sub_check_config.get("example", "")

        # Combine suggestion + example
        suggestion = f"{suggestion_text}\nExample:\n{example}" if example else suggestion_text

        issues.append(
            ValidationIssue(
                severity=severity,
                statement_sid=statement_sid,
                statement_index=statement_idx,
                issue_type="overly_permissive",
                message=message,
                suggestion=suggestion,
                line_number=line_number,
            )
        )

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

    def _get_allowed_wildcards_for_resources(self, config: CheckConfig) -> frozenset[str]:
        """Get allowed_wildcards for resource check configuration.

        This checks for explicit allowed_wildcards configuration in wildcard_resource_check.
        If not configured, it falls back to the parent security_best_practices_check's allowed_wildcards.

        Args:
            config: The check configuration

        Returns:
            A frozenset of allowed wildcard patterns
        """
        sub_check_config = config.config.get("wildcard_resource_check", {})
        if isinstance(sub_check_config, dict) and "allowed_wildcards" in sub_check_config:
            # Explicitly configured in wildcard_resource_check (override)
            allowed_wildcards = sub_check_config.get("allowed_wildcards", [])
            if isinstance(allowed_wildcards, list):
                return frozenset(allowed_wildcards)
            elif isinstance(allowed_wildcards, set | frozenset):
                return frozenset(allowed_wildcards)
            return frozenset()

        # Fall back to parent security_best_practices_check's allowed_wildcards
        parent_allowed_wildcards = config.config.get("allowed_wildcards", [])
        if isinstance(parent_allowed_wildcards, list):
            return frozenset(parent_allowed_wildcards)
        elif isinstance(parent_allowed_wildcards, set | frozenset):
            return frozenset(parent_allowed_wildcards)

        # No configuration found, return empty set (flag all Resource: "*")
        return frozenset()

    async def _get_expanded_allowed_wildcards(
        self, config: CheckConfig, fetcher: AWSServiceFetcher
    ) -> frozenset[str]:
        """Get and expand allowed_wildcards configuration.

        This method retrieves wildcard patterns from the allowed_wildcards config
        and expands them using the AWS API to get all matching actual AWS actions.

        How it works:
        1. Retrieves patterns from config (e.g., ["ec2:Describe*", "s3:List*"])
        2. Expands each pattern using AWS API:
           - "ec2:Describe*" → ["ec2:DescribeInstances", "ec2:DescribeImages", ...]
           - "s3:List*" → ["s3:ListBucket", "s3:ListObjects", ...]
        3. Returns a set of all expanded actions

        This allows you to:
        - Specify patterns like "ec2:Describe*" in config
        - Have the validator allow specific actions like "ec2:DescribeInstances" with Resource: "*"
        - Ensure only real AWS actions (validated via API) are allowed

        Example:
            Config: allowed_wildcards: ["ec2:Describe*"]
            Expands to: ["ec2:DescribeInstances", "ec2:DescribeImages", ...]
            Policy: "Action": ["ec2:DescribeInstances"], "Resource": "*"
            Result: ✅ Allowed (ec2:DescribeInstances is in expanded list)

        Args:
            config: The check configuration
            fetcher: AWS service fetcher for expanding wildcards via AWS API

        Returns:
            A frozenset of all expanded action names from the configured patterns
        """
        # Check wildcard_resource_check first for override
        sub_check_config = config.config.get("wildcard_resource_check", {})
        patterns_to_expand: list[str] = []

        if isinstance(sub_check_config, dict) and "allowed_wildcards" in sub_check_config:
            # Explicitly configured in wildcard_resource_check (override)
            patterns = sub_check_config.get("allowed_wildcards", [])
            if isinstance(patterns, list):
                patterns_to_expand = patterns
        else:
            # Fall back to parent security_best_practices_check's allowed_wildcards
            parent_patterns = config.config.get("allowed_wildcards", [])
            if isinstance(parent_patterns, list):
                patterns_to_expand = parent_patterns

        # If no patterns configured, return empty set
        if not patterns_to_expand:
            return frozenset()

        # Expand the wildcard patterns using the AWS API
        # This converts patterns like "ec2:Describe*" to actual AWS actions
        expanded_actions = await expand_wildcard_actions(patterns_to_expand, fetcher)

        return frozenset(expanded_actions)

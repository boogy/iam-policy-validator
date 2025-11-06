"""Sensitive action check - detects sensitive actions without IAM conditions."""

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


class SensitiveActionCheck(PolicyCheck):
    """Checks for sensitive actions without IAM conditions to limit their use."""

    @property
    def check_id(self) -> str:
        return "sensitive_action"

    @property
    def description(self) -> str:
        return "Checks for sensitive actions without conditions"

    @property
    def default_severity(self) -> str:
        return "medium"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute sensitive action check on a statement."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        actions = statement.get_actions()
        has_conditions = statement.condition is not None and len(statement.condition) > 0

        # Expand wildcards to actual actions using AWS API
        expanded_actions = await expand_wildcard_actions(actions, fetcher)

        # Check if sensitive actions match using any_of/all_of logic
        is_sensitive, matched_actions = check_sensitive_actions(
            expanded_actions, config, DEFAULT_SENSITIVE_ACTIONS
        )

        if is_sensitive and not has_conditions:
            # Create appropriate message based on matched actions using configurable templates
            if len(matched_actions) == 1:
                message_template = config.config.get(
                    "message_single",
                    "Sensitive action '{action}' should have conditions to limit when it can be used",
                )
                message = message_template.format(action=matched_actions[0])
            else:
                action_list = "', '".join(matched_actions)
                message_template = config.config.get(
                    "message_multiple",
                    "Sensitive actions '{actions}' should have conditions to limit when they can be used",
                )
                message = message_template.format(actions=action_list)

            suggestion_text = config.config.get(
                "suggestion",
                "Add IAM conditions to limit when this action can be used. Consider: ABAC (ResourceTag OR RequestTag matching ${aws:PrincipalTag}), IP restrictions (aws:SourceIp), MFA requirements (aws:MultiFactorAuthPresent), or time-based restrictions (aws:CurrentTime)",
            )
            example = config.config.get("example", "")

            # Combine suggestion + example
            suggestion = f"{suggestion_text}\nExample:\n{example}" if example else suggestion_text

            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="missing_condition",
                    message=message,
                    action=(matched_actions[0] if len(matched_actions) == 1 else None),
                    suggestion=suggestion,
                    line_number=statement.line_number,
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
        Execute policy-level sensitive action checks.

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
        sensitive_actions_config = config.config.get("sensitive_actions")
        sensitive_patterns_config = config.config.get("sensitive_action_patterns")

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
                    self.get_severity,
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
                    self.get_severity,
                )
            )

        issues.extend(policy_issues)
        return issues

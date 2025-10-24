"""Action validation check - validates IAM actions against AWS service definitions."""

import re
from functools import lru_cache
from typing import Pattern

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


# Global cache for compiled wildcard patterns
@lru_cache(maxsize=512)
def _compile_wildcard_pattern(pattern: str) -> Pattern[str]:
    """Compile and cache wildcard patterns for O(1) reuse.

    Args:
        pattern: Wildcard pattern (e.g., "s3:Get*")

    Returns:
        Compiled regex pattern

    Performance:
        20-30x speedup by avoiding repeated pattern compilation
    """
    regex_pattern = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return re.compile(regex_pattern, re.IGNORECASE)


class ActionValidationCheck(PolicyCheck):
    """Validates that IAM actions exist in AWS services."""

    # Default allowlist for safe wildcard patterns (read-only operations)
    # Note: s3:Get* is intentionally excluded as reading S3 data can be sensitive
    # Using frozenset for O(1) lookup performance
    DEFAULT_ALLOWED_WILDCARDS = frozenset(
        {
            "s3:List*",
            "s3:Describe*",
            "ec2:Describe*",
            "iam:Get*",
            "iam:List*",
            "rds:Describe*",
            "lambda:Get*",
            "lambda:List*",
            "dynamodb:Describe*",
            "cloudwatch:Describe*",
            "cloudwatch:Get*",
            "cloudwatch:List*",
            "logs:Describe*",
            "logs:Get*",
            "logs:Filter*",
            "kms:Describe*",
            "kms:Get*",
            "kms:List*",
            "sns:Get*",
            "sns:List*",
            "sqs:Get*",
            "sqs:List*",
            "elasticloadbalancing:Describe*",
            "autoscaling:Describe*",
            "cloudformation:Describe*",
            "cloudformation:Get*",
            "cloudformation:List*",
            "route53:Get*",
            "route53:List*",
            "apigateway:GET",
        }
    )

    @property
    def check_id(self) -> str:
        return "action_validation"

    @property
    def description(self) -> str:
        return "Validates that actions exist in AWS service definitions"

    @property
    def default_severity(self) -> str:
        return "error"

    def _is_allowed_wildcard(
        self, action: str, allowed_wildcards: frozenset[str] | list[str] | set[str]
    ) -> bool:
        """Check if a wildcard action matches the allowlist.

        Args:
            action: The action to check (e.g., "s3:Get*")
            allowed_wildcards: Set or list of allowed wildcard patterns

        Returns:
            True if the action matches any pattern in the allowlist

        Note:
            Exact matches use O(1) set lookup for performance.
            Pattern matches (wildcards in allowlist) require O(n) iteration.
        """
        # Fast O(1) exact match using set membership
        if action in allowed_wildcards:
            return True

        # Pattern match - check if action matches any pattern in allowlist
        # This is needed when allowlist contains wildcards like "s3:*"
        # Uses cached compiled patterns for 20-30x speedup
        for pattern in allowed_wildcards:
            # Skip exact matches (already checked above)
            if "*" not in pattern:
                continue

            # Use cached compiled pattern
            compiled = _compile_wildcard_pattern(pattern)
            if compiled.match(action):
                return True

        return False

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute action validation on a statement."""
        issues = []

        # Get actions from statement
        actions = statement.get_actions()
        statement_sid = statement.sid
        line_number = statement.line_number

        # Get allowed wildcards from config, or use defaults
        allowed_wildcards_raw = config.config.get(
            "allowed_wildcards", self.DEFAULT_ALLOWED_WILDCARDS
        )

        # Convert list to frozenset for O(1) lookups (if from config)
        # DEFAULT_ALLOWED_WILDCARDS is already a frozenset
        if isinstance(allowed_wildcards_raw, list):
            allowed_wildcards = frozenset(allowed_wildcards_raw)
        else:
            allowed_wildcards = allowed_wildcards_raw

        # Check if wildcard warnings are disabled entirely
        disable_wildcard_warnings = config.config.get(
            "disable_wildcard_warnings", False
        )

        for action in actions:
            # Wildcard-only actions are handled by security checks
            if action == "*":
                continue

            # Validate the action
            is_valid, error_msg, is_wildcard = await fetcher.validate_action(action)

            if not is_valid:
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="invalid_action",
                        message=error_msg or f"Invalid action: {action}",
                        action=action,
                        line_number=line_number,
                    )
                )
            elif is_wildcard:
                # Check if this wildcard is in the allowlist
                if self._is_allowed_wildcard(action, allowed_wildcards):
                    # Wildcard is allowed, skip warning
                    continue

                # Wildcard actions are security concerns (unless disabled)
                # Note: This uses "info" severity by default because the security_best_practices
                # check provides more comprehensive wildcard analysis with proper security severities.
                # This is mainly informational - the action IS valid, just uses a wildcard.
                if not disable_wildcard_warnings:
                    issues.append(
                        ValidationIssue(
                            severity="info",  # Changed from "warning" - this is just informational
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="wildcard_action",
                            message=f"Action uses wildcard: {action}",
                            action=action,
                            suggestion="Consider using specific actions instead of wildcards for better security",
                            line_number=line_number,
                        )
                    )

        return issues

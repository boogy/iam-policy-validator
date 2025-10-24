"""
Example custom check: MFA Required Check

This check ensures that sensitive IAM actions require Multi-Factor Authentication (MFA).
This is a common security best practice for production environments.

Usage:
    Add to your iam-validator.yaml:

        custom_checks_dir: "./examples/custom_checks"

        checks:
          mfa_required:
            enabled: true
            severity: error
            # Actions that must have MFA
            require_mfa_for:
              - "iam:DeleteUser"
              - "iam:DeleteRole"
              - "s3:DeleteBucket"
            # Or use patterns
            require_mfa_patterns:
              - "^iam:Delete.*"
              - "^s3:DeleteBucket.*"
"""

import re
from typing import List

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class MFARequiredCheck(PolicyCheck):
    """Ensures sensitive actions require MFA authentication."""

    @property
    def check_id(self) -> str:
        return "mfa_required"

    @property
    def description(self) -> str:
        return "Ensures sensitive actions require MFA authentication"

    @property
    def default_severity(self) -> str:
        return "error"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> List[ValidationIssue]:
        """Check that sensitive actions have MFA conditions."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        # Get actions that require MFA from config
        require_mfa_for = set(config.config.get("require_mfa_for", []))
        require_mfa_patterns = config.config.get("require_mfa_patterns", [])

        # Get actions from statement
        actions = statement.get_actions()

        for action in actions:
            # Skip wildcard actions
            if action == "*":
                continue

            # Check if this action requires MFA
            requires_mfa = action in require_mfa_for or self._matches_pattern(
                action, require_mfa_patterns
            )

            if requires_mfa and not self._has_mfa_condition(statement):
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="missing_mfa_condition",
                        message=f"Action '{action}' requires MFA but statement has no MFA condition",
                        action=action,
                        suggestion="Add condition: aws:MultiFactorAuthPresent = true",
                        line_number=statement.line_number,
                    )
                )

        return issues

    def _has_mfa_condition(self, statement: Statement) -> bool:
        """Check if statement has MFA condition."""
        if not statement.condition:
            return False

        # Check all condition operators
        for operator, conditions in statement.condition.items():
            if "aws:MultiFactorAuthPresent" in conditions:
                # Verify it's set to true
                value = conditions["aws:MultiFactorAuthPresent"]
                if isinstance(value, bool) and value:
                    return True
                if isinstance(value, str) and value.lower() == "true":
                    return True

        return False

    def _matches_pattern(self, action: str, patterns: List[str]) -> bool:
        """Check if action matches any regex pattern."""
        for pattern in patterns:
            try:
                if re.match(pattern, action):
                    return True
            except re.error:
                continue
        return False

"""Action validation check - validates IAM actions against AWS service definitions.

This check ensures that all actions specified in IAM policies are valid actions
defined by AWS services. It helps identify typos or deprecated actions that may
lead to unintended access permissions.

This check is not necessary when using Access Analyzer, as it performs similar
validations. However, it can be useful in environments where Access Analyzer is
not available or for pre-deployment policy validation to catch errors early.
"""

import asyncio
from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class ActionValidationCheck(PolicyCheck):
    """Validates that IAM actions exist in AWS services."""

    check_id: ClassVar[str] = "action_validation"
    description: ClassVar[str] = "Validates that actions exist in AWS service definitions"
    default_severity: ClassVar[str] = "error"

    async def _validate_action(
        self,
        action: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        statement_sid: str | None,
        statement_idx: int,
        line_number: int | None,
        field_name: str,
    ) -> ValidationIssue | None:
        """Validate a single action and return an issue if invalid.

        Args:
            action: The action string to validate (e.g., "s3:GetObject")
            fetcher: AWS service fetcher for validation
            config: Check configuration
            statement_sid: Statement ID for error reporting
            statement_idx: Statement index for error reporting
            line_number: Line number for error reporting
            field_name: Field name ("action" or "not_action") for error reporting

        Returns:
            ValidationIssue if action is invalid, None otherwise
        """
        # Skip full wildcard - it's valid but handled by security checks
        if action == "*":
            return None

        # Validate the action exists in AWS (handles both exact and wildcard patterns)
        is_valid, error_msg, _is_wildcard = await fetcher.validate_action(action)

        if not is_valid:
            return ValidationIssue(
                severity=self.get_severity(config),
                statement_sid=statement_sid,
                statement_index=statement_idx,
                issue_type="invalid_action",
                message=error_msg or f"Invalid action: `{action}`",
                action=action,
                line_number=line_number,
                field_name=field_name,
            )

        return None

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute action validation on a statement.

        Validates both Action and NotAction fields to ensure all specified
        actions exist in AWS service definitions. Wildcard patterns like
        "s3:Get*" are validated to ensure they match at least one real action.

        Actions are validated in parallel for better performance.

        Security implications of wildcards are handled by separate checks
        (wildcard_action, service_wildcard, etc.).
        """
        statement_sid = statement.sid
        line_number = statement.line_number

        # Build list of validation tasks for parallel execution
        tasks = []

        # Validate Action field
        for action in statement.get_actions():
            tasks.append(
                self._validate_action(
                    action=action,
                    fetcher=fetcher,
                    config=config,
                    statement_sid=statement_sid,
                    statement_idx=statement_idx,
                    line_number=line_number,
                    field_name="action",
                )
            )

        # Validate NotAction field (same validation - typos in NotAction are equally problematic)
        for action in statement.get_not_actions():
            tasks.append(
                self._validate_action(
                    action=action,
                    fetcher=fetcher,
                    config=config,
                    statement_sid=statement_sid,
                    statement_idx=statement_idx,
                    line_number=line_number,
                    field_name="not_action",
                )
            )

        # Execute all validations in parallel
        if not tasks:
            return []

        results = await asyncio.gather(*tasks)

        # Filter out None results (valid actions)
        return [issue for issue in results if issue is not None]

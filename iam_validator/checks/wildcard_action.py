"""Wildcard action check - detects Action: '*' in IAM policies."""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class WildcardActionCheck(PolicyCheck):
    """Checks for wildcard actions (Action: '*') which grant all permissions."""

    check_id: ClassVar[str] = "wildcard_action"
    description: ClassVar[str] = "Checks for wildcard actions (*)"
    default_severity: ClassVar[str] = "medium"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute wildcard action check on a statement."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        actions = statement.get_actions()

        # Check for wildcard action (Action: "*")
        if "*" in actions:
            message = config.config.get(
                "message", 'Statement allows all actions `"*"` (wildcard action).'
            )
            suggestion = config.config.get(
                "suggestion",
                "Replace wildcard with specific actions needed for your use case",
            )
            example = config.config.get("example", "")

            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="overly_permissive",
                    message=message,
                    suggestion=suggestion,
                    example=example if example else None,
                    line_number=statement.line_number,
                    field_name="action",
                )
            )

        return issues

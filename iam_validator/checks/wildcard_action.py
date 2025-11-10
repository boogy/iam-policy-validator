"""Wildcard action check - detects Action: '*' in IAM policies."""

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class WildcardActionCheck(PolicyCheck):
    """Checks for wildcard actions (Action: '*') which grant all permissions."""

    @property
    def check_id(self) -> str:
        return "wildcard_action"

    @property
    def description(self) -> str:
        return "Checks for wildcard actions (*)"

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
        """Execute wildcard action check on a statement."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        actions = statement.get_actions()

        # Check for wildcard action (Action: "*")
        if "*" in actions:
            message = config.config.get("message", "Statement allows all actions (*)")
            suggestion_text = config.config.get(
                "suggestion",
                "Replace wildcard with specific actions needed for your use case",
            )
            example = config.config.get("example", "")

            # Combine suggestion + example
            suggestion = (
                f"{suggestion_text}\nExample:\n```json\n{example}\n```"
                if example
                else suggestion_text
            )

            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="overly_permissive",
                    message=message,
                    suggestion=suggestion,
                    line_number=statement.line_number,
                )
            )

        return issues

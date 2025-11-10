"""Full wildcard check - detects Action: '*' AND Resource: '*' together (critical security risk)."""

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class FullWildcardCheck(PolicyCheck):
    """Checks for both Action: '*' AND Resource: '*' which grants full administrative access."""

    @property
    def check_id(self) -> str:
        return "full_wildcard"

    @property
    def description(self) -> str:
        return "Checks for both action and resource wildcards together (critical risk)"

    @property
    def default_severity(self) -> str:
        return "critical"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute full wildcard check on a statement."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        actions = statement.get_actions()
        resources = statement.get_resources()

        # Check for both wildcards together (CRITICAL)
        if "*" in actions and "*" in resources:
            message = config.config.get(
                "message",
                "Statement allows all actions on all resources - CRITICAL SECURITY RISK",
            )
            suggestion_text = config.config.get(
                "suggestion",
                "This grants full administrative access. Replace both wildcards with specific actions and resources to follow least-privilege principle",
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
                    issue_type="security_risk",
                    message=message,
                    suggestion=suggestion,
                    line_number=statement.line_number,
                )
            )

        return issues

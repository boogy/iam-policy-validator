"""Action validation check - validates IAM actions against AWS service definitions.

This check ensures that all actions specified in IAM policies are valid actions
defined by AWS services. It helps identify typos or deprecated actions that may
lead to unintended access permissions.

This check is not necessary when using Access Analyzer, as it performs similar
validations. However, it can be useful in environments where Access Analyzer is
not available or for pre-deployment policy validation to catch errors early.
"""

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class ActionValidationCheck(PolicyCheck):
    """Validates that IAM actions exist in AWS services."""

    @property
    def check_id(self) -> str:
        return "action_validation"

    @property
    def description(self) -> str:
        return "Validates that actions exist in AWS service definitions"

    @property
    def default_severity(self) -> str:
        return "error"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute action validation on a statement.

        This check ONLY validates that actions exist in AWS service definitions.
        Wildcard security checks are handled by security_best_practices_check.
        """
        issues = []

        # Get actions from statement
        actions = statement.get_actions()
        statement_sid = statement.sid
        line_number = statement.line_number

        for action in actions:
            # Skip wildcard actions - they're handled by security_best_practices_check
            if action == "*" or "*" in action:
                continue

            # Validate the action exists in AWS
            is_valid, error_msg, _is_wildcard = await fetcher.validate_action(action)

            if not is_valid:
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="invalid_action",
                        message=error_msg or f"Invalid action: `{action}`",
                        action=action,
                        line_number=line_number,
                    )
                )

        return issues

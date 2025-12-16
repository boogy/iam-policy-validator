"""
Example custom check: Cross-Account ExternalId Validation

This check enforces that cross-account assume role permissions include an
ExternalId condition to prevent the "confused deputy" security problem.

This demonstrates a custom check for TRUST POLICIES that validates principal
and condition relationships - something the built-in checks don't cover.

The Confused Deputy Problem:
When your AWS account creates a role that can be assumed by a third-party
service, that service could potentially be tricked into using its permissions
on behalf of a different customer. The ExternalId acts as a secret between
you and the third party to prevent this attack.

References:
- https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html

Usage:
    Add to your iam-validator.yaml:

        custom_checks_dir: "./examples/custom_checks"

        checks:
          cross_account_external_id:
            enabled: true
            severity: error
            # Accounts that don't need ExternalId (your own org accounts)
            trusted_accounts:
              - "123456789012"
              - "987654321098"
"""

import re
from typing import Any, ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class CrossAccountExternalIdCheck(PolicyCheck):
    """Ensures cross-account sts:AssumeRole has ExternalId condition."""

    check_id: ClassVar[str] = "cross_account_external_id"
    description: ClassVar[str] = (
        "Ensures cross-account assume role permissions include ExternalId"
    )
    default_severity: ClassVar[str] = "error"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Check that cross-account AssumeRole has ExternalId condition."""
        del fetcher  # Not used in this check
        issues = []

        # Only check Allow statements with sts:AssumeRole
        if statement.effect != "Allow":
            return issues

        if not self._has_assume_role_action(statement):
            return issues

        # Check if this is cross-account (has principal from another account)
        principal_account = self._extract_account_from_principal(statement.principal)
        if not principal_account:
            return issues

        # Check if account is in trusted list (no ExternalId needed)
        trusted_accounts = config.config.get("trusted_accounts", [])
        if principal_account in trusted_accounts:
            return issues

        # Verify ExternalId condition exists
        if not self._has_external_id_condition(statement.condition):
            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="missing_external_id",
                    message=(
                        f"Cross-account sts:AssumeRole for account `{principal_account}` "
                        f"is missing ExternalId condition (confused deputy vulnerability)"
                    ),
                    suggestion=(
                        "Add a StringEquals condition for sts:ExternalId with a unique "
                        "secret shared between you and the trusted party"
                    ),
                    example=(
                        '"Condition": {\n'
                        '  "StringEquals": {\n'
                        '    "sts:ExternalId": "unique-secret-id"\n'
                        '  }\n'
                        '}'
                    ),
                    line_number=statement.line_number,
                    field_name="condition",
                    documentation_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html",
                )
            )

        return issues

    def _has_assume_role_action(self, statement: Statement) -> bool:
        """Check if statement includes sts:AssumeRole action."""
        actions = statement.get_actions()
        assume_role_patterns = ["sts:AssumeRole", "sts:*", "*"]
        return any(
            action in assume_role_patterns or action.startswith("sts:AssumeRole")
            for action in actions
        )

    def _extract_account_from_principal(self, principal: Any) -> str | None:
        """Extract AWS account ID from principal."""
        if not principal:
            return None

        if isinstance(principal, str):
            # Format: arn:aws:iam::123456789012:root
            match = re.search(r"arn:aws:iam::(\d{12}):", principal)
            return match.group(1) if match else None

        if isinstance(principal, dict):
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            for aws_principal in aws_principals:
                match = re.search(r"arn:aws:iam::(\d{12}):", aws_principal)
                if match:
                    return match.group(1)

        return None

    def _has_external_id_condition(self, condition: dict[str, Any] | None) -> bool:
        """Check if statement has sts:ExternalId condition."""
        if not condition:
            return False

        for operator in ["StringEquals", "StringLike"]:
            if operator in condition:
                operator_conditions = condition[operator]
                if isinstance(operator_conditions, dict):
                    if "sts:ExternalId" in operator_conditions:
                        return True

        return False

"""
Example custom check: Cross-Account Access with ExternalId Validation

This check enforces that cross-account assume role permissions always include
an ExternalId condition to prevent the "confused deputy" security problem.

The Confused Deputy Problem:
When your AWS account (Account A) creates a role that can be assumed by a third-party
service (Account B), Account B could potentially be tricked into using its permissions
on behalf of a different customer. The ExternalId acts as a secret between you and
the third party to prevent this attack.

Use Cases:
- Third-party service integrations (DataDog, Splunk, etc.)
- Cross-account data access
- Vendor integrations requiring role assumption
- Security compliance requirements (SOC2, ISO 27001)

Security References:
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html

Usage:
    Add to your iam-validator.yaml:

        custom_checks_dir: "./examples/custom_checks"

        checks:
          cross_account_external_id:
            enabled: true
            severity: error
            # Optionally specify trusted accounts that don't need ExternalId
            trusted_accounts:
              - "123456789012"  # Your organization's accounts
              - "987654321098"
            # Require specific ExternalId format/pattern
            require_external_id_pattern: "^[a-zA-Z0-9-]{32,}$"  # Min 32 chars
"""

import re
from typing import Any

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class CrossAccountExternalIdCheck(PolicyCheck):
    """Ensures cross-account sts:AssumeRole has ExternalId condition."""

    @property
    def check_id(self) -> str:
        return "cross_account_external_id"

    @property
    def description(self) -> str:
        return "Ensures cross-account assume role permissions include ExternalId to prevent confused deputy attacks"

    @property
    def default_severity(self) -> str:
        return "error"

    def _extract_account_from_principal(self, principal: Any) -> str | None:
        """Extract AWS account ID from principal."""
        if isinstance(principal, str):
            # Format: arn:aws:iam::123456789012:root
            if "arn:aws:iam::" in principal:
                match = re.search(r"arn:aws:iam::(\d{12}):", principal)
                if match:
                    return match.group(1)
        elif isinstance(principal, dict):
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            for aws_principal in aws_principals:
                if "arn:aws:iam::" in aws_principal:
                    match = re.search(r"arn:aws:iam::(\d{12}):", aws_principal)
                    if match:
                        return match.group(1)
        return None

    def _has_external_id_condition(
        self,
        conditions: dict[str, Any] | None,
        required_pattern: str | None = None,
    ) -> tuple[bool, str | None]:
        """
        Check if statement has ExternalId condition.
        Returns (has_condition, external_id_value)
        """
        if not conditions:
            return False, None

        # Check for sts:ExternalId condition
        for operator in ["StringEquals", "StringLike"]:
            if operator in conditions:
                operator_conditions = conditions[operator]
                if isinstance(operator_conditions, dict):
                    external_id = operator_conditions.get("sts:ExternalId")
                    if external_id:
                        return True, external_id

        return False, None

    def _validate_external_id_format(
        self, external_id: str, pattern: str | None
    ) -> tuple[bool, str | None]:
        """Validate ExternalId format against pattern."""
        if not pattern:
            return True, None

        if not re.match(pattern, external_id):
            return (
                False,
                f"ExternalId '{external_id}' does not match required pattern '{pattern}'",
            )

        return True, None

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute the cross-account ExternalId check."""
        issues: list[ValidationIssue] = []

        # Only check Allow statements
        if statement.effect.lower() != "allow":
            return issues

        # Only check sts:AssumeRole actions
        actions = (
            statement.action
            if isinstance(statement.action, list)
            else [statement.action]
            if statement.action
            else []
        )

        has_assume_role = any(
            action in ["sts:AssumeRole", "sts:*", "*"] or action.startswith("sts:AssumeRole*")
            for action in actions
            if action  # Filter out None values
        )

        if not has_assume_role:
            return issues

        # Check if this is a cross-account permission
        principal = statement.principal
        if not principal:
            return issues

        # Get trusted accounts from config
        trusted_accounts = config.config.get("trusted_accounts", [])
        required_pattern = config.config.get("require_external_id_pattern")

        # Extract account ID from principal
        principal_account = self._extract_account_from_principal(principal)

        # If we found a principal account and it's not in trusted list
        if principal_account and principal_account not in trusted_accounts:
            # Check for ExternalId condition
            has_condition, external_id_value = self._has_external_id_condition(
                statement.condition, required_pattern
            )

            if not has_condition:
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type=self.check_id,
                        message=(
                            f"Cross-account sts:AssumeRole permission "
                            f"for account {principal_account} is missing ExternalId condition. "
                            f"This creates a 'confused deputy' security vulnerability."
                        ),
                        suggestion=(
                            f"Add an ExternalId condition to prevent confused deputy attacks. "
                            f"The ExternalId should be a secret shared between you and the trusted party.\n\n"
                            f"Example:\n"
                            f"{{\n"
                            f'  "Effect": "Allow",\n'
                            f'  "Principal": {{\n'
                            f'    "AWS": "arn:aws:iam::{principal_account}:root"\n'
                            f"  }},\n"
                            f'  "Action": "sts:AssumeRole",\n'
                            f'  "Condition": {{\n'
                            f'    "StringEquals": {{\n'
                            f'      "sts:ExternalId": "unique-external-id-here"\n'
                            f"    }}\n"
                            f"  }}\n"
                            f"}}\n\n"
                            f"References:\n"
                            f"- https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"
                        ),
                        line_number=statement.line_number,
                    )
                )
            elif external_id_value and required_pattern:
                # Validate ExternalId format
                is_valid, error_msg = self._validate_external_id_format(
                    external_id_value, required_pattern
                )
                if not is_valid:
                    issues.append(
                        ValidationIssue(
                            severity="warning",
                            statement_sid=statement.sid,
                            statement_index=statement_idx,
                            issue_type=f"{self.check_id}_format",
                            message=error_msg or "Invalid ExternalId format",
                            suggestion=(
                                f"Ensure ExternalId follows your organization's format requirements. "
                                f"Required pattern: {required_pattern}\n"
                                f"Current value: {external_id_value}"
                            ),
                            line_number=statement.line_number,
                        )
                    )

        return issues


# Example usage and test cases:
EXAMPLE_CONFIG = """
# In iam-validator.yaml:

custom_checks_dir: "./examples/custom_checks"

checks:
  cross_account_external_id:
    enabled: true
    severity: error

    # Accounts that don't require ExternalId (e.g., your own organization accounts)
    trusted_accounts:
      - "123456789012"  # Your main AWS account
      - "987654321098"  # Your dev AWS account

    # Optional: Enforce ExternalId format (min 32 characters, alphanumeric and hyphens)
    require_external_id_pattern: "^[a-zA-Z0-9-]{32,}$"
"""

# Example policies:

EXAMPLE_BAD_POLICY = """
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
# ERROR: Missing ExternalId condition - vulnerable to confused deputy attack
"""

EXAMPLE_GOOD_POLICY = """
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "abc123-unique-external-id-xyz789"
        }
      }
    }
  ]
}
# OK: Has ExternalId condition
"""

EXAMPLE_TRUSTED_ACCOUNT_POLICY = """
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
# OK: Principal is in trusted_accounts list, ExternalId not required
"""

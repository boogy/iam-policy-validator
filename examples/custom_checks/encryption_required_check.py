"""
Example custom check: Encryption Required Check

This check ensures that policies require encryption for data operations.
Enforces security best practices for data protection.

Usage:
    Add to your iam-validator.yaml:

        custom_checks_dir: "./examples/custom_checks"

        checks:
          encryption_required:
            enabled: true
            severity: error
            # Actions that must require encryption
            require_encryption_for:
              - "s3:PutObject"
              - "s3:CreateBucket"
              - "dynamodb:CreateTable"
            # Require SecureTransport condition
            require_secure_transport: true
"""

from typing import List

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class EncryptionRequiredCheck(PolicyCheck):
    """Ensures policies require encryption for sensitive operations."""

    @property
    def check_id(self) -> str:
        return "encryption_required"

    @property
    def description(self) -> str:
        return "Ensures policies require encryption for data operations"

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
        """Check encryption requirements."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        require_encryption_for = set(config.config.get("require_encryption_for", []))
        require_secure_transport = config.config.get("require_secure_transport", False)

        actions = statement.get_actions()

        # Check 1: Specific actions that need encryption conditions
        for action in actions:
            if action == "*":
                continue

            if action in require_encryption_for:
                if not self._has_encryption_condition(statement, action):
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            statement_sid=statement.sid,
                            statement_index=statement_idx,
                            issue_type="missing_encryption_condition",
                            message=f"Action '{action}' should require encryption",
                            action=action,
                            suggestion=self._get_encryption_suggestion(action),
                            line_number=statement.line_number,
                        )
                    )

        # Check 2: SecureTransport requirement
        if require_secure_transport and not self._has_secure_transport_condition(
            statement
        ):
            issues.append(
                ValidationIssue(
                    severity="warning",
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="missing_secure_transport",
                    message="Statement should require HTTPS (SecureTransport)",
                    suggestion="Add condition: aws:SecureTransport = true",
                    line_number=statement.line_number,
                )
            )

        return issues

    def _has_encryption_condition(self, statement: Statement, action: str) -> bool:
        """Check if statement has appropriate encryption condition for action."""
        if not statement.condition:
            return False

        # Different services have different encryption condition keys
        encryption_keys = {
            "s3": [
                "s3:x-amz-server-side-encryption",
                "s3:x-amz-server-side-encryption-aws-kms-key-id",
            ],
            "dynamodb": ["dynamodb:EncryptionType"],
            "kms": ["kms:EncryptionContext"],
        }

        service = action.split(":")[0] if ":" in action else ""
        expected_keys = encryption_keys.get(service, [])

        # Check if any encryption-related condition is present
        for operator, conditions in statement.condition.items():
            for condition_key in conditions.keys():
                # Check service-specific keys
                if condition_key in expected_keys:
                    return True
                # Also accept generic encryption indicators
                if "encrypt" in condition_key.lower():
                    return True

        return False

    def _has_secure_transport_condition(self, statement: Statement) -> bool:
        """Check if statement requires HTTPS."""
        if not statement.condition:
            return False

        for operator, conditions in statement.condition.items():
            if "aws:SecureTransport" in conditions:
                value = conditions["aws:SecureTransport"]
                if isinstance(value, bool) and value:
                    return True
                if isinstance(value, str) and value.lower() == "true":
                    return True

        return False

    def _get_encryption_suggestion(self, action: str) -> str:
        """Get action-specific encryption suggestion."""
        service = action.split(":")[0] if ":" in action else ""

        suggestions = {
            "s3": "Add condition: s3:x-amz-server-side-encryption = AES256 or aws:kms",
            "dynamodb": "Add condition: dynamodb:EncryptionType = KMS",
            "kms": "Ensure KMS encryption context is specified",
        }

        return suggestions.get(service, "Add appropriate encryption condition")

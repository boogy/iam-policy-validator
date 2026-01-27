"""MFA Condition Anti-Pattern Check.

Detects dangerous MFA-related condition patterns that may not enforce MFA as intended.
"""

from typing import ClassVar

from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class MFAConditionCheck(PolicyCheck):
    """Check for MFA condition anti-patterns."""

    check_id: ClassVar[str] = "mfa_condition_antipattern"
    description: ClassVar[str] = "Detects dangerous MFA-related condition patterns"
    default_severity: ClassVar[str] = "warning"

    async def execute(
        self, statement: Statement, statement_idx: int, fetcher, config: CheckConfig
    ) -> list[ValidationIssue]:
        """
        Execute the MFA condition anti-pattern check.

        Common anti-patterns:
        1. Using Bool with aws:MultiFactorAuthPresent = false
           Problem: The key may not exist in the request, so condition doesn't enforce anything

        2. Using Null with aws:MultiFactorAuthPresent = false
           Problem: This only checks if the key exists, not if MFA was used

        Args:
            statement: The IAM statement to check
            statement_idx: Index of this statement in the policy
            fetcher: AWS service fetcher (not used in this check)
            config: Check configuration

        Returns:
            List of validation issues found
        """
        issues = []

        # Only check statements with conditions
        if not statement.condition:
            return issues

        statement_sid = statement.sid
        line_number = statement.line_number

        # Check for anti-pattern #1: Bool with aws:MultiFactorAuthPresent = false
        bool_conditions = statement.condition.get("Bool", {})
        for key, value in bool_conditions.items():
            if key.lower() == "aws:multifactorauthpresent":
                # Normalize value to list
                values = value if isinstance(value, list) else [value]
                # Convert to lowercase strings for comparison
                values_lower = [str(v).lower() for v in values]

                if "false" in values_lower or False in values:
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            message=(
                                "**Dangerous MFA condition pattern detected.** "
                                'Using `{"Bool": {"aws:MultiFactorAuthPresent": "false"}}` does not enforce MFA '
                                "because `aws:MultiFactorAuthPresent` may not exist in the request context. "
                                'Consider using `{"Bool": {"aws:MultiFactorAuthPresent": "true"}}` in an `Allow` statement, '
                                "or use `BoolIfExists` in a `Deny` statement."
                            ),
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="mfa_antipattern_bool_false",
                            line_number=line_number,
                            field_name="condition",
                        )
                    )

        # Check for anti-pattern #2: BoolIfExists with aws:MultiFactorAuthPresent = false
        # This is MORE dangerous than Bool because it also matches when the key is missing
        bool_if_exists_conditions = statement.condition.get("BoolIfExists", {})
        for key, value in bool_if_exists_conditions.items():
            if key.lower() == "aws:multifactorauthpresent":
                # Normalize value to list
                values = value if isinstance(value, list) else [value]
                # Convert to lowercase strings for comparison
                values_lower = [str(v).lower() for v in values]

                if "false" in values_lower or False in values:
                    issues.append(
                        ValidationIssue(
                            severity="high",  # Higher than default - this is worse than Bool
                            message=(
                                "**DANGEROUS MFA condition pattern detected.** "
                                'Using `{"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}` '
                                "is MORE dangerous than using `Bool` because it also matches when "
                                "the key is missing entirely (no MFA context in the request). "
                                "This effectively allows access without any MFA verification."
                            ),
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="mfa_antipattern_boolif_exists_false",
                            line_number=line_number,
                            field_name="condition",
                        )
                    )

        # Check for anti-pattern #3: Null with aws:MultiFactorAuthPresent = false
        null_conditions = statement.condition.get("Null", {})
        for key, value in null_conditions.items():
            if key.lower() == "aws:multifactorauthpresent":
                # Normalize value to list
                values = value if isinstance(value, list) else [value]
                # Convert to lowercase strings for comparison
                values_lower = [str(v).lower() for v in values]

                if "false" in values_lower or False in values:
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            message=(
                                "**Dangerous MFA condition pattern detected.** "
                                'Using `{"Null": {"aws:MultiFactorAuthPresent": "false"}}` only checks if the key exists, '
                                "not whether MFA was actually used. This does not enforce MFA. "
                                'Consider using `{"Bool": {"aws:MultiFactorAuthPresent": "true"}}` in an `Allow` statement instead.'
                            ),
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="mfa_antipattern_null_false",
                            line_number=line_number,
                            field_name="condition",
                        )
                    )

                # Check for anti-pattern #4: Null with aws:MultiFactorAuthPresent = true
                # This means "key does NOT exist" = no MFA was used
                if "true" in values_lower or True in values:
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            message=(
                                "**Dangerous MFA condition pattern detected.** "
                                'Using `{"Null": {"aws:MultiFactorAuthPresent": "true"}}` checks if the key '
                                "does NOT exist, which means no MFA was provided in the request context. "
                                "This condition allows access when MFA is absent."
                            ),
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="mfa_antipattern_null_true",
                            line_number=line_number,
                            field_name="condition",
                        )
                    )

        return issues

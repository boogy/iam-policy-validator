"""MFA Condition Anti-Pattern Check.

Detects dangerous MFA-related condition patterns that may not enforce MFA as intended.
"""

from typing import Any, ClassVar

from iam_validator.checks.utils.condition_matching import is_deny
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

        Common anti-patterns (effect-dependent unless noted):
        1. `Bool: {aws:MultiFactorAuthPresent: false}` — doesn't match a missing key,
           so it fails to enforce MFA under either `Allow` or `Deny`.
        2. `BoolIfExists: {aws:MultiFactorAuthPresent: false}` under `Allow` — matches
           when the key is absent, granting access without MFA. Under `Deny` this is
           AWS's documented MFA-enforcement pattern and is not flagged.
        3. `Null: {aws:MultiFactorAuthPresent: false}` — only checks key presence, not
           whether MFA was used; not effect-dependent.
        4. `Null: {aws:MultiFactorAuthPresent: true}` under `Allow` — grants access
           precisely when no MFA context is present. Under `Deny` this is AWS's
           recommended MFA guard and is not flagged.

        Args:
            statement: The IAM statement to check
            statement_idx: Index of this statement in the policy
            fetcher: AWS service fetcher (not used in this check)
            config: Check configuration

        Returns:
            List of validation issues found
        """
        issues: list[ValidationIssue] = []

        # Only check statements with conditions
        if not statement.condition:
            return issues

        deny = is_deny(statement)
        condition = statement.condition

        def operator_block(name: str) -> dict[str, Any]:
            wanted = name.lower()
            for op, block in condition.items():
                if op.strip().lower() == wanted and isinstance(block, dict):
                    return block
            return {}

        statement_sid = statement.sid
        line_number = statement.line_number

        # Check for anti-pattern #1: Bool with aws:MultiFactorAuthPresent = false
        bool_conditions = operator_block("Bool")
        for key, value in bool_conditions.items():
            if key.lower() == "aws:multifactorauthpresent":
                values = value if isinstance(value, list) else [value]
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
        # AWS's canonical Deny-based MFA guard uses this exact condition.
        if not deny:
            bool_if_exists_conditions = operator_block("BoolIfExists")
            for key, value in bool_if_exists_conditions.items():
                if key.lower() == "aws:multifactorauthpresent":
                    values = value if isinstance(value, list) else [value]
                    values_lower = [str(v).lower() for v in values]

                    if "false" in values_lower or False in values:
                        issues.append(
                            ValidationIssue(
                                severity="high",  # Higher than default - this is worse than Bool
                                message=(
                                    "**DANGEROUS MFA condition pattern detected.** "
                                    'Using `{"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}` '
                                    "in an `Allow` statement is MORE dangerous than using `Bool` because "
                                    "it also matches when the key is missing entirely (no MFA context in "
                                    "the request). This effectively allows access without any MFA "
                                    "verification. Under `Deny` this same condition is the recommended "
                                    "MFA-enforcement guard."
                                ),
                                statement_sid=statement_sid,
                                statement_index=statement_idx,
                                issue_type="mfa_antipattern_boolif_exists_false",
                                line_number=line_number,
                                field_name="condition",
                            )
                        )

        # Check for anti-pattern #3: Null with aws:MultiFactorAuthPresent = false
        null_conditions = operator_block("Null")
        for key, value in null_conditions.items():
            if key.lower() == "aws:multifactorauthpresent":
                values = value if isinstance(value, list) else [value]
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
                # "Key absent" means no MFA; under Deny that is AWS's recommended guard.
                if not deny and ("true" in values_lower or True in values):
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            message=(
                                "**Dangerous MFA condition pattern detected.** "
                                'Using `{"Null": {"aws:MultiFactorAuthPresent": "true"}}` in an `Allow` '
                                "statement grants access precisely when no MFA was present in the request "
                                "context. Under `Deny` this same condition is the recommended MFA guard."
                            ),
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="mfa_antipattern_null_true",
                            line_number=line_number,
                            field_name="condition",
                        )
                    )

        return issues

"""Set Operator Validation Check.

Validates proper usage of ForAllValues and ForAnyValue set operators in IAM policies.

Based on AWS IAM best practices:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
"""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.condition_validators import (
    is_multivalued_context_key,
    normalize_operator,
)
from iam_validator.core.models import Statement, ValidationIssue


class SetOperatorValidationCheck(PolicyCheck):
    """Check for proper usage of ForAllValues and ForAnyValue set operators."""

    check_id: ClassVar[str] = "set_operator_validation"
    description: ClassVar[str] = (
        "Validates proper usage of ForAllValues and ForAnyValue set operators"
    )
    default_severity: ClassVar[str] = "error"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """
        Execute the set operator validation check.

        Validates:
        1. ForAllValues/ForAnyValue not used with single-valued context keys (anti-pattern)
        2. ForAllValues with Allow effect includes Null condition check (security)
        3. ForAnyValue with Deny effect includes Null condition check (predictability)

        Args:
            statement: The IAM statement to check
            statement_idx: Index of this statement in the policy
            fetcher: AWS service fetcher (unused but required by interface)
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
        effect = statement.effect

        # Track which condition keys have set operators and Null checks
        set_operator_keys: dict[str, str] = {}  # key -> operator prefix
        null_checked_keys: set[str] = set()

        # First pass: Identify set operators and Null checks
        for operator, conditions in statement.condition.items():
            base_operator, _operator_type, set_prefix = normalize_operator(operator)

            # Track Null checks
            if base_operator == "Null":
                for condition_key in conditions.keys():
                    null_checked_keys.add(condition_key)

            # Track set operators
            if set_prefix in ["ForAllValues", "ForAnyValue"]:
                for condition_key in conditions.keys():
                    set_operator_keys[condition_key] = set_prefix

        # Second pass: Validate set operator usage
        for operator, conditions in statement.condition.items():
            base_operator, _operator_type, set_prefix = normalize_operator(operator)

            if not set_prefix:
                continue

            # Check each condition key used with a set operator
            for condition_key, _condition_values in conditions.items():
                # Issue 1: Set operator used with single-valued context key (anti-pattern)
                if not is_multivalued_context_key(condition_key):
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            message=(
                                f"Set operator `{set_prefix}` should not be used with single-valued "
                                f"condition key `{condition_key}`. This can lead to overly permissive policies. "
                                f"Set operators are designed for multivalued context keys like `aws:TagKeys`. "
                                f"See: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html"
                            ),
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="set_operator_on_single_valued_key",
                            condition_key=condition_key,
                            line_number=line_number,
                            field_name="condition",
                        )
                    )

                # Issue 2: ForAllValues with Allow effect without Null check (security risk)
                if set_prefix == "ForAllValues" and effect == "Allow":
                    if condition_key not in null_checked_keys:
                        issues.append(
                            ValidationIssue(
                                severity="warning",
                                message=(
                                    f"Security risk: `ForAllValues` with `Allow` effect on `{condition_key}` "
                                    f"should include a `Null` condition check. Without it, requests with missing "
                                    f'`{condition_key}` will be granted access. Add: `"Null": {{"{condition_key}": "false"}}`. '
                                    f"See: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html"
                                ),
                                statement_sid=statement_sid,
                                statement_index=statement_idx,
                                issue_type="forallvalues_allow_without_null_check",
                                condition_key=condition_key,
                                line_number=line_number,
                                field_name="condition",
                            )
                        )

                # Issue 3: ForAnyValue with Deny effect without Null check (unpredictable)
                if set_prefix == "ForAnyValue" and effect == "Deny":
                    if condition_key not in null_checked_keys:
                        issues.append(
                            ValidationIssue(
                                severity="warning",
                                message=(
                                    f"Unpredictable behavior: `ForAnyValue` with `Deny` effect on `{condition_key}` "
                                    f"should include a `Null` condition check. Without it, requests with missing "
                                    f"`{condition_key}` will evaluate to `No match` instead of denying access. "
                                    f'Add: `"Null": {{"{condition_key}": "false"}}`. '
                                    f"See: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html"
                                ),
                                statement_sid=statement_sid,
                                statement_index=statement_idx,
                                issue_type="foranyvalue_deny_without_null_check",
                                field_name="condition",
                                condition_key=condition_key,
                                line_number=line_number,
                            )
                        )

        return issues

"""Condition Type Mismatch Check.

Validates that condition operators match the expected types for condition keys and values.
"""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.condition_validators import (
    normalize_operator,
    translate_type,
    validate_value_for_type,
)
from iam_validator.core.models import Statement, ValidationIssue


class ConditionTypeMismatchCheck(PolicyCheck):
    """Check for type mismatches between operators, keys, and values."""

    check_id: ClassVar[str] = "condition_type_mismatch"
    description: ClassVar[str] = (
        "Validates condition operator types match key types and value formats"
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
        Execute the condition type mismatch check.

        Validates:
        1. Operator type matches condition key type
        2. Condition values match the expected type format

        Args:
            statement: The IAM statement to check
            statement_idx: Index of this statement in the policy
            fetcher: AWS service fetcher for looking up condition key types
            config: Check configuration

        Returns:
            List of validation issues found
        """
        issues = []

        # Only check statements with conditions
        if not statement.condition:
            return issues

        # Skip Null operator - it's special and doesn't need type validation
        # (Null just checks if a key exists or doesn't exist)
        skip_operators = {"Null"}

        statement_sid = statement.sid
        line_number = statement.line_number
        actions = statement.get_actions()
        resources = statement.get_resources()

        # Check each condition operator and its keys/values
        for operator, conditions in statement.condition.items():
            # Normalize the operator and get its expected type
            base_operator, operator_type, _set_prefix = normalize_operator(operator)

            if operator_type is None:
                # Unknown operator - this will be caught by another check
                continue

            if base_operator in skip_operators:
                continue

            # Check each condition key
            for condition_key, condition_values in conditions.items():
                # Normalize values to a list
                values = (
                    condition_values if isinstance(condition_values, list) else [condition_values]
                )

                # Get the expected type for this condition key
                key_type = await self._get_condition_key_type(
                    fetcher, condition_key, actions, resources
                )

                if key_type is None:
                    # Unknown condition key - will be caught by condition_key_validation check
                    continue

                # Normalize the key type
                key_type = translate_type(key_type)
                operator_type = translate_type(operator_type)

                # Special case: String operators with ARN types (usable but not recommended)
                if operator_type == "String" and key_type == "ARN":
                    issues.append(
                        ValidationIssue(
                            severity="warning",
                            message=(
                                f"Type mismatch (usable but not recommended): Operator `{operator}` expects "
                                f"`{operator_type}` values, but condition key `{condition_key}` is type `{key_type}`. "
                                f"Consider using an ARN-specific operator like `ArnEquals` or `ArnLike` instead."
                            ),
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="type_mismatch_usable",
                            line_number=line_number,
                            field_name="condition",
                        )
                    )
                # Check if operator type matches key type
                elif not self._types_compatible(operator_type, key_type):
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            message=(
                                f"Type mismatch: Operator `{operator}` expects `{operator_type}` values, "
                                f"but condition key `{condition_key}` is type `{key_type}`."
                            ),
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="type_mismatch",
                            condition_key=condition_key,
                            line_number=line_number,
                            field_name="condition",
                        )
                    )

                # Validate that the values match the expected type format
                is_valid, error_msg = validate_value_for_type(key_type, values)
                if not is_valid:
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            message=(
                                f"Invalid value format for condition key `{condition_key}`: {error_msg}"
                            ),
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="invalid_value_format",
                            condition_key=condition_key,
                            line_number=line_number,
                            field_name="condition",
                        )
                    )

        return issues

    async def _get_condition_key_type(
        self,
        fetcher: AWSServiceFetcher,
        condition_key: str,
        actions: list[str],
        resources: list[str],
    ) -> str | None:
        """
        Get the expected type for a condition key by checking global keys and service definitions.

        Args:
            fetcher: AWS service fetcher
            condition_key: The condition key to look up
            actions: List of actions from the statement
            resources: List of resources from the statement

        Returns:
            Type string or None if not found
        """
        from iam_validator.core.config.aws_global_conditions import (  # pylint: disable=import-outside-toplevel
            get_global_conditions,
        )

        # Check if it's a global condition key
        global_conditions = get_global_conditions()
        key_type = global_conditions.get_key_type(condition_key)
        if key_type:
            return key_type

        # Check service-specific and action-specific condition keys
        for action in actions:
            if action == "*":
                continue

            try:
                service_prefix, action_name = fetcher.parse_action(action)
                service_detail = await fetcher.fetch_service_by_name(service_prefix)

                # Check service-level condition keys
                if condition_key in service_detail.condition_keys:
                    condition_key_obj = service_detail.condition_keys[condition_key]
                    if condition_key_obj.types:
                        return condition_key_obj.types[0]

                # Check action-level condition keys
                if action_name in service_detail.actions:
                    action_detail = service_detail.actions[action_name]

                    # For action-specific keys, we need to check the service condition keys list
                    if (
                        action_detail.action_condition_keys
                        and condition_key in action_detail.action_condition_keys
                    ):
                        if condition_key in service_detail.condition_keys:
                            condition_key_obj = service_detail.condition_keys[condition_key]
                            if condition_key_obj.types:
                                return condition_key_obj.types[0]

                    # Check resource-specific condition keys
                    if resources and action_detail.resources:
                        for res_req in action_detail.resources:
                            resource_name = res_req.get("Name", "")
                            if not resource_name:
                                continue

                            resource_type = service_detail.resources.get(resource_name)
                            if resource_type and resource_type.condition_keys:
                                if condition_key in resource_type.condition_keys:
                                    # Resource condition keys reference service condition keys
                                    if condition_key in service_detail.condition_keys:
                                        condition_key_obj = service_detail.condition_keys[
                                            condition_key
                                        ]
                                        if condition_key_obj.types:
                                            return condition_key_obj.types[0]

            except Exception:  # pylint: disable=broad-exception-caught
                # If we can't look up the action, skip it
                continue

        return None

    def _types_compatible(self, operator_type: str, key_type: str) -> bool:
        """
        Check if an operator type is compatible with a key type.

        Note: String/ARN compatibility is handled separately with a warning,
        so this method returns False for that combination.

        Args:
            operator_type: Type expected by the operator
            key_type: Type of the condition key

        Returns:
            True if compatible
        """
        # Exact match
        if operator_type == key_type:
            return True

        # EpochTime can accept both Date and Numeric
        # (this is a special case mentioned in Parliament)
        if key_type == "Date" and operator_type == "Numeric":
            return True

        return False

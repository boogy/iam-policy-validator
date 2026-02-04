"""Condition key validation check - validates condition keys against AWS definitions."""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.condition_validators import has_if_exists_suffix
from iam_validator.core.models import Statement, ValidationIssue


class ConditionKeyValidationCheck(PolicyCheck):
    """Validates condition keys against AWS service definitions and global keys."""

    check_id: ClassVar[str] = "condition_key_validation"
    description: ClassVar[str] = "Validates condition keys against AWS service definitions"
    default_severity: ClassVar[str] = "error"  # Invalid condition keys are IAM policy errors

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute condition key validation on a statement."""
        issues = []

        # Get conditions from statement
        if not statement.condition:
            return issues

        # Check if global condition key warnings are enabled (default: True)
        warn_on_global_keys = config.config.get("warn_on_global_condition_keys", True)

        statement_sid = statement.sid
        line_number = statement.line_number
        actions = statement.get_actions()
        resources = statement.get_resources()

        # Extract all condition keys from all condition operators
        for operator, conditions in statement.condition.items():
            operator_has_ifexists = has_if_exists_suffix(operator)

            for condition_key in conditions.keys():
                key_valid_for_any_action = False
                key_invalid_actions: list[tuple] = []
                first_warning_result = None

                # Validate this condition key against each action in the statement
                for action in actions:
                    # Skip wildcard actions
                    if action == "*":
                        continue

                    # Validate against action and resource types
                    result = await fetcher.validate_condition_key(action, condition_key, resources)

                    if result.is_valid:
                        key_valid_for_any_action = True
                        if result.warning_message and first_warning_result is None:
                            first_warning_result = (action, result)
                    else:
                        key_invalid_actions.append((action, result))

                # If IfExists is used and the key is valid for at least one action,
                # suppress errors for actions that don't support it.
                # Warnings (global key usage) are still reported.
                if operator_has_ifexists and key_valid_for_any_action:
                    if first_warning_result and warn_on_global_keys:
                        action, result = first_warning_result
                        warning_msg = result.warning_message or ""
                        issues.append(
                            ValidationIssue(
                                severity="warning",
                                statement_sid=statement_sid,
                                statement_index=statement_idx,
                                issue_type="global_condition_key_with_action_specific",
                                message=warning_msg,
                                action=action,
                                condition_key=condition_key,
                                line_number=line_number,
                                field_name="condition",
                            )
                        )
                    continue  # Skip error reporting

                # Report errors (first invalid action)
                if key_invalid_actions:
                    action, result = key_invalid_actions[0]
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="invalid_condition_key",
                            message=result.error_message
                            or f"Invalid condition key: `{condition_key}`",
                            action=action,
                            condition_key=condition_key,
                            line_number=line_number,
                            suggestion=result.suggestion,
                            field_name="condition",
                        )
                    )
                    continue

                # Report warnings for valid keys (no IfExists suppression path)
                if first_warning_result and warn_on_global_keys:
                    action, result = first_warning_result
                    warning_msg = result.warning_message or ""
                    issues.append(
                        ValidationIssue(
                            severity="warning",
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="global_condition_key_with_action_specific",
                            message=warning_msg,
                            action=action,
                            condition_key=condition_key,
                            line_number=line_number,
                            field_name="condition",
                        )
                    )

        return issues

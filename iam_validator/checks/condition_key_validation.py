"""Condition key validation check - validates condition keys against AWS definitions."""

from collections import defaultdict
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
                            message=result.error_message or f"Invalid condition key: `{condition_key}`",
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

        return self._aggregate_invalid_key_issues(issues)

    @staticmethod
    def _condition_key_base(condition_key: str) -> str:
        """Extract base pattern for grouping (e.g., 'aws:RequestTag/owner' -> 'aws:RequestTag').

        Keys with the same base pattern share the same underlying reason for being
        invalid, so they can be merged into a single issue.
        """
        slash_idx = condition_key.find("/")
        if slash_idx > 0:
            return condition_key[:slash_idx]
        return condition_key

    @staticmethod
    def _extract_explanation(message: str) -> str:
        """Extract the explanation part from an error message, after the key-specific prefix.

        Error messages follow the pattern:
          "Condition key `X` is not supported by action `Y`. <explanation>"

        Returns the explanation part, or empty string if not found.
        """
        # Split after the first sentence (which names the specific key)
        dot_space_idx = message.find(". ")
        if dot_space_idx > 0:
            return message[dot_space_idx + 2 :]
        return ""

    def _aggregate_invalid_key_issues(self, issues: list[ValidationIssue]) -> list[ValidationIssue]:
        """Aggregate invalid_condition_key issues that share the same action and key pattern.

        Multiple condition keys failing for the same action and same reason (e.g.,
        aws:RequestTag/owner, aws:RequestTag/jira, aws:RequestTag/env all unsupported
        by lambda:AddPermission) are merged into a single issue listing all keys.
        """
        invalid_key_issues = [i for i in issues if i.issue_type == "invalid_condition_key"]
        other_issues = [i for i in issues if i.issue_type != "invalid_condition_key"]

        if len(invalid_key_issues) <= 1:
            return issues

        # Group by (action, condition_key_base_pattern)
        grouped: dict[tuple[str | None, str], list[ValidationIssue]] = defaultdict(list)
        for issue in invalid_key_issues:
            base = self._condition_key_base(issue.condition_key or "")
            key = (issue.action, base)
            grouped[key].append(issue)

        aggregated = []
        for group in grouped.values():
            if len(group) == 1:
                aggregated.append(group[0])
            else:
                aggregated.append(self._merge_condition_key_issues(group))

        return other_issues + aggregated

    @staticmethod
    def _merge_condition_key_issues(group: list[ValidationIssue]) -> ValidationIssue:
        """Merge multiple invalid_condition_key issues into a single aggregated issue."""
        first = group[0]
        keys = [i.condition_key for i in group if i.condition_key]
        keys_formatted = ", ".join(f"`{k}`" for k in keys)

        # Build aggregated message: list all keys, then shared explanation
        message = f"Condition keys {keys_formatted} are not supported by action `{first.action}`."
        explanation = ConditionKeyValidationCheck._extract_explanation(first.message or "")
        if explanation:
            message += f" {explanation}"

        return ValidationIssue(
            severity=first.severity,
            statement_sid=first.statement_sid,
            statement_index=first.statement_index,
            issue_type="invalid_condition_key",
            message=message,
            action=first.action,
            condition_key=keys[0] if keys else None,
            line_number=first.line_number,
            suggestion=first.suggestion,
            field_name="condition",
        )

"""NotAction/NotResource check - detects dangerous Not* patterns in IAM policies.

NotAction and NotResource are powerful IAM features that can be misused to
grant overly broad permissions. This check detects patterns that violate
the principle of least privilege.
"""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


def _format_list_with_backticks(items: list[str], max_items: int = 3) -> str:
    """Format a list of items with backticks for markdown rendering."""
    formatted = [f"`{item}`" for item in items[:max_items]]
    suffix = "..." if len(items) > max_items else ""
    return ", ".join(formatted) + suffix


class NotActionNotResourceCheck(PolicyCheck):
    """Checks for dangerous NotAction/NotResource patterns.

    Patterns detected:
    1. NotAction with Effect: Allow - grants everything EXCEPT listed actions
    2. NotResource with wildcards - grants access to all resources except listed
    3. NotAction in Allow without strict conditions - missing safeguards

    These patterns are particularly dangerous because they grant permissions
    by exclusion rather than explicit inclusion, making it easy to accidentally
    grant more access than intended.
    """

    check_id: ClassVar[str] = "not_action_not_resource"
    description: ClassVar[str] = "Checks for dangerous NotAction/NotResource patterns"
    default_severity: ClassVar[str] = "high"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute NotAction/NotResource check on a statement."""
        del fetcher  # Unused

        issues = []

        not_actions = statement.get_not_actions()
        not_resources = statement.get_not_resources()
        effect = statement.effect

        # Check 1: NotAction with Effect: Allow
        # This grants ALL actions EXCEPT the listed ones - extremely dangerous
        if not_actions and effect == "Allow":
            has_conditions = bool(statement.condition)

            if has_conditions:
                # NotAction with conditions is still risky but less severe
                issues.append(
                    ValidationIssue(
                        severity="medium",
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="not_action_allow",
                        message=(
                            "Statement uses `NotAction` with `Allow` effect. "
                            "This grants ALL actions except the listed ones. "
                            "While conditions are present, this pattern is still risky."
                        ),
                        suggestion=(
                            "Consider using explicit `Action` lists instead of `NotAction`. "
                            "If `NotAction` is required, ensure conditions are comprehensive."
                        ),
                        example='{\n  "Effect": "Allow",\n  "Action": ["s3:GetObject", "s3:ListBucket"],\n  "Resource": "*"\n}',
                        line_number=statement.line_number,
                        field_name="action",
                        action=_format_list_with_backticks(not_actions, 3),
                    )
                )
            else:
                # NotAction Allow without conditions is critical
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="not_action_allow_no_condition",
                        message=(
                            "Statement uses `NotAction` with `Allow` effect and NO conditions. "
                            f"This grants ALL AWS actions except: {_format_list_with_backticks(not_actions, 5)}. "
                            "This is equivalent to granting near-administrator access."
                        ),
                        suggestion=(
                            "Replace `NotAction` with explicit `Action` list. "
                            "If `NotAction` is required, add strict conditions like "
                            "`aws:SourceIp`, `aws:PrincipalArn`, or `aws:MultiFactorAuthPresent`."
                        ),
                        example='{\n  "Effect": "Allow",\n  "Action": ["specific:Action"],\n  "Resource": "*",\n  "Condition": {\n    "Bool": {"aws:MultiFactorAuthPresent": "true"}\n  }\n}',
                        line_number=statement.line_number,
                        field_name="action",
                        action=_format_list_with_backticks(not_actions, 3),
                    )
                )

        # Check 2: NotResource with wildcards or broad patterns
        if not_resources and effect == "Allow":
            # Check if NotResource is used with wildcard Resource
            resources = statement.get_resources()
            has_wildcard_resource = "*" in resources or any("*" in r for r in resources)

            if has_wildcard_resource or not resources:
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="not_resource_broad",
                        message=(
                            "Statement uses `NotResource` with `Allow` effect and broad `Resource`. "
                            f"This grants access to ALL resources except: {_format_list_with_backticks(not_resources, 3)}."
                        ),
                        suggestion=(
                            "Replace `NotResource` with explicit `Resource` ARNs. "
                            "Using `NotResource` grants access to all current and future resources "
                            "except those explicitly excluded."
                        ),
                        example='{\n  "Effect": "Allow",\n  "Action": ["s3:GetObject"],\n  "Resource": "arn:aws:s3:::my-bucket/*"\n}',
                        line_number=statement.line_number,
                        field_name="resource",
                        resource=_format_list_with_backticks(not_resources, 3),
                    )
                )

        # Check 3: Combined NotAction AND NotResource with Allow
        # This is the most dangerous pattern - grants nearly all actions on nearly all resources
        if not_actions and not_resources and effect == "Allow":
            issues.append(
                ValidationIssue(
                    severity="critical",
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="combined_not_action_not_resource",
                    message=(
                        "**CRITICAL:** Policy uses both `NotAction` AND `NotResource` with `Allow` effect. "
                        f"This grants ALL actions except [{_format_list_with_backticks(not_actions, 3)}] "
                        f"on ALL resources except [{_format_list_with_backticks(not_resources, 3)}]. "
                        "This is equivalent to near-administrator access."
                    ),
                    suggestion=(
                        "Rewrite using explicit `Action` and `Resource` lists instead of negations. "
                        "The combination of `NotAction` + `NotResource` is almost always a mistake."
                    ),
                    example='{\n  "Effect": "Allow",\n  "Action": ["specific:Action"],\n  "Resource": "arn:aws:service:::specific-resource"\n}',
                    line_number=statement.line_number,
                    field_name="action",
                    action=_format_list_with_backticks(not_actions, 3),
                    resource=_format_list_with_backticks(not_resources, 3),
                )
            )

        # Check 4: NotAction with Deny - less dangerous but worth noting
        # NotAction with Deny means "deny everything except these actions"
        # which is actually a valid deny pattern but should be reviewed
        if not_actions and effect == "Deny":
            resources = statement.get_resources()
            has_wildcard_resource = "*" in resources

            if has_wildcard_resource:
                issues.append(
                    ValidationIssue(
                        severity="low",
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="not_action_deny_review",
                        message=(
                            "Statement uses `NotAction` with `Deny` effect on all resources. "
                            f"This denies everything except: {_format_list_with_backticks(not_actions, 5)}. "
                            "Review to ensure this is the intended behavior."
                        ),
                        suggestion=(
                            "Verify that allowing only these specific actions is intended. "
                            "Consider if an explicit `Allow` list would be clearer."
                        ),
                        line_number=statement.line_number,
                        field_name="action",
                        action=_format_list_with_backticks(not_actions, 3),
                    )
                )

        return issues

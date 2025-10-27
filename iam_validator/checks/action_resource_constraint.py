"""Action resource constraint check - validates resource constraints for actions.

This check ensures that:
- Actions WITHOUT required resource types (empty or missing Resources field in AWS API)
  MUST use Resource: "*" because they are account-level operations

Examples of actions without required resources:
- s3:ListAllMyBuckets (lists all buckets in account)
- iam:ListRoles (lists all roles in account)
- ec2:DescribeInstances (describes instances across all regions)

These actions cannot target specific resources because they operate at the account level.
"""

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class ActionResourceConstraintCheck(PolicyCheck):
    """Validates resource constraints based on action requirements.
    This check ensures that actions without required resource types use Resource: "*".

    Examples of such actions include s3:ListAllMyBuckets, iam:ListRoles, etc.
    """

    @property
    def check_id(self) -> str:
        return "action_resource_constraint"

    @property
    def description(self) -> str:
        return "Validates that actions without required resource types use Resource: '*'"

    @property
    def default_severity(self) -> str:
        return "error"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute action resource constraint validation on a statement."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        # Get actions and resources from statement
        actions = statement.get_actions()
        resources = statement.get_resources()
        statement_sid = statement.sid
        line_number = statement.line_number

        # Skip if no actions or wildcard action
        if not actions or "*" in actions:
            return issues

        # Skip if already using wildcard resource (this is correct for these actions)
        if "*" in resources:
            return issues

        # Check each action for resource requirements
        actions_without_required_resources = []

        for action in actions:
            # Skip wildcard actions
            if "*" in action:
                continue

            try:
                # Parse action to get service and action name
                service_prefix, action_name = fetcher.parse_action(action)

                # Fetch service detail to check resource requirements
                service_detail = await fetcher.fetch_service_by_name(service_prefix)

                # Check if action exists
                if action_name not in service_detail.actions:
                    # Action doesn't exist - skip (will be caught by action_validation_check)
                    continue

                action_detail = service_detail.actions[action_name]

                # Check if action has NO required resources (empty or missing Resources field)
                has_no_required_resources = (
                    not action_detail.resources or len(action_detail.resources) == 0
                )

                if has_no_required_resources:
                    actions_without_required_resources.append(action)

            except ValueError:
                # Invalid action format - skip (will be caught by action_validation_check)
                continue
            except Exception:
                # Service not found or other error - skip
                continue

        # If we found actions without required resources, report the issue
        if actions_without_required_resources:
            # Get a sample of the resources to show in error message
            resource_sample = resources[:3] if len(resources) > 3 else resources
            resource_display = ", ".join(f'"{r}"' for r in resource_sample)
            if len(resources) > 3:
                resource_display += f", ... ({len(resources) - 3} more)"

            # Format action list
            action_list = ", ".join(f'"{a}"' for a in actions_without_required_resources)

            # Determine message based on how many actions are affected
            if len(actions_without_required_resources) == 1:
                message = (
                    f"Action {action_list} does not operate on specific resources "
                    f'and requires Resource: "*"'
                )
                suggestion = (
                    f"Action {action_list} is an account-level operation that cannot target "
                    'specific resources. Move this action to a separate statement with Resource: "*", '
                    "and keep resource-specific actions in another statement with their specific ARNs"
                )
            else:
                message = (
                    f"Actions {action_list} do not operate on specific resources "
                    f'and require Resource: "*"'
                )
                suggestion = (
                    "These actions are account-level operations that cannot target "
                    'specific resources. Move these actions to a dedicated statement with Resource: "*", '
                    "and keep resource-specific actions in separate statements with their specific ARNs"
                )

            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),
                    statement_sid=statement_sid,
                    statement_index=statement_idx,
                    issue_type="invalid_resource_constraint",
                    message=message,
                    action=action_list,
                    resource=resource_display,
                    suggestion=suggestion,
                    line_number=line_number,
                )
            )

        return issues

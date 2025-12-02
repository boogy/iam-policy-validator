"""Service wildcard check - detects service-level wildcards like 'iam:*', 's3:*'."""

from typing import ClassVar

from iam_validator.checks.utils.action_parser import parse_action
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class ServiceWildcardCheck(PolicyCheck):
    """Checks for service-level wildcards (e.g., 'iam:*', 's3:*') which grant all permissions for a service."""

    check_id: ClassVar[str] = "service_wildcard"
    description: ClassVar[str] = "Checks for service-level wildcards (e.g., 'iam:*', 's3:*')"
    default_severity: ClassVar[str] = "high"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute service wildcard check on a statement."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        actions = statement.get_actions()
        allowed_services = self._get_allowed_service_wildcards(config)

        for action in actions:
            # Skip full wildcard (covered by wildcard_action check)
            if action == "*":
                continue

            # Parse action and check if it's a service-level wildcard (e.g., "iam:*", "s3:*")
            parsed = parse_action(action)
            if parsed and parsed.action_name == "*":
                service = parsed.service

                # Check if this service is in the allowed list
                if service not in allowed_services:
                    # Get message template and replace placeholders
                    message_template = config.config.get(
                        "message",
                        "Service-level wildcard `{action}` grants all permissions for `{service}` service",
                    )
                    suggestion_template = config.config.get(
                        "suggestion",
                        "Consider specifying explicit actions instead of `{action}`. If you need multiple actions, list them individually or use more specific wildcards like `{service}:Get*` or `{service}:List*`.",
                    )
                    example_template = config.config.get("example", "")

                    message = message_template.format(action=action, service=service)
                    suggestion = suggestion_template.format(action=action, service=service)
                    example = (
                        example_template.format(action=action, service=service)
                        if example_template
                        else ""
                    )

                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            statement_sid=statement.sid,
                            statement_index=statement_idx,
                            issue_type="overly_permissive",
                            message=message,
                            action=action,
                            suggestion=suggestion,
                            example=example if example else None,
                            line_number=statement.line_number,
                            field_name="action",
                        )
                    )

        return issues

    def _get_allowed_service_wildcards(self, config: CheckConfig) -> set[str]:
        """
        Get list of services that are allowed to use service-level wildcards.

        This allows configuration like:
          service_wildcard:
            allowed_services:
              - "logs"        # Allow "logs:*"
              - "cloudwatch"  # Allow "cloudwatch:*"

        Returns empty set if no exceptions are configured.
        """
        allowed = config.config.get("allowed_services", [])
        if allowed and isinstance(allowed, list):
            return set(allowed)
        return set()

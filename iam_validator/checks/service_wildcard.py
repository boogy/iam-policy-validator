"""Service wildcard check - detects service-level wildcards like 'iam:*', 's3:*'."""

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class ServiceWildcardCheck(PolicyCheck):
    """Checks for service-level wildcards (e.g., 'iam:*', 's3:*') which grant all permissions for a service."""

    @property
    def check_id(self) -> str:
        return "service_wildcard"

    @property
    def description(self) -> str:
        return "Checks for service-level wildcards (e.g., 'iam:*', 's3:*')"

    @property
    def default_severity(self) -> str:
        return "high"

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

            # Check if it's a service-level wildcard (e.g., "iam:*", "s3:*")
            if ":" in action and action.endswith(":*"):
                service = action.split(":")[0]

                # Check if this service is in the allowed list
                if service not in allowed_services:
                    # Get message template and replace placeholders
                    message_template = config.config.get(
                        "message",
                        "Service-level wildcard '{action}' grants all permissions for {service} service",
                    )
                    suggestion_template = config.config.get(
                        "suggestion",
                        "Consider specifying explicit actions instead of '{action}'. If you need multiple actions, list them individually or use more specific wildcards like '{service}:Get*' or '{service}:List*'.",
                    )
                    example_template = config.config.get("example", "")

                    message = message_template.format(action=action, service=service)
                    suggestion_text = suggestion_template.format(
                        action=action, service=service
                    )
                    example = (
                        example_template.format(action=action, service=service)
                        if example_template
                        else ""
                    )

                    # Combine suggestion + example
                    suggestion = (
                        f"{suggestion_text}\nExample:\n```json\n{example}\n```"
                        if example
                        else suggestion_text
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
                            line_number=statement.line_number,
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

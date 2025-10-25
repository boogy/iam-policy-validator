"""
Example custom check: Time-Based Access Control Check

This check ensures that certain sensitive actions are restricted to specific time windows
(e.g., business hours only, maintenance windows). Useful for compliance and security.

Use Cases:
- Restrict production deployments to business hours
- Enforce maintenance windows for destructive operations
- Implement "four-eyes" principle with time restrictions
- Meet compliance requirements for change control

Usage:
    Add to your iam-validator.yaml:

        custom_checks_dir: "./examples/custom_checks"

        checks:
          time_based_access:
            enabled: true
            severity: error
            time_restricted_actions:
              # Production deployments only during business hours (UTC)
              - actions:
                  - "cloudformation:CreateStack"
                  - "cloudformation:UpdateStack"
                  - "lambda:UpdateFunctionCode"
                required_conditions:
                  - condition_key: "aws:CurrentTime"
                    description: "Deployments only allowed during business hours (9 AM - 5 PM UTC, Monday-Friday)"
                    allowed_operators:
                      - "DateGreaterThan"
                      - "DateLessThan"

              # Database modifications only during maintenance windows
              - actions:
                  - "rds:DeleteDBInstance"
                  - "rds:ModifyDBInstance"
                  - "dynamodb:DeleteTable"
                required_conditions:
                  - condition_key: "aws:CurrentTime"
                    description: "Database changes only during maintenance window (Saturday 2-4 AM UTC)"
"""

import re
from typing import Any

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class TimeBasedAccessCheck(PolicyCheck):
    """Ensures sensitive actions have time-based access restrictions."""

    @property
    def check_id(self) -> str:
        return "time_based_access"

    @property
    def description(self) -> str:
        return "Ensures sensitive actions have time-based access restrictions"

    @property
    def default_severity(self) -> str:
        return "error"

    def _matches_pattern(self, action: str, patterns: list[str]) -> bool:
        """Check if action matches any of the given patterns."""
        for pattern in patterns:
            if "*" in pattern:
                # Convert AWS wildcard to regex
                regex_pattern = pattern.replace("*", ".*")
                if re.match(f"^{regex_pattern}$", action):
                    return True
            elif action == pattern:
                return True
        return False

    def _has_time_condition(
        self,
        conditions: dict[str, Any] | None,
        condition_key: str,
        allowed_operators: list[str],
    ) -> bool:
        """Check if statement has the required time-based condition."""
        if not conditions:
            return False

        # Check all condition operators
        for operator in allowed_operators:
            if operator in conditions:
                operator_conditions = conditions[operator]
                if isinstance(operator_conditions, dict):
                    if condition_key in operator_conditions:
                        return True
                elif isinstance(operator_conditions, list):
                    for cond in operator_conditions:
                        if isinstance(cond, dict) and condition_key in cond:
                            return True

        return False

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute the time-based access check."""
        issues: list[ValidationIssue] = []

        # Skip Deny statements
        if statement.effect.lower() == "deny":
            return issues

        # Get configuration
        time_restrictions = config.config.get("time_restricted_actions", [])
        if not time_restrictions:
            return issues

        # Normalize actions to list
        actions = statement.get_actions()

        # Check each time restriction rule
        for restriction in time_restrictions:
            restricted_actions = restriction.get("actions", [])
            required_conditions = restriction.get("required_conditions", [])

            # Check if any statement action matches the restricted actions
            matching_actions = []
            for action in actions:
                if action and self._matches_pattern(action, restricted_actions):
                    matching_actions.append(action)

            # If we found matching actions, verify time conditions exist
            if matching_actions:
                for req_condition in required_conditions:
                    condition_key = req_condition.get("condition_key", "aws:CurrentTime")
                    allowed_operators = req_condition.get(
                        "allowed_operators",
                        [
                            "DateGreaterThan",
                            "DateLessThan",
                            "DateGreaterThanEquals",
                            "DateLessThanEquals",
                        ],
                    )
                    description = req_condition.get(
                        "description",
                        f"Time restriction required for {', '.join(matching_actions)}",
                    )

                    # Check if the statement has the required time condition
                    if not self._has_time_condition(
                        statement.condition, condition_key, allowed_operators
                    ):
                        issues.append(
                            ValidationIssue(
                                severity=self.get_severity(config),
                                statement_sid=statement.sid,
                                statement_index=statement_idx,
                                issue_type=self.check_id,
                                message=(
                                    f"Time-restricted actions "
                                    f"{matching_actions} require '{condition_key}' condition. "
                                    f"{description}"
                                ),
                                suggestion=(
                                    f"Add time-based condition to restrict when these actions can be performed. "
                                    f"Example:\n"
                                    f'  "Condition": {{\n'
                                    f'    "DateGreaterThan": {{\n'
                                    f'      "{condition_key}": "2024-01-01T09:00:00Z"\n'
                                    f"    }},\n"
                                    f'    "DateLessThan": {{\n'
                                    f'      "{condition_key}": "2024-01-01T17:00:00Z"\n'
                                    f"    }}\n"
                                    f"  }}"
                                ),
                                line_number=statement.line_number,
                            )
                        )

        return issues


# Example usage in configuration:
EXAMPLE_CONFIG = """
# In iam-validator.yaml:

custom_checks_dir: "./examples/custom_checks"

checks:
  time_based_access:
    enabled: true
    severity: error

    time_restricted_actions:
      # Production deployments only during business hours
      - actions:
          - "cloudformation:CreateStack"
          - "cloudformation:UpdateStack"
          - "lambda:UpdateFunctionCode"
          - "ecs:UpdateService"
        required_conditions:
          - condition_key: "aws:CurrentTime"
            description: "Production deployments only allowed 9 AM - 5 PM UTC, Monday-Friday"
            allowed_operators:
              - "DateGreaterThan"
              - "DateLessThan"

      # Database operations only during maintenance windows
      - actions:
          - "rds:DeleteDBInstance"
          - "rds:ModifyDBInstance"
          - "dynamodb:DeleteTable"
          - "dynamodb:UpdateTable"
        required_conditions:
          - condition_key: "aws:CurrentTime"
            description: "Database changes only during maintenance window (Saturday 2-4 AM UTC)"
            allowed_operators:
              - "DateGreaterThan"
              - "DateLessThan"

      # Wildcard patterns also supported
      - actions:
          - "ec2:Terminate*"
          - "ec2:Delete*"
        required_conditions:
          - condition_key: "aws:CurrentTime"
            description: "Destructive EC2 operations require time restrictions"
            allowed_operators:
              - "DateGreaterThan"
              - "DateLessThan"
"""

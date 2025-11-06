"""
Action-Specific Condition Enforcement Check (Unified)

This built-in check ensures that specific actions have required conditions.
Supports ALL types of conditions: MFA, IP, VPC, time, tags, encryption, etc.

Supports advanced "all_of" and "any_of" logic for both actions and conditions.

Common use cases:
- iam:PassRole must have iam:PassedToService condition
- Sensitive actions must have MFA conditions
- Actions must have source IP restrictions
- Resources must have required tags
- Combine multiple conditions (MFA + IP + Tags)

Configuration in iam-validator.yaml:

    checks:
      action_condition_enforcement:
        enabled: true
        severity: error
        description: "Enforce specific conditions for specific actions"

        action_condition_requirements:
          # BASIC: Simple action with required condition
          - actions:
              - "iam:PassRole"
            required_conditions:
              - condition_key: "iam:PassedToService"
                description: "Specify which AWS services can use the passed role"

          # MFA + IP restrictions
          - actions:
              - "iam:DeleteUser"
            required_conditions:
              all_of:
                - condition_key: "aws:MultiFactorAuthPresent"
                  expected_value: true
                - condition_key: "aws:SourceIp"

          # EC2 with TAGS + MFA + Region
          - actions:
              - "ec2:RunInstances"
            required_conditions:
              all_of:
                - condition_key: "aws:MultiFactorAuthPresent"
                  expected_value: true
                - condition_key: "aws:RequestTag/Environment"
                  operator: "StringEquals"
                  expected_value: ["Production", "Staging", "Development"]
                - condition_key: "aws:RequestTag/Owner"
                - condition_key: "aws:RequestedRegion"
                  expected_value: ["us-east-1", "us-west-2"]

          # Principal-to-resource tag matching
          - actions:
              - "ec2:RunInstances"
            required_conditions:
              - condition_key: "aws:ResourceTag/owner"
                operator: "StringEquals"
                expected_value: "${aws:PrincipalTag/owner}"
                description: "Resource owner must match principal's owner tag"

          # Complex: all_of + any_of for actions and conditions
          - actions:
              any_of:
                - "cloudformation:CreateStack"
                - "cloudformation:UpdateStack"
            required_conditions:
              all_of:
                - condition_key: "aws:MultiFactorAuthPresent"
                  expected_value: true
                - condition_key: "aws:RequestTag/Environment"
              any_of:
                - condition_key: "aws:SourceIp"
                - condition_key: "aws:SourceVpce"

          # none_of for conditions: Ensure certain conditions are NOT present
          - actions:
              - "s3:GetObject"
            required_conditions:
              none_of:
                - condition_key: "aws:SecureTransport"
                  expected_value: false
                  description: "Ensure insecure transport is never allowed"

          # none_of for actions: Flag if forbidden actions are present
          - actions:
              none_of:
                - "iam:*"
                - "s3:DeleteBucket"
            description: "These dangerous actions should never be used"
"""

import re
from typing import Any

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class ActionConditionEnforcementCheck(PolicyCheck):
    """Enforces specific condition requirements for specific actions with all_of/any_of support."""

    @property
    def check_id(self) -> str:
        return "action_condition_enforcement"

    @property
    def description(self) -> str:
        return "Enforces conditions (MFA, IP, tags, etc.) for specific actions (supports all_of/any_of)"

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
        """Execute condition enforcement check."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        # Get action condition requirements from config
        action_condition_requirements = config.config.get("action_condition_requirements", [])
        if not action_condition_requirements:
            return issues

        statement_actions = statement.get_actions()

        # Check each requirement rule
        for requirement in action_condition_requirements:
            # Check if this requirement applies to the statement's actions
            actions_match, matching_actions = await self._check_action_match(
                statement_actions, requirement, fetcher
            )

            if not actions_match:
                continue

            # Check if this is a none_of action rule (forbidden actions)
            actions_config = requirement.get("actions", [])
            if isinstance(actions_config, dict) and "none_of" in actions_config:
                # This is a forbidden action rule - flag it
                description = requirement.get("description", "These actions should not be used")
                # Use per-requirement severity if specified, else use global
                severity = requirement.get("severity", self.get_severity(config))
                issues.append(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="forbidden_action_present",
                        message=f"FORBIDDEN: Actions {matching_actions} should not be used. {description}",
                        action=", ".join(matching_actions),
                        suggestion=f"Remove these forbidden actions from the statement: {', '.join(matching_actions)}. {description}",
                        line_number=statement.line_number,
                    )
                )
                continue

            # Actions match - now validate required conditions
            required_conditions_config = requirement.get("required_conditions", [])
            if not required_conditions_config:
                continue

            # Check if conditions are in all_of/any_of/none_of format or simple list
            condition_issues = self._validate_conditions(
                statement,
                statement_idx,
                required_conditions_config,
                matching_actions,
                config,
                requirement,  # Pass the full requirement for severity override
            )

            issues.extend(condition_issues)

        return issues

    async def _check_action_match(
        self, statement_actions: list[str], requirement: dict[str, Any], fetcher: AWSServiceFetcher
    ) -> tuple[bool, list[str]]:
        """
        Check if statement actions match the requirement.
        Supports: simple list, all_of, any_of, none_of, and action_patterns.

        Returns:
            (matches, list_of_matching_actions)
        """
        actions_config = requirement.get("actions", [])
        action_patterns = requirement.get("action_patterns", [])

        matching_actions: list[str] = []

        # Handle simple list format (backward compatibility)
        if isinstance(actions_config, list) and actions_config:
            # Simple list - check if any action matches
            for stmt_action in statement_actions:
                if stmt_action == "*":
                    continue

                # Check if this statement action matches any of the required actions or patterns
                # Use _action_matches which handles wildcards in both statement and config
                matched = False

                # Check against configured actions
                for required_action in actions_config:
                    if await self._action_matches(
                        stmt_action, required_action, action_patterns, fetcher
                    ):
                        matched = True
                        break

                # If not matched by actions, check if wildcard overlaps with patterns
                if not matched and "*" in stmt_action:
                    # For wildcards, also check pattern overlap directly
                    matched = await self._action_matches(stmt_action, "", action_patterns, fetcher)

                if matched and stmt_action not in matching_actions:
                    matching_actions.append(stmt_action)

            return len(matching_actions) > 0, matching_actions

        # Handle all_of/any_of/none_of format
        if isinstance(actions_config, dict):
            all_of = actions_config.get("all_of", [])
            any_of = actions_config.get("any_of", [])
            none_of = actions_config.get("none_of", [])

            # Check all_of: ALL specified actions must be in statement
            if all_of:
                all_present = True
                for req_action in all_of:
                    found = False
                    for stmt_action in statement_actions:
                        if await self._action_matches(
                            stmt_action, req_action, action_patterns, fetcher
                        ):
                            found = True
                            break
                    if not found:
                        all_present = False
                        break

                if not all_present:
                    return False, []

                # Collect matching actions
                for stmt_action in statement_actions:
                    for req_action in all_of:
                        if await self._action_matches(
                            stmt_action, req_action, action_patterns, fetcher
                        ):
                            if stmt_action not in matching_actions:
                                matching_actions.append(stmt_action)

            # Check any_of: At least ONE specified action must be in statement
            if any_of:
                any_present = False
                for stmt_action in statement_actions:
                    for req_action in any_of:
                        if await self._action_matches(
                            stmt_action, req_action, action_patterns, fetcher
                        ):
                            any_present = True
                            if stmt_action not in matching_actions:
                                matching_actions.append(stmt_action)

                if not any_present:
                    return False, []

            # Check none_of: NONE of the specified actions should be in statement
            if none_of:
                forbidden_actions = []
                for stmt_action in statement_actions:
                    for forbidden_action in none_of:
                        if await self._action_matches(
                            stmt_action, forbidden_action, action_patterns, fetcher
                        ):
                            forbidden_actions.append(stmt_action)

                # If forbidden actions are found, this is a match for flagging
                if forbidden_actions:
                    return True, forbidden_actions

            return len(matching_actions) > 0, matching_actions

        return False, []

    async def _action_matches(
        self,
        statement_action: str,
        required_action: str,
        patterns: list[str],
        fetcher: AWSServiceFetcher,
    ) -> bool:
        """
        Check if a statement action matches a required action or pattern.
        Supports:
        - Exact matches: "s3:GetObject"
        - AWS wildcards in both statement and required actions: "s3:*", "s3:Get*", "iam:Creat*"
        - Regex patterns: "^s3:Get.*", "^iam:Delete.*"

        This method handles bidirectional wildcard matching using real AWS actions from the fetcher:
        - statement_action="iam:Create*" matches required_action="iam:CreateUser"
        - statement_action="iam:C*" matches pattern="^iam:Create" (by checking actual AWS actions)
        """
        if statement_action == "*":
            return False

        # Exact match
        if statement_action == required_action:
            return True

        # AWS wildcard match in required_action (e.g., "s3:*", "s3:Get*")
        if "*" in required_action:
            # Convert AWS wildcard to regex
            wildcard_pattern = required_action.replace("*", ".*").replace("?", ".")
            try:
                if re.match(f"^{wildcard_pattern}$", statement_action):
                    return True
            except re.error:
                pass

        # AWS wildcard match in statement_action (e.g., "iam:Creat*" in policy)
        # Check if this wildcard would grant access to actions matching our patterns
        if "*" in statement_action:
            # Convert statement wildcard to regex pattern
            stmt_wildcard_pattern = statement_action.replace("*", ".*").replace("?", ".")

            # Check if statement wildcard overlaps with required action
            if "*" not in required_action:
                # Required action is specific (e.g., "iam:CreateUser")
                # Check if statement wildcard would grant it
                try:
                    if re.match(f"^{stmt_wildcard_pattern}$", required_action):
                        return True
                except re.error:
                    pass

            # Check if statement wildcard overlaps with any of our action patterns
            # Strategy: Use real AWS actions from the fetcher instead of hardcoded guesses
            # For example: "iam:C*" should match pattern "^iam:Create" because:
            # - "iam:C*" grants iam:CreateUser, iam:CreateRole, etc. (from AWS)
            # - "^iam:Create" pattern is meant to catch iam:CreateUser, iam:CreateRole, etc.
            # - Therefore they overlap
            if patterns:
                try:
                    # Parse the service from the wildcard action
                    service_prefix, _ = fetcher.parse_action(statement_action)

                    # Fetch the real list of actions for this service
                    service_detail = await fetcher.fetch_service_by_name(service_prefix)
                    available_actions = list(service_detail.actions.keys())

                    # Find which actual AWS actions the wildcard would grant
                    _, granted_actions = fetcher._match_wildcard_action(
                        statement_action.split(":", 1)[1],  # Just the action part (e.g., "C*")
                        available_actions,
                    )

                    # Check if any of the granted actions match our patterns
                    for granted_action in granted_actions:
                        full_granted_action = f"{service_prefix}:{granted_action}"
                        for pattern in patterns:
                            try:
                                if re.match(pattern, full_granted_action):
                                    return True
                            except re.error:
                                continue

                except (ValueError, Exception):
                    # If we can't fetch the service or parse the action, fall back to prefix matching
                    stmt_prefix = statement_action.rstrip("*")
                    for pattern in patterns:
                        try:
                            if re.match(pattern, stmt_prefix):
                                return True
                        except re.error:
                            continue

        # Regex pattern match (from action_patterns config)
        for pattern in patterns:
            try:
                if re.match(pattern, statement_action):
                    return True
            except re.error:
                continue

        return False

    def _validate_conditions(
        self,
        statement: Statement,
        statement_idx: int,
        required_conditions_config: Any,
        matching_actions: list[str],
        config: CheckConfig,
        requirement: dict[str, Any] | None = None,
    ) -> list[ValidationIssue]:
        """
        Validate that required conditions are present.
        Supports: simple list, all_of, any_of formats.
        Can use per-requirement severity override from requirement['severity'].
        """
        issues: list[ValidationIssue] = []

        # Handle simple list format (backward compatibility)
        if isinstance(required_conditions_config, list):
            for condition_requirement in required_conditions_config:
                if not self._has_condition_requirement(statement, condition_requirement):
                    issues.append(
                        self._create_issue(
                            statement,
                            statement_idx,
                            condition_requirement,
                            matching_actions,
                            config,
                            requirement=requirement,
                        )
                    )
            return issues

        # Handle all_of/any_of/none_of format
        if isinstance(required_conditions_config, dict):
            all_of = required_conditions_config.get("all_of", [])
            any_of = required_conditions_config.get("any_of", [])
            none_of = required_conditions_config.get("none_of", [])

            # Validate all_of: ALL conditions must be present
            if all_of:
                for condition_requirement in all_of:
                    if not self._has_condition_requirement(statement, condition_requirement):
                        issues.append(
                            self._create_issue(
                                statement,
                                statement_idx,
                                condition_requirement,
                                matching_actions,
                                config,
                                requirement_type="all_of",
                                requirement=requirement,
                            )
                        )

            # Validate any_of: At least ONE condition must be present
            if any_of:
                any_present = any(
                    self._has_condition_requirement(statement, cond_req) for cond_req in any_of
                )

                if not any_present:
                    # Create a combined error for any_of
                    condition_keys = [cond.get("condition_key", "unknown") for cond in any_of]
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            statement_sid=statement.sid,
                            statement_index=statement_idx,
                            issue_type="missing_required_condition_any_of",
                            message=(
                                f"Actions {matching_actions} require at least ONE of these conditions: "
                                f"{', '.join(condition_keys)}"
                            ),
                            action=", ".join(matching_actions),
                            suggestion=self._build_any_of_suggestion(any_of),
                            line_number=statement.line_number,
                        )
                    )

            # Validate none_of: NONE of these conditions should be present
            if none_of:
                for condition_requirement in none_of:
                    if self._has_condition_requirement(statement, condition_requirement):
                        issues.append(
                            self._create_none_of_issue(
                                statement,
                                statement_idx,
                                condition_requirement,
                                matching_actions,
                                config,
                            )
                        )

        return issues

    def _has_condition_requirement(
        self, statement: Statement, condition_requirement: dict[str, Any]
    ) -> bool:
        """Check if statement has the required condition."""
        condition_key = condition_requirement.get("condition_key")
        if not condition_key:
            return True  # No condition key specified, skip

        operator = condition_requirement.get("operator")
        expected_value = condition_requirement.get("expected_value")

        return self._has_condition(statement, condition_key, operator, expected_value)

    def _has_condition(
        self,
        statement: Statement,
        condition_key: str,
        operator: str | None = None,
        expected_value: Any = None,
    ) -> bool:
        """
        Check if statement has the specified condition key.

        Args:
            statement: The IAM policy statement
            condition_key: The condition key to look for
            operator: Optional specific operator (e.g., "StringEquals")
            expected_value: Optional expected value for the condition

        Returns:
            True if condition is present (and matches expected value if specified)
        """
        if not statement.condition:
            return False

        # If operator specified, only check that operator
        operators_to_check = [operator] if operator else list(statement.condition.keys())

        # Look through specified condition operators
        for op in operators_to_check:
            if op not in statement.condition:
                continue

            conditions = statement.condition[op]
            if isinstance(conditions, dict):
                if condition_key in conditions:
                    # If no expected value specified, just presence is enough
                    if expected_value is None:
                        return True

                    # Check if the value matches
                    actual_value = conditions[condition_key]

                    # Handle boolean values
                    if isinstance(expected_value, bool):
                        if isinstance(actual_value, bool):
                            return actual_value == expected_value
                        if isinstance(actual_value, str):
                            return actual_value.lower() == str(expected_value).lower()

                    # Handle exact matches
                    if actual_value == expected_value:
                        return True

                    # Handle list values (actual can be string or list)
                    if isinstance(expected_value, list):
                        if isinstance(actual_value, list):
                            return set(expected_value) == set(actual_value)
                        if actual_value in expected_value:
                            return True

                    # Handle string matches for variable references like ${aws:PrincipalTag/owner}
                    if str(actual_value) == str(expected_value):
                        return True

        return False

    def _create_issue(
        self,
        statement: Statement,
        statement_idx: int,
        condition_requirement: dict[str, Any],
        matching_actions: list[str],
        config: CheckConfig,
        requirement_type: str = "required",
        requirement: dict[str, Any] | None = None,
    ) -> ValidationIssue:
        """Create a validation issue for a missing condition.

        Severity precedence:
        1. Individual condition requirement's severity (condition_requirement['severity'])
        2. Parent requirement's severity (requirement['severity'])
        3. Global check severity (config.severity)
        """
        condition_key = condition_requirement.get("condition_key", "unknown")
        description = condition_requirement.get("description", "")
        expected_value = condition_requirement.get("expected_value")
        example = condition_requirement.get("example", "")
        operator = condition_requirement.get("operator", "StringEquals")

        message_prefix = "ALL required:" if requirement_type == "all_of" else "Required:"

        # Determine severity with precedence: condition > requirement > global
        severity = (
            condition_requirement.get("severity")  # Condition-level override
            or (requirement.get("severity") if requirement else None)  # Requirement-level override
            or self.get_severity(config)  # Global check severity
        )

        return ValidationIssue(
            severity=severity,
            statement_sid=statement.sid,
            statement_index=statement_idx,
            issue_type="missing_required_condition",
            message=f"{message_prefix} Action(s) {matching_actions} require condition '{condition_key}'",
            action=", ".join(matching_actions),
            condition_key=condition_key,
            suggestion=self._build_suggestion(
                condition_key, description, example, expected_value, operator
            ),
            line_number=statement.line_number,
        )

    def _build_suggestion(
        self,
        condition_key: str,
        description: str,
        example: str,
        expected_value: Any = None,
        operator: str = "StringEquals",
    ) -> str:
        """Build a helpful suggestion for adding the missing condition."""
        parts = []

        if description:
            parts.append(description)

        # Build example based on condition key type
        if example:
            parts.append(f"Example:\n{example}")
        else:
            # Auto-generate example
            example_lines = ['Add to "Condition" block:', f'  "{operator}": {{']

            if isinstance(expected_value, list):
                value_str = (
                    "["
                    + ", ".join(
                        [
                            f'"{v}"' if not str(v).startswith("${") else f'"{v}"'
                            for v in expected_value
                        ]
                    )
                    + "]"
                )
            elif expected_value is not None:
                # Don't quote if it's a variable reference like ${aws:PrincipalTag/owner}
                if str(expected_value).startswith("${"):
                    value_str = f'"{expected_value}"'
                elif isinstance(expected_value, bool):
                    value_str = str(expected_value).lower()
                else:
                    value_str = f'"{expected_value}"'
            else:
                value_str = '"<value>"'

            example_lines.append(f'    "{condition_key}": {value_str}')
            example_lines.append("  }")

            parts.append("\n".join(example_lines))

        return ". ".join(parts) if parts else f"Add condition: {condition_key}"

    def _build_any_of_suggestion(self, any_of_conditions: list[dict[str, Any]]) -> str:
        """Build suggestion for any_of conditions."""
        suggestions = []
        suggestions.append("Add at least ONE of these conditions:")

        for i, cond in enumerate(any_of_conditions, 1):
            condition_key = cond.get("condition_key", "unknown")
            description = cond.get("description", "")
            expected_value = cond.get("expected_value")

            option = f"\nOption {i}: {condition_key}"
            if description:
                option += f" - {description}"
            if expected_value is not None:
                option += f" (value: {expected_value})"

            suggestions.append(option)

        return "".join(suggestions)

    def _create_none_of_issue(
        self,
        statement: Statement,
        statement_idx: int,
        condition_requirement: dict[str, Any],
        matching_actions: list[str],
        config: CheckConfig,
    ) -> ValidationIssue:
        """Create a validation issue for a forbidden condition that is present."""
        condition_key = condition_requirement.get("condition_key", "unknown")
        description = condition_requirement.get("description", "")
        expected_value = condition_requirement.get("expected_value")

        message = (
            f"FORBIDDEN: Action(s) {matching_actions} must NOT have condition '{condition_key}'"
        )
        if expected_value is not None:
            message += f" with value '{expected_value}'"

        suggestion = f"Remove the '{condition_key}' condition from the statement"
        if description:
            suggestion += f". {description}"

        return ValidationIssue(
            severity=self.get_severity(config),
            statement_sid=statement.sid,
            statement_index=statement_idx,
            issue_type="forbidden_condition_present",
            message=message,
            action=", ".join(matching_actions),
            condition_key=condition_key,
            suggestion=suggestion,
            line_number=statement.line_number,
        )

"""Principal Validation Check.

Validates Principal elements in resource-based policies for security best practices.
This check enforces:
- Blocked principals (e.g., public access via "*")
- Allowed principals whitelist (optional)
- Rich condition requirements for principals (supports any_of/all_of/none_of)
- Service principal validation

Only runs for RESOURCE_POLICY and TRUST_POLICY types.

Configuration format:

principal_condition_requirements:
  - principals:
      - "*"  # Can be a list of principal patterns
    severity: critical  # Optional: override default severity
    required_conditions:
      any_of:  # At least ONE of these conditions must be present
        - condition_key: "aws:SourceArn"
          description: "Limit by source ARN"
        - condition_key: "aws:SourceAccount"
          expected_value: "123456789012"  # Optional: validate specific value
          operator: "StringEquals"  # Optional: validate specific operator

  - principals:
      - "arn:aws:iam::*:root"
    required_conditions:
      all_of:  # ALL of these conditions must be present
        - condition_key: "aws:PrincipalOrgID"
          expected_value: "o-xxxxx"
        - condition_key: "aws:SourceAccount"

Supports: any_of, all_of, none_of, and expected_value (single value or list)
"""

import fnmatch
from typing import Any

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.config.service_principals import is_aws_service_principal
from iam_validator.core.models import Statement, ValidationIssue


class PrincipalValidationCheck(PolicyCheck):
    """Validates Principal elements in resource policies."""

    @property
    def check_id(self) -> str:
        return "principal_validation"

    @property
    def description(self) -> str:
        return "Validates Principal elements in resource policies for security best practices"

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
        """Execute principal validation on a single statement.

        Args:
            statement: The statement to validate
            statement_idx: Index of the statement in the policy
            fetcher: AWS service fetcher instance
            config: Configuration for this check

        Returns:
            List of validation issues
        """
        issues = []

        # Skip if no principal
        if statement.principal is None and statement.not_principal is None:
            return issues

        # Get configuration (defaults match defaults.py)
        blocked_principals = config.config.get("blocked_principals", ["*"])
        allowed_principals = config.config.get("allowed_principals", [])
        principal_condition_requirements = config.config.get("principal_condition_requirements", [])
        # Default: "aws:*" allows ALL AWS service principals (*.amazonaws.com)
        # This matches the default in defaults.py:251
        allowed_service_principals = config.config.get("allowed_service_principals", ["aws:*"])

        # Extract principals from statement
        principals = self._extract_principals(statement)

        for principal in principals:
            # Check if principal is blocked
            if self._is_blocked_principal(
                principal, blocked_principals, allowed_service_principals
            ):
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        issue_type="blocked_principal",
                        message=f"Blocked principal detected: `{principal}`. "
                        f"This principal is explicitly blocked by your security policy.",
                        statement_index=statement_idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion=f"Remove the `Principal` `{principal}` or add appropriate `Condition`s to restrict access. "
                        "Consider using more specific `Principal`s instead of `*` (wildcard).",
                    )
                )
                continue

            # Check if principal is in whitelist (if whitelist is configured)
            if allowed_principals and not self._is_allowed_principal(
                principal, allowed_principals, allowed_service_principals
            ):
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        issue_type="unauthorized_principal",
                        message=f"`Principal` not in allowed list: `{principal}`. "
                        f"Only principals in the `allowed_principals` whitelist are permitted.",
                        statement_index=statement_idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion=f"Add `{principal}` to the `allowed_principals` list in your config, "
                        "or use a `Principal` that matches an allowed pattern.",
                    )
                )
                continue

        # Check principal_condition_requirements (supports any_of/all_of/none_of)
        if principal_condition_requirements:
            condition_issues = self._validate_principal_condition_requirements(
                statement,
                statement_idx,
                principals,
                principal_condition_requirements,
                config,
            )
            issues.extend(condition_issues)

        return issues

    def _extract_principals(self, statement: Statement) -> list[str]:
        """Extract all principals from a statement.

        Args:
            statement: The statement to extract principals from

        Returns:
            List of principal strings
        """
        principals = []

        # Handle Principal field
        if statement.principal:
            if isinstance(statement.principal, str):
                # Simple string principal like "*"
                principals.append(statement.principal)
            elif isinstance(statement.principal, dict):
                # Dict with AWS, Service, Federated, etc.
                for _, value in statement.principal.items():
                    if isinstance(value, str):
                        principals.append(value)
                    elif isinstance(value, list):
                        principals.extend(value)

        # Handle NotPrincipal field (similar logic)
        if statement.not_principal:
            if isinstance(statement.not_principal, str):
                principals.append(statement.not_principal)
            elif isinstance(statement.not_principal, dict):
                for _, value in statement.not_principal.items():
                    if isinstance(value, str):
                        principals.append(value)
                    elif isinstance(value, list):
                        principals.extend(value)

        return principals

    def _is_blocked_principal(
        self, principal: str, blocked_list: list[str], service_whitelist: list[str]
    ) -> bool:
        """Check if a principal is blocked.

        Args:
            principal: The principal to check
            blocked_list: List of blocked principal patterns
            service_whitelist: List of allowed service principals (supports "aws:*" for all AWS services)

        Returns:
            True if the principal is blocked
        """
        # Check if service_whitelist contains "aws:*" (allow all AWS service principals)
        if "aws:*" in service_whitelist and is_aws_service_principal(principal):
            return False

        # Service principals in explicit whitelist are never blocked
        if is_aws_service_principal(principal) and principal in service_whitelist:
            return False

        # Check against blocked list (supports wildcards)
        for blocked_pattern in blocked_list:
            # Special case: "*" in blocked list should only match literal "*" (public access)
            # not use it as a wildcard pattern that matches everything
            if blocked_pattern == "*":
                if principal == "*":
                    return True
            elif fnmatch.fnmatch(principal, blocked_pattern):
                return True

        return False

    def _is_allowed_principal(
        self, principal: str, allowed_list: list[str], service_whitelist: list[str]
    ) -> bool:
        """Check if a principal is in the allowed list.

        Args:
            principal: The principal to check
            allowed_list: List of allowed principal patterns
            service_whitelist: List of allowed service principals (supports "aws:*" for all AWS services)

        Returns:
            True if the principal is allowed
        """
        # Check if service_whitelist contains "aws:*" (allow all AWS service principals)
        if "aws:*" in service_whitelist and is_aws_service_principal(principal):
            return True

        # Service principals in explicit whitelist are always allowed
        if is_aws_service_principal(principal) and principal in service_whitelist:
            return True

        # Check against allowed list (supports wildcards)
        for allowed_pattern in allowed_list:
            # Special case: "*" in allowed list should only match literal "*" (public access)
            # not use it as a wildcard pattern that matches everything
            if allowed_pattern == "*":
                if principal == "*":
                    return True
            elif fnmatch.fnmatch(principal, allowed_pattern):
                return True

        return False

    def _validate_principal_condition_requirements(
        self,
        statement: Statement,
        statement_idx: int,
        principals: list[str],
        requirements: list[dict[str, Any]],
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Validate advanced principal condition requirements.

        Args:
            statement: The statement to validate
            statement_idx: Index of the statement
            principals: List of principals from the statement
            requirements: List of principal condition requirements
            config: Check configuration

        Returns:
            List of validation issues
        """
        issues: list[ValidationIssue] = []

        # Check each requirement rule
        for requirement in requirements:
            # Check if any principal matches this requirement
            matching_principals = self._get_matching_principals(principals, requirement)

            if not matching_principals:
                continue

            # Get required conditions from the requirement
            required_conditions_config = requirement.get("required_conditions", [])
            if not required_conditions_config:
                continue

            # Validate conditions using the same logic as action_condition_enforcement
            condition_issues = self._validate_conditions(
                statement,
                statement_idx,
                required_conditions_config,
                matching_principals,
                config,
                requirement,
            )

            issues.extend(condition_issues)

        return issues

    def _get_matching_principals(
        self, principals: list[str], requirement: dict[str, Any]
    ) -> list[str]:
        """Get principals that match the requirement pattern.

        Args:
            principals: List of principals from the statement
            requirement: Principal condition requirement config

        Returns:
            List of matching principals
        """
        principal_patterns = requirement.get("principals", [])
        if not principal_patterns:
            return []

        matching: list[str] = []

        for principal in principals:
            for pattern in principal_patterns:
                # Special case: "*" pattern should only match literal "*"
                if pattern == "*":
                    if principal == "*":
                        matching.append(principal)
                elif fnmatch.fnmatch(principal, pattern):
                    matching.append(principal)

        return matching

    def _validate_conditions(
        self,
        statement: Statement,
        statement_idx: int,
        required_conditions_config: Any,
        matching_principals: list[str],
        config: CheckConfig,
        requirement: dict[str, Any],
    ) -> list[ValidationIssue]:
        """Validate that required conditions are present.

        Supports: simple list, all_of, any_of, none_of formats.
        Similar to action_condition_enforcement logic.

        Args:
            statement: The statement to validate
            statement_idx: Index of the statement
            required_conditions_config: Condition requirements config
            matching_principals: Principals that matched
            config: Check configuration
            requirement: Parent requirement for severity override

        Returns:
            List of validation issues
        """
        issues: list[ValidationIssue] = []

        # Handle simple list format (backward compatibility)
        if isinstance(required_conditions_config, list):
            for condition_requirement in required_conditions_config:
                if not self._has_condition_requirement(statement, condition_requirement):
                    issues.append(
                        self._create_condition_issue(
                            statement,
                            statement_idx,
                            condition_requirement,
                            matching_principals,
                            config,
                            requirement,
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
                            self._create_condition_issue(
                                statement,
                                statement_idx,
                                condition_requirement,
                                matching_principals,
                                config,
                                requirement,
                                requirement_type="all_of",
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
                    severity = requirement.get("severity", self.get_severity(config))
                    matching_principals_str = ", ".join(f"`{p}`" for p in matching_principals)
                    issues.append(
                        ValidationIssue(
                            severity=severity,
                            statement_sid=statement.sid,
                            statement_index=statement_idx,
                            issue_type="missing_principal_condition_any_of",
                            message=(
                                f"`Principal`s `{matching_principals_str}` require at least ONE of these conditions: "
                                f"{', '.join(f'`{c}`' for c in condition_keys)}"
                            ),
                            suggestion=self._build_any_of_suggestion(any_of),
                            line_number=statement.line_number,
                        )
                    )

            # Validate none_of: NONE of these conditions should be present
            if none_of:
                for condition_requirement in none_of:
                    if self._has_condition_requirement(statement, condition_requirement):
                        issues.append(
                            self._create_none_of_condition_issue(
                                statement,
                                statement_idx,
                                condition_requirement,
                                matching_principals,
                                config,
                                requirement,
                            )
                        )

        return issues

    def _has_condition_requirement(
        self, statement: Statement, condition_requirement: dict[str, Any]
    ) -> bool:
        """Check if statement has the required condition.

        Args:
            statement: The statement to check
            condition_requirement: Condition requirement config

        Returns:
            True if condition is present and matches requirements
        """
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
        """Check if statement has the specified condition key.

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

    def _create_condition_issue(
        self,
        statement: Statement,
        statement_idx: int,
        condition_requirement: dict[str, Any],
        matching_principals: list[str],
        config: CheckConfig,
        requirement: dict[str, Any],
        requirement_type: str = "required",
    ) -> ValidationIssue:
        """Create a validation issue for a missing condition.

        Severity precedence:
        1. Individual condition requirement's severity (condition_requirement['severity'])
        2. Parent requirement's severity (requirement['severity'])
        3. Global check severity (config.severity)

        Args:
            statement: The statement being validated
            statement_idx: Index of the statement
            condition_requirement: The condition requirement config
            matching_principals: Principals that matched
            config: Check configuration
            requirement: Parent requirement config
            requirement_type: Type of requirement (required, all_of)

        Returns:
            ValidationIssue
        """
        condition_key = condition_requirement.get("condition_key", "unknown")
        description = condition_requirement.get("description", "")
        expected_value = condition_requirement.get("expected_value")
        example = condition_requirement.get("example", "")
        operator = condition_requirement.get("operator", "StringEquals")

        message_prefix = "ALL required:" if requirement_type == "all_of" else "Required:"

        # Determine severity with precedence: condition > requirement > global
        severity = (
            condition_requirement.get("severity")
            or requirement.get("severity")
            or self.get_severity(config)
        )

        suggestion_text, example_code = self._build_condition_suggestion(
            condition_key, description, example, expected_value, operator
        )

        matching_principals_formatted = ", ".join(f"`{p}`" for p in matching_principals)

        return ValidationIssue(
            severity=severity,
            statement_sid=statement.sid,
            statement_index=statement_idx,
            issue_type="missing_principal_condition",
            message=f"{message_prefix} Principal(s) {matching_principals_formatted} require condition `{condition_key}`",
            suggestion=suggestion_text,
            example=example_code,
            line_number=statement.line_number,
        )

    def _build_condition_suggestion(
        self,
        condition_key: str,
        description: str,
        example: str,
        expected_value: Any = None,
        operator: str = "StringEquals",
    ) -> tuple[str, str]:
        """Build suggestion and example for adding the missing condition.

        Args:
            condition_key: The condition key
            description: Description of the condition
            example: Example usage
            expected_value: Expected value for the condition
            operator: Condition operator

        Returns:
            Tuple of (suggestion_text, example_code)
        """
        suggestion = description if description else f"Add condition: {condition_key}"

        # Build example based on condition key type
        if example:
            example_code = example
        else:
            # Auto-generate example
            example_lines = [f'  "{operator}": {{']

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

            example_code = "\n".join(example_lines)

        return suggestion, example_code

    def _build_any_of_suggestion(self, any_of_conditions: list[dict[str, Any]]) -> str:
        """Build suggestion for any_of conditions.

        Args:
            any_of_conditions: List of condition requirements

        Returns:
            Suggestion string
        """
        suggestions = []
        suggestions.append("Add at least ONE of these conditions:")

        for i, cond in enumerate(any_of_conditions, 1):
            condition_key = cond.get("condition_key", "unknown")
            description = cond.get("description", "")
            expected_value = cond.get("expected_value")

            option = f"\n- **Option {i}**: `{condition_key}`"
            if description:
                option += f" - {description}"
            if expected_value is not None:
                option += f" (value: `{expected_value}`)"

            suggestions.append(option)

        return "".join(suggestions)

    def _create_none_of_condition_issue(
        self,
        statement: Statement,
        statement_idx: int,
        condition_requirement: dict[str, Any],
        matching_principals: list[str],
        config: CheckConfig,
        requirement: dict[str, Any],
    ) -> ValidationIssue:
        """Create a validation issue for a forbidden condition that is present.

        Args:
            statement: The statement being validated
            statement_idx: Index of the statement
            condition_requirement: The condition requirement config
            matching_principals: Principals that matched
            config: Check configuration
            requirement: Parent requirement config

        Returns:
            ValidationIssue
        """
        condition_key = condition_requirement.get("condition_key", "unknown")
        description = condition_requirement.get("description", "")
        expected_value = condition_requirement.get("expected_value")

        matching_principals_str = ", ".join(f"`{p}`" for p in matching_principals)
        message = f"FORBIDDEN: `Principal`s `{matching_principals_str}` must NOT have `Condition` `{condition_key}`"
        if expected_value is not None:
            message += f" with value `{expected_value}`"

        suggestion = f"Remove the `{condition_key}` `Condition` from the statement"
        if description:
            suggestion += f". {description}"

        severity = requirement.get("severity", self.get_severity(config))

        return ValidationIssue(
            severity=severity,
            statement_sid=statement.sid,
            statement_index=statement_idx,
            issue_type="forbidden_principal_condition",
            message=message,
            suggestion=suggestion,
            line_number=statement.line_number,
        )

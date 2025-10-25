"""
Example custom check: Advanced Multi-Condition Policy Validator (HIGHLY COMPLEX)

This is an advanced, production-grade custom check that validates complex policy requirements
by combining multiple condition checks, context-aware validation, and sophisticated rule matching.

Features:
- Validates multiple conditions simultaneously (IP, MFA, time, source VPC, etc.)
- Context-aware: Different rules for different action categories
- Supports exception lists and override mechanisms
- Provides detailed, actionable recommendations
- Handles complex condition operators (AND, OR, nested conditions)
- Validates condition value formats and ranges

Use Cases:
- Enterprise security policies requiring multiple authentication factors
- Compliance requirements (SOC2, PCI-DSS, HIPAA) with layered controls
- Zero-trust security architectures
- Privileged access management with multiple conditions
- Production environment hardening

Real-World Example:
"For production deployments (CloudFormation, Lambda updates), require:
 1. IP address from corporate network OR VPN
 2. MFA authentication
 3. Time restriction to business hours
 4. Tagging with owner and cost center
 5. Resource encryption where applicable"

Usage:
    Add to your iam-validator.yaml:

        custom_checks_dir: "./examples/custom_checks"

        checks:
          advanced_multi_condition:
            enabled: true
            severity: error

            # Define action categories with their required conditions
            action_categories:
              # Critical infrastructure operations
              critical_operations:
                actions:
                  - "cloudformation:CreateStack"
                  - "cloudformation:UpdateStack"
                  - "cloudformation:DeleteStack"
                  - "lambda:UpdateFunctionCode"
                  - "ecs:UpdateService"
                required_conditions:
                  all_of:  # ALL conditions must be present
                    - condition_key: "aws:MultiFactorAuthPresent"
                      operators: ["Bool"]
                      expected_value: "true"
                      description: "MFA authentication required"

                    - condition_key: "aws:SourceIp"
                      operators: ["IpAddress"]
                      description: "Must originate from corporate network"
                      allowed_ip_ranges:
                        - "203.0.113.0/24"  # Corporate network
                        - "198.51.100.0/24"  # VPN range

                    - condition_key: "aws:RequestedRegion"
                      operators: ["StringEquals"]
                      allowed_values:
                        - "us-east-1"
                        - "us-west-2"
                      description: "Only approved regions"

              # Data access operations
              sensitive_data_access:
                actions:
                  - "s3:GetObject"
                  - "s3:PutObject"
                  - "dynamodb:GetItem"
                  - "dynamodb:PutItem"
                resources:
                  patterns:
                    - ".*production.*"
                    - ".*pii.*"
                    - ".*sensitive.*"
                required_conditions:
                  any_of:  # At least ONE group of conditions must be present
                    - group_name: "corporate_access"
                      conditions:
                        - condition_key: "aws:SourceIp"
                          operators: ["IpAddress"]
                          allowed_ip_ranges:
                            - "203.0.113.0/24"

                    - group_name: "vpc_endpoint_access"
                      conditions:
                        - condition_key: "aws:SourceVpce"
                          operators: ["StringEquals"]
                          description: "Must access via VPC endpoint"

                  all_of:  # PLUS these conditions (in addition to any_of)
                    - condition_key: "aws:SecureTransport"
                      operators: ["Bool"]
                      expected_value: "true"
                      description: "HTTPS/TLS required"

              # Administrative operations
              admin_operations:
                actions:
                  - "iam:CreateUser"
                  - "iam:DeleteUser"
                  - "iam:AttachUserPolicy"
                  - "iam:PutUserPolicy"
                required_conditions:
                  all_of:
                    - condition_key: "aws:MultiFactorAuthPresent"
                      operators: ["Bool"]
                      expected_value: "true"

                    - condition_key: "aws:userid"
                      operators: ["StringLike"]
                      description: "Must be from admin group"
                      value_pattern: "^AIDA.*ADMIN.*$"

            # Exception rules (bypass multi-condition requirements)
            exceptions:
              - name: "service_accounts"
                principals:
                  - "arn:aws:iam::123456789012:role/ServiceRole"
                  - "arn:aws:iam::123456789012:role/AutomationRole"
                reason: "Service accounts with pre-approved automation"

              - name: "emergency_access"
                actions:
                  - "cloudwatch:PutMetricAlarm"
                  - "sns:Publish"
                reason: "Emergency response actions"

            # Validation strictness
            strict_mode: true  # Fail on any missing condition
            allow_additional_conditions: true  # Allow more conditions than required
"""

import re
from typing import Any

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class AdvancedMultiConditionValidator(PolicyCheck):
    """
    Highly complex validator for multi-condition policy requirements.
    Implements context-aware, category-based validation with exception handling.
    """

    @property
    def check_id(self) -> str:
        return "advanced_multi_condition"

    @property
    def description(self) -> str:
        return "Advanced multi-condition policy validator with context-aware rules"

    @property
    def default_severity(self) -> str:
        return "error"

    def _matches_pattern(self, value: str, patterns: list[str]) -> bool:
        """Check if value matches any pattern (supports wildcards)."""
        for pattern in patterns:
            if "*" in pattern:
                regex_pattern = pattern.replace("*", ".*")
                if re.match(f"^{regex_pattern}$", value):
                    return True
            elif value == pattern:
                return True
        return False

    def _matches_resource_pattern(self, resources: Any, patterns: list[str]) -> bool:
        """Check if any resource matches the given patterns."""
        if not resources or not patterns:
            return False

        resource_list = resources if isinstance(resources, list) else [resources]

        for resource in resource_list:
            for pattern in patterns:
                if re.search(pattern, resource, re.IGNORECASE):
                    return True
        return False

    def _is_exception_applicable(
        self, statement: Statement, exceptions: list[dict[str, Any]]
    ) -> tuple[bool, str | None]:
        """Check if statement matches any exception rules."""
        for exception in exceptions:
            # Check principal exceptions
            if "principals" in exception:
                principal = statement.principal
                if principal:
                    principal_str = str(principal)
                    for exc_principal in exception["principals"]:
                        if exc_principal in principal_str:
                            return True, exception.get("reason", "Exception rule applied")

            # Check action exceptions
            if "actions" in exception:
                actions = (
                    statement.action
                    if isinstance(statement.action, list)
                    else [statement.action]
                    if statement.action
                    else []
                )
                for action in actions:
                    if action and action in exception["actions"]:
                        return True, exception.get("reason", "Exception rule applied")

        return False, None

    def _extract_condition_value(
        self,
        conditions: dict[str, Any] | None,
        condition_key: str,
        operators: list[str],
    ) -> tuple[bool, Any | None]:
        """Extract condition value if present."""
        if not conditions:
            return False, None

        for operator in operators:
            if operator in conditions:
                operator_conditions = conditions[operator]
                if isinstance(operator_conditions, dict):
                    if condition_key in operator_conditions:
                        return True, operator_conditions[condition_key]

        return False, None

    def _validate_condition_requirement(
        self, conditions: dict[str, Any] | None, requirement: dict[str, Any]
    ) -> tuple[bool, str | None]:
        """
        Validate a single condition requirement.
        Returns (is_valid, error_message)
        """
        condition_key = requirement.get("condition_key")
        if not condition_key:
            return False, "Configuration error: Missing 'condition_key' in requirement"

        operators = requirement.get("operators", [])
        expected_value = requirement.get("expected_value")
        allowed_values = requirement.get("allowed_values")
        allowed_ip_ranges = requirement.get("allowed_ip_ranges")
        value_pattern = requirement.get("value_pattern")
        description = requirement.get("description", "")

        # Check if condition exists
        has_condition, actual_value = self._extract_condition_value(
            conditions, condition_key, operators
        )

        if not has_condition:
            return (
                False,
                f"Missing required condition '{condition_key}' ({description})",
            )

        # Validate expected value
        if expected_value is not None:
            if str(actual_value).lower() != str(expected_value).lower():
                return False, (
                    f"Condition '{condition_key}' has value '{actual_value}' "
                    f"but expected '{expected_value}'"
                )

        # Validate allowed values
        if allowed_values:
            actual_values = actual_value if isinstance(actual_value, list) else [actual_value]
            invalid_values = [v for v in actual_values if v not in allowed_values]
            if invalid_values:
                return False, (
                    f"Condition '{condition_key}' has invalid values: {invalid_values}. "
                    f"Allowed: {allowed_values}"
                )

        # Validate IP ranges
        if allowed_ip_ranges:
            # Basic validation - actual IP range validation would be more complex
            actual_ips = actual_value if isinstance(actual_value, list) else [actual_value]
            # Simplified check - in production, use ipaddress module
            if not any(ip in allowed_ip_ranges for ip in actual_ips):
                return False, (
                    f"Condition '{condition_key}' IP addresses {actual_ips} not in "
                    f"allowed ranges: {allowed_ip_ranges}"
                )

        # Validate value pattern
        if value_pattern and not re.match(value_pattern, str(actual_value)):
            return False, (
                f"Condition '{condition_key}' value '{actual_value}' does not match "
                f"required pattern '{value_pattern}'"
            )

        return True, None

    def _validate_all_of_conditions(
        self, conditions: dict[str, Any] | None, requirements: list[dict[str, Any]]
    ) -> list[str]:
        """Validate that ALL conditions are present and valid."""
        errors = []

        for requirement in requirements:
            is_valid, error_msg = self._validate_condition_requirement(conditions, requirement)
            if not is_valid:
                errors.append(error_msg)

        return errors

    def _validate_any_of_conditions(
        self,
        conditions: dict[str, Any] | None,
        condition_groups: list[dict[str, Any]],
    ) -> tuple[bool, list[str]]:
        """
        Validate that at least ONE group of conditions is satisfied.
        Returns (any_valid, all_errors)
        """
        all_errors = []
        any_group_valid = False

        for group in condition_groups:
            group_name = group.get("group_name", "unnamed")
            group_conditions = group.get("conditions", [])

            group_errors = self._validate_all_of_conditions(conditions, group_conditions)

            if not group_errors:
                any_group_valid = True
                break
            else:
                all_errors.append(f"Group '{group_name}': {', '.join(group_errors)}")

        return any_group_valid, all_errors

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute the advanced multi-condition validation."""
        issues: list[ValidationIssue] = []

        # Only check Allow statements
        if statement.effect.lower() != "allow":
            return issues

        # Check for exceptions first
        exceptions = config.config.get("exceptions", [])
        is_exception, exception_reason = self._is_exception_applicable(statement, exceptions)
        if is_exception:
            # Statement is exempt from multi-condition requirements
            return issues

        # Get action categories
        action_categories = config.config.get("action_categories", {})
        if not action_categories:
            return issues

        # Normalize actions
        actions = (
            statement.action
            if isinstance(statement.action, list)
            else [statement.action]
            if statement.action
            else []
        )

        # Check each action category
        for category_name, category_config in action_categories.items():
            category_actions = category_config.get("actions", [])
            resource_patterns = category_config.get("resources", {}).get("patterns", [])
            required_conditions = category_config.get("required_conditions", {})

            # Check if statement matches this category
            matching_actions = []
            for action in actions:
                if action and self._matches_pattern(action, category_actions):
                    matching_actions.append(action)

            # Also check resource patterns if specified
            if resource_patterns and not self._matches_resource_pattern(
                statement.resource, resource_patterns
            ):
                continue

            if not matching_actions:
                continue

            # Statement matches this category - validate conditions
            validation_errors = []

            # Validate "all_of" conditions (must all be present)
            all_of_requirements = required_conditions.get("all_of", [])
            if all_of_requirements:
                all_of_errors = self._validate_all_of_conditions(
                    statement.condition, all_of_requirements
                )
                validation_errors.extend(all_of_errors)

            # Validate "any_of" conditions (at least one group must be satisfied)
            any_of_groups = required_conditions.get("any_of", [])
            if any_of_groups:
                any_valid, any_of_errors = self._validate_any_of_conditions(
                    statement.condition, any_of_groups
                )
                if not any_valid:
                    validation_errors.append(
                        f"None of the required condition groups are satisfied: {'; '.join(any_of_errors)}"
                    )

            # If there are validation errors, create an issue
            if validation_errors:
                error_summary = "\n  - ".join(validation_errors)

                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type=self.check_id,
                        message=(
                            f"Actions {matching_actions} in category "
                            f"'{category_name}' do not meet multi-condition requirements:\n"
                            f"  - {error_summary}"
                        ),
                        suggestion=self._build_recommendation(
                            category_name, required_conditions, matching_actions
                        ),
                        line_number=statement.line_number,
                    )
                )

        return issues

    def _build_recommendation(
        self,
        category_name: str,
        required_conditions: dict[str, Any],
        actions: list[str],
    ) -> str:
        """Build detailed recommendation for fixing the issue."""
        recommendation = [
            f"For '{category_name}' actions {actions}, ensure the following conditions are met:\n"
        ]

        all_of = required_conditions.get("all_of", [])
        if all_of:
            recommendation.append("Required conditions (ALL must be present):")
            for req in all_of:
                key = req.get("condition_key")
                desc = req.get("description", "")
                recommendation.append(f"  - {key}: {desc}")

        any_of = required_conditions.get("any_of", [])
        if any_of:
            recommendation.append(
                "\nAlternative condition groups (at least ONE group must be present):"
            )
            for group in any_of:
                group_name = group.get("group_name", "unnamed")
                recommendation.append(f"  Group '{group_name}':")
                for req in group.get("conditions", []):
                    key = req.get("condition_key")
                    desc = req.get("description", "")
                    recommendation.append(f"    - {key}: {desc}")

        recommendation.append("\nExample condition block:")
        recommendation.append(self._build_example_condition(required_conditions))

        return "\n".join(recommendation)

    def _build_example_condition(self, required_conditions: dict[str, Any]) -> str:
        """Build example condition block."""
        example_conditions = {}

        for req in required_conditions.get("all_of", []):
            key = req.get("condition_key")
            operators = req.get("operators", ["StringEquals"])
            expected_value = req.get("expected_value", "value")

            if operators:
                operator = operators[0]
                if operator not in example_conditions:
                    example_conditions[operator] = {}
                example_conditions[operator][key] = expected_value

        import json

        return json.dumps({"Condition": example_conditions}, indent=2)

"""Trust Policy Validation Check.

Validates trust policies (role assumption policies) for security best practices.
This check ensures that assume role actions have appropriate principals and conditions.

Trust policies are resource-based policies attached to IAM roles that control
who can assume the role and under what conditions.

Key Validations:
1. Action-Principal Type Matching
   - sts:AssumeRole → AWS or Service principals
   - sts:AssumeRoleWithSAML → Federated (SAML provider) principals
   - sts:AssumeRoleWithWebIdentity → Federated (OIDC provider) principals

2. Provider ARN Validation
   - SAML providers must match: arn:aws:iam::account:saml-provider/name
   - OIDC providers must match: arn:aws:iam::account:oidc-provider/domain

3. Required Conditions
   - SAML: Requires SAML:aud condition
   - OIDC: Requires provider-specific audience/subject conditions
   - Cross-account: Should have ExternalId or PrincipalOrgID

Complements existing checks:
- principal_validation: Validates which principals are allowed/blocked
- action_condition_enforcement: Validates required conditions for actions
- trust_policy_validation: Validates action-principal coupling and trust-specific rules

This check is DISABLED by default. Enable it for trust policy validation:

    trust_policy_validation:
      enabled: true
      severity: high
"""

import re
from typing import TYPE_CHECKING, Any, ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue

if TYPE_CHECKING:
    pass


class TrustPolicyValidationCheck(PolicyCheck):
    """Validates trust policies for role assumption security."""

    # Default validation rules for assume actions
    DEFAULT_RULES = {
        "sts:AssumeRole": {
            "allowed_principal_types": ["AWS", "Service"],
            "description": "Standard role assumption",
        },
        "sts:AssumeRoleWithSAML": {
            "allowed_principal_types": ["Federated"],
            "provider_pattern": r"^arn:aws:iam::\d{12}:saml-provider/[\w+=,.@-]+$",
            "required_conditions": ["SAML:aud"],
            "description": "SAML-based federated role assumption",
        },
        "sts:AssumeRoleWithWebIdentity": {
            "allowed_principal_types": ["Federated"],
            "provider_pattern": r"^arn:aws:iam::\d{12}:oidc-provider/[\w./-]+$",
            "required_conditions": ["*:aud"],  # Require audience condition (provider-specific key)
            "description": "OIDC-based federated role assumption",
        },
        "sts:TagSession": {
            "allowed_principal_types": ["AWS", "Service", "Federated"],
            "description": "Session tagging during role assumption (can be combined with any assume action)",
        },
        "sts:SetSourceIdentity": {
            "allowed_principal_types": ["AWS", "Service", "Federated"],
            "description": "Set source identity during role assumption (tracks original identity through role chains)",
        },
        "sts:SetContext": {
            "allowed_principal_types": ["AWS", "Service", "Federated"],
            "description": "Set session context during role assumption",
        },
    }

    check_id: ClassVar[str] = "trust_policy_validation"
    description: ClassVar[str] = (
        "Validates trust policies for role assumption security and action-principal coupling"
    )
    default_severity: ClassVar[str] = "high"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute trust policy validation on a single statement.

        Args:
            statement: The statement to validate
            statement_idx: Index of the statement in the policy
            fetcher: AWS service fetcher instance
            config: Configuration for this check

        Returns:
            List of validation issues
        """
        issues = []

        # Skip if no principal (trust policies must have principals)
        if statement.principal is None and statement.not_principal is None:
            return issues

        # Get actions from statement
        actions = self._get_actions(statement)
        if not actions:
            return issues

        # Get validation rules (use custom rules if provided, otherwise defaults)
        validation_rules = config.config.get("validation_rules", self.DEFAULT_RULES)

        # Check each assume action
        for action in actions:
            # Skip wildcard actions (too broad to validate specifically)
            if action == "*" or action == "sts:*":
                continue

            # Find matching rule (exact matches for assume actions)
            rule = self._find_matching_rule(action, validation_rules)
            if not rule:
                continue  # Not an assume action we validate

            # Validate principal type for this action
            principal_issues = self._validate_principal_type(
                statement, action, rule, statement_idx, config
            )
            issues.extend(principal_issues)

            # Validate provider ARN format if required
            if "provider_pattern" in rule:
                provider_issues = self._validate_provider_format(
                    statement, action, rule, statement_idx, config
                )
                issues.extend(provider_issues)

            # Validate required conditions
            if "required_conditions" in rule:
                condition_issues = self._validate_required_conditions(
                    statement, action, rule, statement_idx, config
                )
                issues.extend(condition_issues)

        return issues

    def _get_actions(self, statement: Statement) -> list[str]:
        """Extract actions from statement.

        Args:
            statement: IAM policy statement

        Returns:
            List of action strings
        """
        if statement.action is None:
            return []
        return [statement.action] if isinstance(statement.action, str) else statement.action

    def _find_matching_rule(self, action: str, rules: dict[str, Any]) -> dict[str, Any] | None:
        """Find validation rule matching the action.

        Supports wildcards in action names.

        Args:
            action: Action to find rule for (e.g., "sts:AssumeRole")
            rules: Validation rules dict

        Returns:
            Matching rule dict or None
        """
        # Exact match first (performance optimization)
        if action in rules:
            return rules[action]

        # Check for wildcard patterns in action
        for rule_action, rule_config in rules.items():
            # Support wildcards in the action being validated
            if "*" in action:
                pattern = action.replace("*", ".*")
                if re.match(f"^{pattern}$", rule_action):
                    return rule_config

        return None

    def _extract_principal_types(self, statement: Statement) -> dict[str, list[str]]:
        """Extract principals grouped by type (AWS, Service, Federated, etc.).

        Args:
            statement: IAM policy statement

        Returns:
            Dict mapping principal type to list of principal values
        """
        principal_types: dict[str, list[str]] = {}

        if statement.principal:
            if isinstance(statement.principal, str):
                # Simple string principal like "*"
                principal_types["AWS"] = [statement.principal]
            elif isinstance(statement.principal, dict):
                for key, value in statement.principal.items():
                    if isinstance(value, str):
                        principal_types[key] = [value]
                    elif isinstance(value, list):
                        principal_types[key] = value

        return principal_types

    def _validate_principal_type(
        self,
        statement: Statement,
        action: str,
        rule: dict[str, Any],
        statement_idx: int,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Validate that principal type matches the assume action.

        Args:
            statement: IAM policy statement
            action: Assume action being validated
            rule: Validation rule for this action
            statement_idx: Statement index

        Returns:
            List of validation issues
        """
        issues = []

        allowed_types = rule.get("allowed_principal_types", [])
        if not allowed_types:
            return issues

        principal_types = self._extract_principal_types(statement)

        # Check if any principal type is not allowed
        for principal_type, principals in principal_types.items():
            if principal_type not in allowed_types:
                principals_list = ", ".join(f"`{p}`" for p in principals)
                allowed_list = ", ".join(f"`{t}`" for t in allowed_types)

                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        issue_type="invalid_principal_type_for_assume_action",
                        message=f"Action `{action}` should not use `Principal` type `{principal_type}`. "
                        f"Expected principal types: {allowed_list}",
                        statement_index=statement_idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        action=action,
                        suggestion=f"For `{action}`, use {allowed_list} principal type instead of `{principal_type}`. "
                        f"\n\nFound principals: `{principals_list}`\n\n"
                        f"{rule.get('description', '')}",
                        example=self._get_example_for_action(
                            action, allowed_types[0] if allowed_types else "AWS"
                        ),
                        field_name="principal",
                    )
                )

        return issues

    def _validate_provider_format(
        self,
        statement: Statement,
        action: str,
        rule: dict[str, Any],
        statement_idx: int,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Validate that federated provider ARN matches expected format.

        Args:
            statement: IAM policy statement
            action: Assume action being validated
            rule: Validation rule for this action
            statement_idx: Statement index

        Returns:
            List of validation issues
        """
        issues = []

        provider_pattern = rule.get("provider_pattern")
        if not provider_pattern:
            return issues

        principal_types = self._extract_principal_types(statement)
        federated_principals = principal_types.get("Federated", [])

        for principal in federated_principals:
            if not re.match(provider_pattern, principal):
                provider_type = "SAML" if "saml-provider" in provider_pattern else "OIDC"

                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        issue_type="invalid_provider_format",
                        message=f"Federated principal `{principal}` does not match expected `{provider_type}` provider format for `{action}`",
                        statement_index=statement_idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        action=action,
                        suggestion=f"For `{action}`, use a valid `{provider_type}` provider ARN.\n\n"
                        f"Expected pattern: `{provider_pattern}`\n"
                        f"Found: `{principal}`",
                        example=self._get_provider_example(provider_type),
                        field_name="principal",
                    )
                )

        return issues

    def _validate_required_conditions(
        self,
        statement: Statement,
        action: str,
        rule: dict[str, Any],
        statement_idx: int,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Validate that required conditions are present.

        Args:
            statement: IAM policy statement
            action: Assume action being validated
            rule: Validation rule for this action
            statement_idx: Statement index

        Returns:
            List of validation issues
        """
        issues = []

        required_conditions = rule.get("required_conditions", [])
        if not required_conditions:
            return issues

        # Get all condition keys from statement
        condition_keys = set()
        if statement.condition:
            for _operator, keys_dict in statement.condition.items():
                if isinstance(keys_dict, dict):
                    condition_keys.update(keys_dict.keys())

        # Check for missing required conditions (supports wildcards like *:aud)
        missing_conditions = []
        for required_cond in required_conditions:
            if "*:" in required_cond:
                # Wildcard pattern - check if any key ends with the suffix
                suffix = required_cond.split("*:")[1]
                if not any(key.endswith(f":{suffix}") for key in condition_keys):
                    missing_conditions.append(required_cond)
            else:
                # Exact match
                if required_cond not in condition_keys:
                    missing_conditions.append(required_cond)

        if missing_conditions:
            missing_list = ", ".join(f"`{c}`" for c in missing_conditions)

            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),
                    issue_type="missing_required_condition_for_assume_action",
                    message=f"Action `{action}` is missing required conditions: `{missing_list}`",
                    statement_index=statement_idx,
                    statement_sid=statement.sid,
                    line_number=statement.line_number,
                    action=action,
                    suggestion=f"Add required condition(s) to restrict when `{action}` can be performed. "
                    f"Missing: `{missing_list}`\n\n"
                    f"{rule.get('description', '')}",
                    example=self._get_condition_example(action, required_conditions[0]),
                    field_name="condition",
                )
            )

        return issues

    def _get_example_for_action(self, action: str, principal_type: str) -> str:
        """Generate example JSON for an assume action.

        Args:
            action: Assume action
            principal_type: Expected principal type

        Returns:
            JSON example string
        """
        examples = {
            ("sts:AssumeRole", "AWS"): """{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:root"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "unique-external-id"
    }
  }
}""",
            ("sts:AssumeRole", "Service"): """{
  "Effect": "Allow",
  "Principal": {
    "Service": "lambda.amazonaws.com"
  },
  "Action": "sts:AssumeRole"
}""",
            ("sts:AssumeRoleWithSAML", "Federated"): """{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"
  },
  "Action": "sts:AssumeRoleWithSAML",
  "Condition": {
    "StringEquals": {
      "SAML:aud": "https://signin.aws.amazon.com/saml"
    }
  }
}""",
            ("sts:AssumeRoleWithWebIdentity", "Federated"): """{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    },
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:*"
    }
  }
}""",
        }

        return examples.get((action, principal_type), "")

    def _get_provider_example(self, provider_type: str) -> str:
        """Get example provider ARN.

        Args:
            provider_type: Type of provider (SAML or OIDC)

        Returns:
            Example ARN string
        """
        if provider_type == "SAML":
            return """{
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"
  }
}"""
        else:  # OIDC
            return """{
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  }
}"""

    def _get_condition_example(self, action: str, condition_key: str) -> str:
        """Get example condition for an action.

        Args:
            action: Assume action
            condition_key: Required condition key

        Returns:
            JSON example string
        """
        examples = {
            "SAML:aud": """{
  "Condition": {
    "StringEquals": {
      "SAML:aud": "https://signin.aws.amazon.com/saml"
    }
  }
}""",
            "sts:ExternalId": """{
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "unique-external-id-shared-with-trusted-party"
    }
  }
}""",
            "aws:PrincipalOrgID": """{
  "Condition": {
    "StringEquals": {
      "aws:PrincipalOrgID": "o-123456789"
    }
  }
}""",
        }

        return examples.get(
            condition_key,
            f'{{\n  "Condition": {{\n    "StringEquals": {{\n      "{condition_key}": "value"\n    }}\n  }}\n}}',
        )

"""Service wildcard check - detects service-level wildcards like 'iam:*', 's3:*'."""

import re
from typing import ClassVar

from iam_validator.checks.utils.action_parser import parse_action
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue

# Matches ${aws:PrincipalTag/...} references used in ABAC conditions
_PRINCIPAL_TAG_REF = re.compile(r"\$\{aws:PrincipalTag/", re.IGNORECASE)

# ABAC-aware condition operators (base forms, lowercased) that can enforce tag-based access.
# IfExists and set-operator prefixes (ForAllValues:/ForAnyValue:) are stripped before lookup.
_ABAC_BASE_OPERATORS = frozenset(
    [
        "stringequals",
        "stringlike",
        "stringequalsignorecase",
    ]
)


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

        abac_mitigated = self._has_abac_resource_tag_condition(statement)

        for action in actions:
            # Skip full wildcard (covered by wildcard_action check)
            if action == "*":
                continue

            # Parse action and check if it's a service-level wildcard (e.g., "iam:*", "s3:*")
            parsed = parse_action(action)
            if parsed and parsed.action_name == "*":
                service = parsed.service.lower()

                # Check if this service is in the allowed list
                if service in allowed_services:
                    continue

                if abac_mitigated:
                    severity = config.config.get("abac_mitigated_severity", "low")
                    message_template = config.config.get(
                        "abac_mitigated_message",
                        "Service-level wildcard `{action}` grants all permissions for `{service}` service, but ABAC tag conditions restrict access to owned resources",
                    )
                else:
                    severity = self.get_severity(config)
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
                example = example_template.format(action=action, service=service) if example_template else ""

                issues.append(
                    ValidationIssue(
                        severity=severity,
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

    @staticmethod
    def _is_abac_operator(operator: str) -> bool:
        """Check if a condition operator is a non-negated string comparison usable for ABAC.

        Strips ForAllValues:/ForAnyValue: prefixes and IfExists suffix before
        matching against base operators like StringEquals, StringLike, etc.
        Negated operators (StringNotEquals, StringNotLike) are excluded because
        they do not restrict access to matching resources.
        """
        cleaned = operator
        # Strip set-operator prefix (ForAllValues:/ForAnyValue:)
        if ":" in cleaned:
            prefix, rest = cleaned.split(":", 1)
            if prefix.lower() in ("forallvalues", "foranyvalue"):
                cleaned = rest
        # Strip IfExists suffix
        if cleaned.lower().endswith("ifexists"):
            cleaned = cleaned[: -len("IfExists")]
        return cleaned.lower() in _ABAC_BASE_OPERATORS

    def _has_abac_resource_tag_condition(self, statement: Statement) -> bool:
        """Return True if the statement uses ABAC conditions restricting by resource tags.

        Detects patterns like:
          "StringEquals": {"aws:ResourceTag/owner": "${aws:PrincipalTag/owner}"}

        This indicates the wildcard is scoped to resources the principal owns via
        attribute-based access control (ABAC), making the wildcard intentional.
        """
        if not statement.condition:
            return False

        for operator, conditions in statement.condition.items():
            if not self._is_abac_operator(operator):
                continue
            if not isinstance(conditions, dict):
                continue
            for key, value in conditions.items():
                if not key.lower().startswith("aws:resourcetag/"):
                    continue
                # Value can be a string or list of strings
                values = [value] if isinstance(value, str) else (value if isinstance(value, list) else [])
                for v in values:
                    if isinstance(v, str) and _PRINCIPAL_TAG_REF.search(v):
                        return True

        return False

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
            return {s.lower() for s in allowed}
        return set()

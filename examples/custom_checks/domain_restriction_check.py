"""
Example custom check: Domain Restriction Check

This check validates that all resources in a policy statement match approved
domain patterns. Useful for enforcing organizational resource naming conventions.

This demonstrates a custom check that validates RESOURCES (not conditions),
which is different from what `action_condition_enforcement` provides.

Usage:
    Add to your iam-validator.yaml:

        custom_checks_dir: "./examples/custom_checks"

        checks:
          domain_restriction:
            enabled: true
            severity: error
            approved_domains:
              - "arn:aws:s3:::prod-*"
              - "arn:aws:s3:::shared-*"
              - "arn:aws:dynamodb:*:*:table/prod-*"
"""

import fnmatch
from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class DomainRestrictionCheck(PolicyCheck):
    """Validates that all resources match approved domain patterns."""

    check_id: ClassVar[str] = "domain_restriction"
    description: ClassVar[str] = "Validates resources against approved domain patterns"
    default_severity: ClassVar[str] = "error"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Check that all resources match approved domain patterns."""
        del fetcher  # Not used in this check
        issues = []

        approved_domains = config.config.get("approved_domains", [])
        if not approved_domains:
            return issues

        resources = statement.get_resources()

        for resource in resources:
            # Skip wildcard resources (caught by other checks)
            if resource == "*":
                continue

            if not self._matches_approved_domain(resource, approved_domains):
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="unapproved_resource_domain",
                        message=f"Resource `{resource}` does not match any approved domain pattern",
                        resource=resource,
                        suggestion=f"Approved patterns: {', '.join(approved_domains)}",
                        line_number=statement.line_number,
                        field_name="resource",
                    )
                )

        return issues

    def _matches_approved_domain(self, resource: str, approved_domains: list[str]) -> bool:
        """Check if resource matches any approved domain pattern."""
        for pattern in approved_domains:
            if fnmatch.fnmatch(resource, pattern):
                return True
        return False

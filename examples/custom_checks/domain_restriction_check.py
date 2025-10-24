"""
Example custom check: Domain Restriction Check

This example demonstrates how to create a custom policy check that
validates resources against an approved list of domain patterns.

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

Author: Your Organization
"""


from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class DomainRestrictionCheck(PolicyCheck):
    """
    Validates that all resources in a policy statement match approved domain patterns.

    This check helps enforce organizational policies about which resources
    can be accessed by ensuring resources match pre-approved patterns.
    """

    @property
    def check_id(self) -> str:
        return "domain_restriction"

    @property
    def description(self) -> str:
        return "Validates resources against approved domain patterns"

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
        """
        Check that all resources match approved domain patterns.

        Args:
            statement: The IAM policy statement to check
            statement_idx: Index of the statement in the policy
            fetcher: AWS service fetcher (not used in this check)
            config: Check configuration containing approved_domains list

        Returns:
            List of validation issues found
        """
        issues = []

        # Get approved domains from config
        approved_domains = config.config.get("approved_domains", [])

        if not approved_domains:
            # If no domains configured, skip this check
            return issues

        # Get resources from statement
        resources = statement.get_resources()

        for resource in resources:
            # Skip wildcard resources (these should be caught by other checks)
            if resource == "*":
                continue

            # Check if resource matches any approved domain pattern
            if not self._matches_approved_domain(resource, approved_domains):
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type=self.check_id,
                        message=f"Resource '{resource}' does not match any approved domain pattern",
                        resource=resource,
                        suggestion=f"Approved domains: {', '.join(approved_domains)}",
                        line_number=statement.line_number,
                    )
                )

        return issues

    def _matches_approved_domain(
        self, resource: str, approved_domains: list[str]
    ) -> bool:
        """
        Check if a resource matches any approved domain pattern.

        Supports wildcards in domain patterns (e.g., "prod-*" matches "prod-bucket").

        Args:
            resource: The resource ARN to check
            approved_domains: List of approved domain patterns

        Returns:
            True if resource matches at least one pattern
        """
        import fnmatch

        for pattern in approved_domains:
            if fnmatch.fnmatch(resource, pattern):
                return True

        return False

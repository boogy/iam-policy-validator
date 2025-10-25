"""
Example custom check: Region Restriction Check

This check ensures that policies only grant access to resources in approved regions.
Useful for enforcing data residency requirements and cost control.

Usage:
    Add to your iam-validator.yaml:

        custom_checks_dir: "./examples/custom_checks"

        checks:
          region_restriction:
            enabled: true
            severity: error
            approved_regions:
              - "us-east-1"
              - "us-west-2"
              - "eu-west-1"
            # Optional: require region restrictions on all statements
            require_region_condition: true
"""

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class RegionRestrictionCheck(PolicyCheck):
    """Validates that resources are limited to approved AWS regions."""

    @property
    def check_id(self) -> str:
        return "region_restriction"

    @property
    def description(self) -> str:
        return "Validates resources are limited to approved AWS regions"

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
        """Check region restrictions."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        approved_regions = config.config.get("approved_regions", [])
        require_condition = config.config.get("require_region_condition", False)

        if not approved_regions:
            return issues

        # Check 1: Extract regions from resource ARNs
        resources = statement.get_resources()
        for resource in resources:
            if resource == "*":
                continue

            region = self._extract_region_from_arn(resource)
            if region and region not in approved_regions:
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="unapproved_region",
                        message=f"Resource in unapproved region '{region}': {resource}",
                        resource=resource,
                        suggestion=f"Approved regions: {', '.join(approved_regions)}",
                        line_number=statement.line_number,
                    )
                )

        # Check 2: Verify aws:RequestedRegion condition if required
        if require_condition and not self._has_region_condition(statement, approved_regions):
            issues.append(
                ValidationIssue(
                    severity="warning",
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="missing_region_condition",
                    message="Statement should include aws:RequestedRegion condition",
                    suggestion=f"Add condition limiting regions to: {', '.join(approved_regions)}",
                    line_number=statement.line_number,
                )
            )

        return issues

    def _extract_region_from_arn(self, arn: str) -> str:
        """
        Extract region from ARN.

        ARN format: arn:partition:service:region:account-id:resource
        """
        if not arn.startswith("arn:"):
            return ""

        parts = arn.split(":")
        if len(parts) >= 4:
            return parts[3]  # Region is the 4th component

        return ""

    def _has_region_condition(self, statement: Statement, approved_regions: list[str]) -> bool:
        """Check if statement has appropriate region condition."""
        if not statement.condition:
            return False

        # Look for aws:RequestedRegion condition
        for operator, conditions in statement.condition.items():
            if "aws:RequestedRegion" in conditions:
                # Verify it restricts to approved regions
                value = conditions["aws:RequestedRegion"]

                # Handle different value types
                if isinstance(value, str):
                    return value in approved_regions
                elif isinstance(value, list):
                    return all(v in approved_regions for v in value)

        return False

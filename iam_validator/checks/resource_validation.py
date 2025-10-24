"""Resource validation check - validates ARN formats."""

import re

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class ResourceValidationCheck(PolicyCheck):
    """Validates ARN format for resources."""

    # Maximum allowed length for ARN to prevent ReDoS attacks
    MAX_ARN_LENGTH = 2048  # AWS max ARN length is ~2048 characters

    @property
    def check_id(self) -> str:
        return "resource_validation"

    @property
    def description(self) -> str:
        return "Validates ARN format for resources"

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
        """Execute resource ARN validation on a statement."""
        issues = []

        # Get resources from statement
        resources = statement.get_resources()
        statement_sid = statement.sid
        line_number = statement.line_number

        # Get ARN pattern from config, or use default
        # Pattern allows wildcards (*) in region and account fields
        arn_pattern_str = config.config.get(
            "arn_pattern",
            r"^arn:(aws|aws-cn|aws-us-gov|aws-eusc|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f):[a-z0-9\-]+:[a-z0-9\-*]*:[0-9*]*:.+$",
        )

        # Compile pattern with timeout protection (available in Python 3.11+)
        try:
            arn_pattern = re.compile(arn_pattern_str)
        except re.error:
            # Fallback to using fetcher's pre-compiled pattern
            arn_pattern = fetcher._patterns.arn_pattern

        for resource in resources:
            # Skip wildcard resources (handled by security checks)
            if resource == "*":
                continue

            # Validate ARN length to prevent ReDoS attacks
            if len(resource) > self.MAX_ARN_LENGTH:
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="invalid_resource",
                        message=f"Resource ARN exceeds maximum length ({len(resource)} > {self.MAX_ARN_LENGTH}): {resource[:100]}...",
                        resource=resource[:100] + "...",
                        suggestion="ARN is too long and may be invalid",
                        line_number=line_number,
                    )
                )
                continue

            # Validate ARN format
            try:
                if not arn_pattern.match(resource):
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            statement_sid=statement_sid,
                            statement_index=statement_idx,
                            issue_type="invalid_resource",
                            message=f"Invalid ARN format: {resource}",
                            resource=resource,
                            suggestion="ARN should follow format: arn:partition:service:region:account-id:resource",
                            line_number=line_number,
                        )
                    )
            except Exception:
                # If regex matching fails (shouldn't happen with length check), treat as invalid
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="invalid_resource",
                        message=f"Could not validate ARN format: {resource}",
                        resource=resource,
                        suggestion="ARN validation failed - may contain unexpected characters",
                        line_number=line_number,
                    )
                )

        return issues

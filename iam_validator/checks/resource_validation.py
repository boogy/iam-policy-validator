"""Resource validation check - validates ARN formats."""

import re
from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.constants import DEFAULT_ARN_VALIDATION_PATTERN, MAX_ARN_LENGTH
from iam_validator.core.models import Statement, ValidationIssue
from iam_validator.sdk.arn_matching import (
    has_template_variables,
    normalize_template_variables,
)


class ResourceValidationCheck(PolicyCheck):
    """Validates ARN format for resources."""

    check_id: ClassVar[str] = "resource_validation"
    description: ClassVar[str] = "Validates ARN format for resources"
    default_severity: ClassVar[str] = "error"

    def _validate_resource(
        self,
        resource: str,
        arn_pattern: re.Pattern[str],
        allow_template_variables: bool,
        config: CheckConfig,
        statement_sid: str | None,
        statement_idx: int,
        line_number: int | None,
        field_name: str,
    ) -> ValidationIssue | None:
        """Validate a single resource ARN and return an issue if invalid.

        Args:
            resource: The resource ARN string to validate
            arn_pattern: Compiled regex pattern for ARN validation
            allow_template_variables: Whether to allow template variables
            config: Check configuration
            statement_sid: Statement ID for error reporting
            statement_idx: Statement index for error reporting
            line_number: Line number for error reporting
            field_name: Field name ("resource" or "not_resource") for error reporting

        Returns:
            ValidationIssue if resource is invalid, None otherwise
        """
        # Skip wildcard resources (handled by security checks)
        if resource == "*":
            return None

        # Validate ARN length to prevent ReDoS attacks
        if len(resource) > MAX_ARN_LENGTH:
            return ValidationIssue(
                severity=self.get_severity(config),
                statement_sid=statement_sid,
                statement_index=statement_idx,
                issue_type="invalid_resource",
                message=f"Resource ARN exceeds maximum length ({len(resource)} > {MAX_ARN_LENGTH}): {resource[:100]}...",
                resource=resource[:100] + "...",
                suggestion="`ARN` is too long and may be invalid",
                line_number=line_number,
                field_name=field_name,
            )

        # Check if resource contains template variables
        has_templates = has_template_variables(resource)

        # If template variables are found and allowed, normalize them for validation
        validation_resource = resource
        if has_templates and allow_template_variables:
            validation_resource = normalize_template_variables(resource)

        # Validate ARN format
        try:
            if not arn_pattern.match(validation_resource):
                # If original resource had templates and normalization didn't help,
                # provide a more informative message
                if has_templates and allow_template_variables:
                    return ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="invalid_resource",
                        message=f"Invalid `ARN` format even after normalizing template variables: `{resource}`",
                        resource=resource,
                        suggestion="`ARN` should follow format: `arn:partition:service:region:account-id:resource` (template variables like `${aws_account_id}` are supported)",
                        line_number=line_number,
                        field_name=field_name,
                    )
                else:
                    return ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="invalid_resource",
                        message=f"Invalid `ARN` format: `{resource}`",
                        resource=resource,
                        suggestion="`ARN` should follow format: `arn:partition:service:region:account-id:resource`",
                        line_number=line_number,
                        field_name=field_name,
                    )
        except Exception:  # pylint: disable=broad-exception-caught
            # If regex matching fails (shouldn't happen with length check), treat as invalid
            return ValidationIssue(
                severity=self.get_severity(config),
                statement_sid=statement_sid,
                statement_index=statement_idx,
                issue_type="invalid_resource",
                message=f"Could not validate `ARN` format: `{resource}`",
                resource=resource,
                suggestion="`ARN` validation failed - may contain unexpected characters",
                line_number=line_number,
                field_name=field_name,
            )

        return None

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute resource ARN validation on a statement.

        Validates both Resource and NotResource fields to ensure all specified
        ARNs follow the correct format.
        """
        del fetcher  # Unused
        issues = []

        statement_sid = statement.sid
        line_number = statement.line_number

        # Get ARN pattern from config, or use default
        # Pattern allows wildcards (*) in region and account fields
        arn_pattern_str = config.config.get("arn_pattern", DEFAULT_ARN_VALIDATION_PATTERN)

        # Compile pattern
        try:
            arn_pattern = re.compile(arn_pattern_str)
        except re.error:
            # Fallback to default pattern if custom pattern is invalid
            arn_pattern = re.compile(DEFAULT_ARN_VALIDATION_PATTERN)

        # Check if template variable support is enabled (default: true)
        # Try global settings first, then check-specific config
        allow_template_variables = config.root_config.get("settings", {}).get(
            "allow_template_variables",
            config.config.get("allow_template_variables", True),
        )

        # Validate Resource field
        for resource in statement.get_resources():
            issue = self._validate_resource(
                resource=resource,
                arn_pattern=arn_pattern,
                allow_template_variables=allow_template_variables,
                config=config,
                statement_sid=statement_sid,
                statement_idx=statement_idx,
                line_number=line_number,
                field_name="resource",
            )
            if issue:
                issues.append(issue)

        # Validate NotResource field (same validation - typos in NotResource are equally problematic)
        for resource in statement.get_not_resources():
            issue = self._validate_resource(
                resource=resource,
                arn_pattern=arn_pattern,
                allow_template_variables=allow_template_variables,
                config=config,
                statement_sid=statement_sid,
                statement_idx=statement_idx,
                line_number=line_number,
                field_name="not_resource",
            )
            if issue:
                issues.append(issue)

        return issues

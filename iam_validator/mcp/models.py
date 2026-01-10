"""Pydantic models for MCP tool request/response types.

This module defines MCP-specific models that extend the core validation models
for use with the FastMCP server implementation.
"""

from typing import Any

from pydantic import BaseModel, Field

from iam_validator.core.models import ValidationIssue


class ValidationResult(BaseModel):
    """Result of policy validation.

    Used by validation tools to return validation status and issues found.
    """

    is_valid: bool = Field(
        description="Whether the policy passed validation (no errors or warnings)"
    )
    issues: list[ValidationIssue] = Field(
        default_factory=list, description="List of validation issues found"
    )
    policy_file: str | None = Field(
        default=None, description="Path to the policy file that was validated"
    )
    policy_type_detected: str | None = Field(
        default=None,
        description="The policy type used for validation: 'identity', 'resource', or 'trust'. "
        "Shows auto-detected type when policy_type was not explicitly provided.",
    )


class GenerationResult(BaseModel):
    """Result of policy generation.

    Returned by all policy generation tools (from description, template, or actions).
    Always includes validation results and security notes.
    """

    policy: dict[str, Any] = Field(description="The generated IAM policy document")
    validation: ValidationResult = Field(description="Validation results for the generated policy")
    security_notes: list[str] = Field(
        default_factory=list,
        description="Security warnings and auto-applied conditions (e.g., 'Auto-added MFA condition')",
    )
    template_used: str | None = Field(
        default=None, description="Name of the template used for generation (if applicable)"
    )


class PolicySummary(BaseModel):
    """Summary of a policy's structure and contents.

    Provides high-level statistics about a policy for quick analysis.
    """

    total_statements: int = Field(description="Total number of statements in the policy")
    allow_statements: int = Field(description="Number of statements with Effect: Allow")
    deny_statements: int = Field(description="Number of statements with Effect: Deny")
    services_used: list[str] = Field(
        default_factory=list, description="List of AWS services referenced (e.g., ['s3', 'ec2'])"
    )
    actions_count: int = Field(description="Total number of unique actions across all statements")
    has_wildcards: bool = Field(
        description="Whether the policy contains wildcard actions or resources"
    )
    has_conditions: bool = Field(description="Whether the policy contains any conditions")


class ActionDetails(BaseModel):
    """Details about an AWS action.

    Returned by query tools to provide comprehensive information about an IAM action.
    """

    action: str = Field(description="Full action name (e.g., 's3:GetObject')")
    service: str = Field(description="AWS service prefix (e.g., 's3', 'ec2')")
    access_level: str = Field(
        description="Access level category: Read, Write, List, Tagging, or Permissions management"
    )
    resource_types: list[str] = Field(
        default_factory=list,
        description="Resource types this action can be applied to (e.g., ['bucket', 'object'])",
    )
    condition_keys: list[str] = Field(
        default_factory=list,
        description="Condition keys that can be used with this action",
    )
    description: str | None = Field(
        default=None, description="Human-readable description of what the action does"
    )


class EnforcementResult(BaseModel):
    """Result of security enforcement on a policy.

    Returned by the security enforcement layer after applying required conditions
    and validating security constraints.
    """

    policy: dict[str, Any] = Field(
        description="The policy after security enforcement (with auto-added conditions)"
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Security warnings for issues that were auto-fixed (e.g., 'Added MFA condition')",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Security errors that could not be auto-fixed (generation should fail)",
    )
    conditions_added: list[str] = Field(
        default_factory=list,
        description="List of conditions that were automatically added (e.g., 'aws:MultiFactorAuthPresent')",
    )

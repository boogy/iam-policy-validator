"""Pydantic models for MCP tool request/response types.

This module defines MCP-specific models that extend the core validation models
for use with the FastMCP server implementation.
"""

from pydantic import BaseModel, Field

from iam_validator.core.models import ValidationIssue


class ValidationResult(BaseModel):
    """Result of policy validation.

    Used by validation tools to return validation status and issues found.
    """

    is_valid: bool = Field(description="Whether the policy passed validation (no errors or warnings)")
    issues: list[ValidationIssue] = Field(default_factory=list, description="List of validation issues found")
    policy_file: str | None = Field(default=None, description="Path to the policy file that was validated")
    policy_type_detected: str | None = Field(
        default=None,
        description="The policy type used for validation: 'identity', 'resource', or 'trust'. "
        "Shows auto-detected type when policy_type was not explicitly provided.",
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
    has_wildcards: bool = Field(description="Whether the policy contains wildcard actions or resources")
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
    description: str | None = Field(default=None, description="Human-readable description of what the action does")

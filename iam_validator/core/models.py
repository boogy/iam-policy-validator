"""Data models for AWS IAM policy validation.

This module defines Pydantic models for AWS service information,
IAM policies, and validation results.
"""

from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

from iam_validator.core import constants

# Policy Type Constants
PolicyType = Literal[
    "IDENTITY_POLICY",
    "RESOURCE_POLICY",
    "TRUST_POLICY",  # Trust policies (role assumption policies - subtype of resource policies)
    "SERVICE_CONTROL_POLICY",
    "RESOURCE_CONTROL_POLICY",
]


# AWS Service Reference Models
class ServiceInfo(BaseModel):
    """Basic information about an AWS service."""

    service: str
    url: str


class ActionDetail(BaseModel):
    """Details about an AWS IAM action."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True)

    name: str = Field(alias="Name")
    action_condition_keys: list[str] | None = Field(
        default_factory=list, alias="ActionConditionKeys"
    )
    resources: list[dict[str, Any]] | None = Field(default_factory=list, alias="Resources")
    annotations: dict[str, Any] | None = Field(default=None, alias="Annotations")
    supported_by: dict[str, Any] | None = Field(default=None, alias="SupportedBy")


class ResourceType(BaseModel):
    """Details about an AWS resource type."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True)

    name: str = Field(alias="Name")
    arn_formats: list[str] | None = Field(default=None, alias="ARNFormats")
    condition_keys: list[str] | None = Field(default_factory=list, alias="ConditionKeys")

    @property
    def arn_pattern(self) -> str | None:
        """
        Get the first ARN format for backwards compatibility.

        AWS provides ARN formats as an array (ARNFormats), but most code
        just needs a single pattern. This property returns the first one.

        Returns:
            First ARN format string, or None if no formats are defined
        """
        return self.arn_formats[0] if self.arn_formats else None


class ConditionKey(BaseModel):
    """Details about an AWS condition key."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True)

    name: str = Field(alias="Name")
    description: str | None = Field(default=None, alias="Description")
    types: list[str] | None = Field(default_factory=list, alias="Types")


class ServiceDetail(BaseModel):
    """Detailed information about an AWS service."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True)

    name: str = Field(alias="Name")
    prefix: str | None = None  # Not always present in API response
    actions: dict[str, ActionDetail] = Field(default_factory=dict)
    resources: dict[str, ResourceType] = Field(default_factory=dict)
    condition_keys: dict[str, ConditionKey] = Field(default_factory=dict)
    version: str | None = Field(default=None, alias="Version")

    # Raw API data
    actions_list: list[ActionDetail] = Field(default_factory=list, alias="Actions")
    resources_list: list[ResourceType] = Field(default_factory=list, alias="Resources")
    condition_keys_list: list[ConditionKey] = Field(default_factory=list, alias="ConditionKeys")

    def model_post_init(self, __context: Any, /) -> None:
        """Convert lists to dictionaries for easier lookup."""
        # Convert actions list to dict
        self.actions = {action.name: action for action in self.actions_list}
        # Convert resources list to dict
        self.resources = {resource.name: resource for resource in self.resources_list}
        # Convert condition keys list to dict
        self.condition_keys = {ck.name: ck for ck in self.condition_keys_list}


# IAM Policy Models
class Statement(BaseModel):
    """IAM policy statement."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, extra="allow")

    sid: str | None = Field(default=None, alias="Sid")
    effect: str | None = Field(default=None, alias="Effect")
    action: list[str] | str | None = Field(default=None, alias="Action")
    not_action: list[str] | str | None = Field(default=None, alias="NotAction")
    resource: list[str] | str | None = Field(default=None, alias="Resource")
    not_resource: list[str] | str | None = Field(default=None, alias="NotResource")
    condition: dict[str, dict[str, Any]] | None = Field(default=None, alias="Condition")
    principal: dict[str, Any] | str | None = Field(default=None, alias="Principal")
    not_principal: dict[str, Any] | str | None = Field(default=None, alias="NotPrincipal")
    # Line number metadata (populated during parsing)
    line_number: int | None = Field(default=None, exclude=True)

    def get_actions(self) -> list[str]:
        """Get list of actions, handling both string and list formats."""
        if self.action is None:
            return []
        return [self.action] if isinstance(self.action, str) else self.action

    def get_not_actions(self) -> list[str]:
        """Get list of NotAction values, handling both string and list formats."""
        if self.not_action is None:
            return []
        return [self.not_action] if isinstance(self.not_action, str) else self.not_action

    def get_resources(self) -> list[str]:
        """Get list of resources, handling both string and list formats."""
        if self.resource is None:
            return []
        return [self.resource] if isinstance(self.resource, str) else self.resource

    def get_not_resources(self) -> list[str]:
        """Get list of NotResource values, handling both string and list formats."""
        if self.not_resource is None:
            return []
        return [self.not_resource] if isinstance(self.not_resource, str) else self.not_resource


class IAMPolicy(BaseModel):
    """IAM policy document."""

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True, extra="allow")

    version: str | None = Field(default=None, alias="Version")
    statement: list[Statement] | None = Field(default=None, alias="Statement")
    id: str | None = Field(default=None, alias="Id")


# Validation Result Models
class ValidationIssue(BaseModel):
    """A single validation issue found in a policy.

    Severity Levels:
    - IAM Validity: "error", "warning", "info"
      (for issues that make the policy invalid according to AWS IAM rules)
    - Security: "critical", "high", "medium", "low"
      (for security best practices and configuration issues)
    """

    severity: str  # "error", "warning", "info" OR "critical", "high", "medium", "low"
    statement_sid: str | None = None
    statement_index: int
    issue_type: str  # "invalid_action", "invalid_condition_key", "invalid_resource", etc.
    message: str
    action: str | None = None
    resource: str | None = None
    condition_key: str | None = None
    suggestion: str | None = None
    example: str | None = None  # Code example (JSON/YAML) - formatted separately for GitHub
    line_number: int | None = None  # Line number in the policy file (if available)
    check_id: str | None = (
        None  # Check that triggered this issue (e.g., "policy_size", "sensitive_action")
    )
    # Field that caused the issue (for precise line detection in PR comments)
    # Values: "action", "resource", "condition", "principal", "effect", "sid"
    field_name: str | None = None

    # Enhanced finding quality fields (Phase 3)
    # Explains why this issue is a security risk or compliance concern
    risk_explanation: str | None = None
    # Link to relevant AWS documentation or org-specific runbook
    documentation_url: str | None = None
    # Step-by-step remediation guidance
    remediation_steps: list[str] | None = None
    # Risk category for classification (e.g., "privilege_escalation", "data_exfiltration")
    risk_category: str | None = None

    # Severity level constants (ClassVar to avoid Pydantic treating them as fields)
    VALID_SEVERITIES: ClassVar[frozenset[str]] = frozenset(
        [
            "error",
            "warning",
            "info",  # IAM validity severities
            "critical",
            "high",
            "medium",
            "low",  # Security severities
        ]
    )

    # Severity ordering for fail_on_severity (higher value = more severe)
    SEVERITY_RANK: ClassVar[dict[str, int]] = {
        "error": 100,  # IAM validity errors (highest)
        "critical": 90,  # Critical security issues
        "high": 70,  # High security issues
        "warning": 50,  # IAM validity warnings
        "medium": 40,  # Medium security issues
        "low": 20,  # Low security issues
        "info": 10,  # Informational (lowest)
    }

    def get_severity_rank(self) -> int:
        """Get the numeric rank of this issue's severity (higher = more severe)."""
        return self.SEVERITY_RANK.get(self.severity, 0)

    def is_security_severity(self) -> bool:
        """Check if this issue uses security severity levels (critical/high/medium/low)."""
        return self.severity in {"critical", "high", "medium", "low"}

    def is_validity_severity(self) -> bool:
        """Check if this issue uses IAM validity severity levels (error/warning/info)."""
        return self.severity in {"error", "warning", "info"}

    def to_pr_comment(self, include_identifier: bool = True, file_path: str = "") -> str:
        """Format issue as a PR comment.

        Args:
            include_identifier: Whether to include bot identifier (for cleanup)
            file_path: Relative path to the policy file (for finding ID)

        Returns:
            Formatted comment string
        """
        # Get severity config with emoji and action guidance
        severity_config = constants.SEVERITY_CONFIG.get(
            self.severity, {"emoji": "•", "action": "Review"}
        )
        emoji = severity_config["emoji"]
        action = severity_config["action"]

        # Get risk category icon if available
        from iam_validator.core.config.check_documentation import RISK_CATEGORY_ICONS

        risk_icon = ""
        if self.risk_category:
            icon = RISK_CATEGORY_ICONS.get(self.risk_category, "")
            if icon:
                # Format risk category for display (e.g., "privilege_escalation" -> "Privilege Escalation")
                category_display = self.risk_category.replace("_", " ").title()
                risk_icon = f" | {icon} {category_display}"

        parts = []

        # Add identifier for bot comment cleanup (HTML comment - not visible to users)
        if include_identifier:
            parts.append(f"{constants.REVIEW_IDENTIFIER}\n")
            parts.append(f"{constants.BOT_IDENTIFIER}\n")
            # Add issue type identifier to allow multiple issues at same line
            parts.append(f"<!-- issue-type: {self.issue_type} -->\n")
            # Add finding ID for ignore tracking
            if file_path:
                from iam_validator.core.finding_fingerprint import compute_finding_hash

                finding_hash = compute_finding_hash(
                    file_path=file_path,
                    check_id=self.check_id,
                    issue_type=self.issue_type,
                    statement_sid=self.statement_sid,
                    statement_index=self.statement_index,
                    action=self.action,
                    resource=self.resource,
                    condition_key=self.condition_key,
                )
                parts.append(f"<!-- finding-id: {finding_hash} -->\n")

        # Main issue header with severity, action guidance, and risk category
        parts.append(f"{emoji} **{self.severity.upper()}** - {action}{risk_icon}")
        parts.append("")

        # Build statement context for better navigation
        statement_context = f"Statement[{self.statement_index}]"
        if self.statement_sid:
            statement_context = f"`{self.statement_sid}` ({statement_context})"
        if self.line_number:
            statement_context = f"{statement_context} (line {self.line_number})"

        # Statement context on its own line
        parts.append(f"**Statement:** {statement_context}")
        parts.append("")

        # Show message immediately (not collapsed)
        parts.append(self.message)

        # Add risk explanation if present (shown prominently)
        if self.risk_explanation:
            parts.append("")
            parts.append(f"> **Why this matters:** {self.risk_explanation}")

        # Put additional details in collapsible section if there are any
        has_details = bool(
            self.action
            or self.resource
            or self.condition_key
            or self.suggestion
            or self.example
            or self.remediation_steps
        )

        if has_details:
            parts.append("")
            parts.append("<details>")
            parts.append("<summary>📋 <b>View Details</b></summary>")
            parts.append("")
            parts.append("")  # Extra spacing after opening

            # Add affected fields section if any are present
            if self.action or self.resource or self.condition_key:
                parts.append("**Affected Fields:**")
                if self.action:
                    parts.append(f"  - Action: `{self.action}`")
                if self.resource:
                    parts.append(f"  - Resource: `{self.resource}`")
                if self.condition_key:
                    parts.append(f"  - Condition Key: `{self.condition_key}`")
                parts.append("")

            # Add remediation steps if present
            if self.remediation_steps:
                parts.append("**🔧 How to Fix:**")
                for i, step in enumerate(self.remediation_steps, 1):
                    parts.append(f"  {i}. {step}")
                parts.append("")

            # Add suggestion if present
            if self.suggestion:
                parts.append("**💡 Suggested Fix:**")
                parts.append("")
                parts.append(self.suggestion)
                parts.append("")

            # Add example if present (formatted as JSON code block for GitHub)
            if self.example:
                parts.append("**Example:**")
                parts.append("```json")
                parts.append(self.example)
                parts.append("```")

            parts.append("")
            parts.append("</details>")

        # Add check ID and documentation link at the bottom
        footer_parts = []
        if self.check_id:
            footer_parts.append(f"*Check: `{self.check_id}`*")
        if self.documentation_url:
            footer_parts.append(f"[📖 Documentation]({self.documentation_url})")

        if footer_parts:
            parts.append("")
            parts.append("---")
            parts.append(" | ".join(footer_parts))

        return "\n".join(parts)


class PolicyValidationResult(BaseModel):
    """Result of validating a single IAM policy."""

    policy_file: str
    is_valid: bool
    policy_type: PolicyType = "IDENTITY_POLICY"
    issues: list[ValidationIssue] = Field(default_factory=list)
    actions_checked: int = 0
    condition_keys_checked: int = 0
    resources_checked: int = 0


class ValidationReport(BaseModel):
    """Complete validation report for all policies."""

    total_policies: int
    valid_policies: int
    invalid_policies: int  # Policies with IAM validity issues (error/warning)
    policies_with_security_issues: int = (
        0  # Policies with security findings (critical/high/medium/low)
    )
    total_issues: int
    validity_issues: int = 0  # Count of IAM validity issues (error/warning/info)
    security_issues: int = 0  # Count of security issues (critical/high/medium/low)
    results: list[PolicyValidationResult] = Field(default_factory=list)
    parsing_errors: list[tuple[str, str]] = Field(
        default_factory=list
    )  # (file_path, error_message)

    def get_summary(self) -> str:
        """Generate a human-readable summary."""
        parts = []
        parts.append(f"Validated {self.total_policies} policies:")

        # Always show valid/invalid counts
        parts.append(f"{self.valid_policies} valid")

        if self.invalid_policies > 0:
            parts.append(f"{self.invalid_policies} invalid (IAM validity)")

        if self.policies_with_security_issues > 0:
            parts.append(f"{self.policies_with_security_issues} with security findings")

        parts.append(f"{self.total_issues} total issues")

        # Show breakdown if there are issues
        if self.total_issues > 0 and (self.validity_issues > 0 or self.security_issues > 0):
            breakdown_parts = []
            if self.validity_issues > 0:
                breakdown_parts.append(f"{self.validity_issues} validity")
            if self.security_issues > 0:
                breakdown_parts.append(f"{self.security_issues} security")
            parts.append(f"({', '.join(breakdown_parts)})")

        return " ".join(parts)

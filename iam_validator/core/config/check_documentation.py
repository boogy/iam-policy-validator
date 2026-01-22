"""Check Documentation Registry.

This module provides centralized documentation for all built-in checks,
including risk explanations, AWS documentation links, and remediation steps.

Used to enhance ValidationIssue objects with actionable guidance.
"""

from dataclasses import dataclass, field
from typing import ClassVar

# Risk category icons for display in PR comments
RISK_CATEGORY_ICONS = {
    "privilege_escalation": "🔐",
    "data_exfiltration": "📤",
    "denial_of_service": "🚫",
    "resource_exposure": "🌐",
    "credential_exposure": "🔑",
    "compliance": "📋",
    "configuration": "⚙️",
    "validation": "✅",
}


@dataclass
class CheckDocumentation:
    """Documentation for a single check.

    Attributes:
        check_id: Unique check identifier (e.g., "wildcard_action")
        risk_explanation: Why this issue is a security risk
        documentation_url: Link to relevant AWS docs or runbook
        remediation_steps: Step-by-step fix guidance
        risk_category: Category of risk (e.g., "privilege_escalation", "data_exfiltration")
    """

    check_id: str
    risk_explanation: str
    documentation_url: str
    remediation_steps: list[str] = field(default_factory=list)
    risk_category: str | None = None


class CheckDocumentationRegistry:
    """Registry for check documentation.

    Provides centralized lookup for risk explanations, documentation links,
    and remediation steps for all built-in checks.
    """

    # AWS IAM documentation base URLs
    AWS_IAM_DOCS = "https://docs.aws.amazon.com/IAM/latest/UserGuide"
    AWS_IAM_REFERENCE = "https://docs.aws.amazon.com/service-authorization/latest/reference"

    # Registry of all check documentation
    _registry: ClassVar[dict[str, CheckDocumentation]] = {}

    @classmethod
    def register(cls, doc: CheckDocumentation) -> None:
        """Register documentation for a check."""
        cls._registry[doc.check_id] = doc

    @classmethod
    def get(cls, check_id: str) -> CheckDocumentation | None:
        """Get documentation for a check by ID."""
        return cls._registry.get(check_id)

    @classmethod
    def get_risk_explanation(cls, check_id: str) -> str | None:
        """Get risk explanation for a check."""
        doc = cls.get(check_id)
        return doc.risk_explanation if doc else None

    @classmethod
    def get_documentation_url(cls, check_id: str) -> str | None:
        """Get documentation URL for a check."""
        doc = cls.get(check_id)
        return doc.documentation_url if doc else None

    @classmethod
    def get_remediation_steps(cls, check_id: str) -> list[str] | None:
        """Get remediation steps for a check."""
        doc = cls.get(check_id)
        return doc.remediation_steps if doc else None


# Register documentation for all built-in checks
# ==============================================

# AWS Validation Checks
# ---------------------

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="action_validation",
        risk_explanation=(
            "Invalid `Action`s may silently fail to grant intended permissions, "
            "or indicate a typo that could expose unintended access."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_REFERENCE}/reference_policies_actions-resources-contextkeys.html",
        remediation_steps=[
            "Verify the `Action` name against AWS documentation for the target service",
            "Use the AWS IAM policy simulator to test your intended permissions",
            "Check for common typos (e.g., `S3` vs `s3`, `GetObjects` vs `GetObject`)",
        ],
        risk_category="validation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="condition_key_validation",
        risk_explanation=(
            "Invalid condition keys are silently ignored by AWS IAM, meaning your "
            "intended access restrictions may not be enforced."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/reference_policies_condition-keys.html",
        remediation_steps=[
            "Verify the `Condition` key exists for the target service",
            "Check AWS documentation for the correct `Condition` key name and format for the target service",
            "Use global condition keys (`aws:*`) for cross-service restrictions",
        ],
        risk_category="validation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="condition_type_mismatch",
        risk_explanation=(
            "Using the wrong condition operator type (e.g., `StringEquals` with a "
            "numeric value) may cause unexpected behavior or silent failures."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/reference_policies_elements_condition_operators.html",
        remediation_steps=[
            "Match the condition operator to the `Condition` key's data type",
            "Use `String` operators for string keys, `Numeric` for numbers, `Date` for timestamps",
            "Consider using `IfExists` variants for optional conditions",
        ],
        risk_category="validation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="resource_validation",
        risk_explanation=(
            "Invalid `Resource` ARNs may silently fail to match intended resources, "
            "leaving permissions ineffective or overly broad."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_REFERENCE}/reference_policies_actions-resources-contextkeys.html",
        remediation_steps=[
            "Verify `Resource` ARN format matches the target service's documentation",
            "Ensure region and account ID are correct or use wildcards intentionally",
            "Test the policy with AWS IAM policy simulator before deployment",
        ],
        risk_category="validation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="sid_uniqueness",
        risk_explanation=(
            "Duplicate SIDs can cause confusion and make policy auditing difficult. "
            "Some AWS services may behave unexpectedly with duplicate SIDs."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/reference_policies_elements_sid.html",
        remediation_steps=[
            "Ensure each statement has a unique SID within the policy",
            "Use descriptive SIDs that indicate the statement's purpose",
            "Consider a naming convention like 'AllowS3ReadAccess' or 'DenyPublicAccess'",
        ],
        risk_category="compliance",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="policy_size",
        risk_explanation=(
            "Policies exceeding AWS size limits cannot be attached to IAM entities. "
            "Inline policies have a 2KB limit, managed policies have a 6KB limit (for the entire policy document)."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/reference_iam-quotas.html",
        remediation_steps=[
            "Split large policies into multiple smaller policies",
            "Use managed policies instead of inline policies for larger permissions",
            "Remove redundant statements or consolidate similar `Action`s",
            "Consider using permission boundaries or SCPs for broad restrictions",
        ],
        risk_category="validation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="policy_structure",
        risk_explanation=(
            "Malformed policy structure will cause AWS IAM to reject the policy entirely, "
            "preventing any permissions from being granted."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/reference_policies_grammar.html",
        remediation_steps=[
            "Verify the policy follows AWS IAM policy grammar",
            "Ensure all required elements (`Version`, `Statement`) are present",
            "Check that `Effect`, `Action`, and `Resource` are properly formatted",
        ],
        risk_category="validation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="set_operator_validation",
        risk_explanation=(
            "Invalid `ForAllValues`/`ForAnyValue` operators may cause conditions to "
            "behave unexpectedly, potentially granting or denying unintended access."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/reference_policies_multi-value-conditions.html",
        remediation_steps=[
            "Use `ForAllValues` when ALL values must match the condition",
            "Use `ForAnyValue` when ANY value matching is sufficient",
            "Consider the empty set behavior: `ForAllValues` returns true for empty sets",
        ],
        risk_category="validation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="mfa_condition_check",
        risk_explanation=(
            "Sensitive operations without MFA requirements may be performed by "
            "compromised credentials, increasing the blast radius of credential theft."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/id_credentials_mfa_configure-api-require.html",
        remediation_steps=[
            "Add `aws:MultiFactorAuthPresent`: `true` condition for sensitive actions",
            "Consider using `aws:MultiFactorAuthAge` to require recent MFA",
            "Ensure MFA is enforced at the identity level as well as policy level",
        ],
        risk_category="credential_exposure",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="principal_validation",
        risk_explanation=(
            "Invalid principals in resource policies may fail to grant access to "
            "intended entities, or may inadvertently grant access to unintended parties."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/reference_policies_elements_principal.html",
        remediation_steps=[
            "Verify AWS account IDs and IAM ARNs are correct",
            "Use specific principals instead of wildcards where possible",
            "For service principals, use the canonical format (e.g., 's3.amazonaws.com')",
        ],
        risk_category="resource_exposure",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="policy_type_validation",
        risk_explanation=(
            "Using policy elements not supported by the policy type may cause "
            "silent failures or unexpected behavior."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/access_policies.html",
        remediation_steps=[
            "Identity policies: Don't include `Principal` element",
            "Resource policies: Include `Principal` element",
            "SCPs: Use only `Allow` statements with specific conditions",
        ],
        risk_category="configuration",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="action_resource_matching",
        risk_explanation=(
            "`Action`s that don't support the specified `Resource`s will silently fail, "
            "resulting in permissions that don't work as intended."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_REFERENCE}/reference_policies_actions-resources-contextkeys.html",
        remediation_steps=[
            "Check AWS documentation for supported resource types per action",
            "Use `*` (wildcard) for actions that don't support resource-level permissions",
            "Split statements when actions require different resource types",
        ],
        risk_category="validation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="trust_policy_validation",
        risk_explanation=(
            "Misconfigured trust policies can allow unauthorized principals to "
            "assume roles, potentially leading to privilege escalation."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/id_roles_create_for-user.html",
        remediation_steps=[
            "Restrict `Principal` to specific accounts/roles/users (e.g., `arn:aws:iam::123456789012:role/foo`)",
            "Add conditions to limit who can assume the role",
            "Avoid wildcards in `Principal` unless absolutely necessary",
            "Use ExternalId for cross-account role assumption",
        ],
        risk_category="privilege_escalation",
    )
)

# Security Checks
# ---------------

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="wildcard_action",
        risk_explanation=(
            "Wildcard actions (e.g., `s3:*`) grant all current AND future permissions "
            "for a service, violating least privilege and increasing attack surface."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/best-practices.html#grant-least-privilege",
        remediation_steps=[
            "Replace wildcards with specific `Action` lists needed for the use case",
            "Use action groups like `s3:Get*` for read-only access",
            "Review and reduce permissions periodically if not needed",
        ],
        risk_category="privilege_escalation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="wildcard_resource",
        risk_explanation=(
            "Wildcard resources (`*`) grant access to ALL resources of a type, "
            "including resources created in the future, violating least privilege."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/best-practices.html#grant-least-privilege",
        remediation_steps=[
            "Specify exact `Resource` ARNs when possible",
            "Use resource tags and conditions for dynamic access control (ABAC)",
            "Limit scope to specific accounts, regions, or resource prefixes",
            "Use `aws:ResourceAccount`, `aws:ResourceOrgID`, or `aws:ResourceOrgPaths` conditions to restrict scope",
        ],
        risk_category="resource_exposure",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="full_wildcard",
        risk_explanation=(
            "Full wildcard access ('Action': '*', 'Resource': '*') grants complete "
            "control over all AWS resources, equivalent to administrator access."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/best-practices.html#grant-least-privilege",
        remediation_steps=[
            "Immediately restrict to specific services and actions needed",
            "Use AWS managed policies like PowerUserAccess for broad access",
            "Implement permission boundaries to limit maximum possible permissions",
            "Consider using service control policies (SCPs) as guardrails",
        ],
        risk_category="privilege_escalation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="service_wildcard",
        risk_explanation=(
            "Service-level wildcards (e.g., `iam:*`) grant all permissions for "
            "an entire service, including destructive and privilege escalation actions."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/best-practices.html#grant-least-privilege",
        remediation_steps=[
            "Replace with specific actions required for the use case",
            "Use AWS managed policies for common patterns",
            "Consider permission boundaries to limit sensitive actions and enforce least privilege",
        ],
        risk_category="privilege_escalation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="sensitive_action",
        risk_explanation=(
            "Sensitive actions (e.g., `iam:*`, `sts:AssumeRole`, `kms:Decrypt`) can lead "
            "to privilege escalation, data exfiltration, or account compromise."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/best-practices.html#grant-least-privilege",
        remediation_steps=[
            "Add conditions to restrict when these actions can be used",
            "Require Attribute Based Access Control (ABAC) for sensitive operations",
            "Limit to specific resources and accounts where possible",
        ],
        risk_category="privilege_escalation",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="action_condition_enforcement",
        risk_explanation=(
            "Certain sensitive actions should always have conditions to prevent "
            "misuse, such as Account/Organization boundaries, VPC/VPCe restrictions, MFA requirements, or time-based access."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/reference_policies_elements_condition.html",
        remediation_steps=[
            "Add appropriate conditions based on the action type",
            "Use `aws:ResourceAccount` and `aws:PrincipalAccount` for account-restricted actions",
            "Use `aws:ResourceOrgID` and `aws:PrincipalOrgID` for organization-restricted actions",
            "Use `aws:SourceVpc` or `aws:SourceVpce` for VPC-restricted actions",
            "Use `aws:SourceIp` for network-restricted actions",
            "Use `aws:RequestedRegion` to limit geographic scope",
        ],
        risk_category="compliance",
    )
)

CheckDocumentationRegistry.register(
    CheckDocumentation(
        check_id="not_action_not_resource",
        risk_explanation=(
            "`NotAction` and `NotResource` grant permissions by exclusion rather than "
            "inclusion. This can accidentally grant far more access than intended, "
            "including access to actions and resources created in the future."
        ),
        documentation_url=f"{CheckDocumentationRegistry.AWS_IAM_DOCS}/reference_policies_elements_notaction.html",
        remediation_steps=[
            "Replace `NotAction` with explicit `Action` lists when possible",
            "Replace `NotResource` with specific `Resource` ARNs",
            "If `NotAction` is required, add strict conditions (`aws:SourceIp`, `aws:SourceVpc`, `aws:SourceVpce`, `aws:ResourceAccount`, `aws:ResourceOrgID`, `aws:RequestedRegion`, etc.)",
            "Document why exclusion-based permissions are necessary",
        ],
        risk_category="privilege_escalation",
    )
)

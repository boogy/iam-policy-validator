"""Policy structure validation check.

This check validates the fundamental structure of IAM policy statements,
ensuring they meet AWS IAM requirements. It checks for:

1. Required fields (Effect, Action/NotAction, Resource/NotResource)
2. Mutual exclusivity (Action vs NotAction, Resource vs NotResource, Principal vs NotPrincipal)
3. Valid field values (Effect must be "Allow" or "Deny")
4. Unknown/unexpected fields in statements
5. Valid Version field in policy document

This check is inspired by Parliament's analyze_statement function and should run
BEFORE all other checks to catch fundamental structural issues early.

By detecting these issues early, we can:
- Provide detailed error messages about what's wrong
- Post specific findings to GitHub for user feedback
- Allow other checks to run and find additional issues
- Help users fix policies that would otherwise be rejected by Pydantic validation
"""

import re
from typing import Any, ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import IAMPolicy, PolicyType, ValidationIssue

# Valid statement fields according to AWS IAM policy grammar
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
VALID_STATEMENT_FIELDS = {
    "Effect",
    "Sid",
    "Principal",
    "NotPrincipal",
    "Action",
    "NotAction",
    "Resource",
    "NotResource",
    "Condition",
}

# Valid policy document fields
VALID_POLICY_FIELDS = {
    "Version",
    "Statement",
    "Id",
}

# Valid AWS IAM policy versions
VALID_POLICY_VERSIONS = {"2012-10-17", "2008-10-17"}

# Valid Effect values
VALID_EFFECTS = {"Allow", "Deny"}

# SID format: alphanumeric characters only (no spaces, hyphens, or underscores in AWS strict grammar)
# However, AWS console and APIs often accept hyphens and underscores, so we allow them
SID_PATTERN = re.compile(r"^[a-zA-Z0-9]+$")

# Assume role actions used in trust policies (frozen set for O(1) lookup performance)
ASSUME_ROLE_ACTIONS = frozenset(
    {
        "sts:AssumeRole",
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity",
        "sts:TagSession",
        "sts:SetSourceIdentity",
        "sts:SetContext",
    }
)


def is_trust_policy(policy: IAMPolicy) -> bool:
    """Detect if policy is a trust policy (role assumption policy).

    Trust policies are a special type of resource policy attached to IAM roles.
    They control who can assume the role.

    Battle-hardened detection logic (minimizes false positives):
    1. Has Principal element (resource policy characteristic)
    2. Contains assume role actions (sts:AssumeRole*, sts:TagSession)
    3. Effect is "Allow" (trust policies grant assumption, never Deny)
    4. No specific resource ARNs (role itself is the resource; only * or *:* allowed)

    Conservative approach prevents false positives:
    - Exact action matching (not just startswith)
    - Rejects policies with specific resource ARNs
    - Validates Effect is Allow

    Args:
        policy: IAM policy to analyze

    Returns:
        True if policy appears to be a trust policy

    Examples:
        Trust policy (returns True):
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
             "Action": "sts:AssumeRole"}

        S3 bucket policy (returns False - has specific resources):
            {"Effect": "Allow", "Principal": "*",
             "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}
    """
    # First pass: Check if ANY statement has specific resource ARNs
    # Trust policies don't have specific resource ARNs (role itself is the resource)
    for statement in policy.statement or []:
        if statement.resource:
            resources = (
                [statement.resource] if isinstance(statement.resource, str) else statement.resource
            )
            for resource in resources:
                if isinstance(resource, str) and resource != "*" and not resource.endswith(":*"):
                    # Specific resource ARN found in ANY statement - NOT a trust policy
                    # Trust policies should only have *, *:*, or no Resource field
                    return False

    # Second pass: Check for valid assume statements
    has_valid_assume_statement = False

    for statement in policy.statement or []:
        # Skip if no principal (trust policies must have principals)
        if statement.principal is None and statement.not_principal is None:
            continue

        # Skip if Effect is Deny (trust policies use Allow)
        if statement.effect and statement.effect.lower() != "allow":
            continue

        # Get actions (handle both string and list)
        actions = []
        if statement.action:
            actions = [statement.action] if isinstance(statement.action, str) else statement.action

        # Check if any action is an assume action (O(1) set lookup)
        has_assume_action = any(
            action in ASSUME_ROLE_ACTIONS or action in ("sts:*", "*")
            for action in actions
            if isinstance(action, str)
        )

        if has_assume_action:
            # Found a valid trust policy statement
            has_valid_assume_statement = True
            # Continue checking - we already validated no specific resources in first pass

    return has_valid_assume_statement


def detect_policy_type(policy: IAMPolicy) -> PolicyType:
    """Auto-detect policy type based on statement structure.

    Detection logic (simple and safe - avoids false positives):
    1. If any statement has Principal/NotPrincipal → RESOURCE_POLICY
    2. Otherwise → IDENTITY_POLICY (default, also covers SCPs)

    Note: The following policy types require EXPLICIT specification via --policy-type flag
    and are NOT auto-detected to avoid false positives and confusing errors:

    - TRUST_POLICY: Requires explicit flag to enable trust-specific validation
      and suppress irrelevant warnings (missing Resource field, etc.)
      Use: --policy-type TRUST_POLICY

    - SERVICE_CONTROL_POLICY: SCPs have the same structure as identity policies
      and cannot be reliably distinguished without context
      Use: --policy-type SERVICE_CONTROL_POLICY

    - RESOURCE_CONTROL_POLICY: RCPs have strict requirements that require explicit
      validation mode to avoid false positives
      Use: --policy-type RESOURCE_CONTROL_POLICY

    Auto-detection only distinguishes between:
    - IDENTITY_POLICY (no Principal element) - most common
    - RESOURCE_POLICY (has Principal element) - S3, SNS, SQS, etc.

    Args:
        policy: IAM policy to analyze

    Returns:
        Detected PolicyType (IDENTITY_POLICY or RESOURCE_POLICY only)
    """
    # Check if any statement has Principal/NotPrincipal (indicates resource policy)
    for statement in policy.statement or []:
        if statement.principal is not None or statement.not_principal is not None:
            return "RESOURCE_POLICY"

    # Default to identity policy (most common case)
    # SCPs have the same structure and will be detected as IDENTITY_POLICY
    return "IDENTITY_POLICY"


def validate_policy_document(policy_dict: dict[str, Any]) -> list[ValidationIssue]:
    """Validate the top-level policy document structure.

    Args:
        policy_dict: Raw policy dictionary

    Returns:
        List of validation issues
    """
    issues: list[ValidationIssue] = []

    # Check for unknown fields in policy document
    unknown_fields = set(policy_dict.keys()) - VALID_POLICY_FIELDS
    if unknown_fields:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_index=-1,  # Policy-level issue
                issue_type="unknown_policy_field",
                message=f"Policy document contains unknown field(s): {', '.join(sorted(f'`{f}`' for f in unknown_fields))}",
                suggestion=f"Remove the unknown field(s). Valid policy fields are: {', '.join(f'`{f}`' for f in sorted(VALID_POLICY_FIELDS))}",
                example=('{\n  "Version": "2012-10-17",\n  "Statement": [...]\n}'),
            )
        )

    # Validate Version field
    if "Version" not in policy_dict:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_index=-1,
                issue_type="missing_version",
                message="Policy document is missing the `Version` field",
                suggestion="Add a `Version` field with value `2012-10-17` (recommended) or `2008-10-17`",
                example=('{\n  "Version": "2012-10-17",\n  "Statement": [...]\n}'),
            )
        )
    elif policy_dict["Version"] not in VALID_POLICY_VERSIONS:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_index=-1,
                issue_type="invalid_version",
                message=f"Invalid policy `Version`: `{policy_dict['Version']}`. Must be `2012-10-17` or `2008-10-17`",
                suggestion="Use `Version` `2012-10-17` (recommended) for the latest IAM policy grammar",
                example=('{\n  "Version": "2012-10-17",\n  "Statement": [...]\n}'),
            )
        )

    # Validate Statement field
    if "Statement" not in policy_dict:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_index=-1,
                issue_type="missing_statement",
                message="Policy document is missing the `Statement` field",
                suggestion="Add a `Statement` field containing an array of policy statements",
                example=(
                    "{\n"
                    '  "Version": "2012-10-17",\n'
                    '  "Statement": [\n'
                    "    {\n"
                    '      "Effect": "Allow",\n'
                    '      "Action": "s3:GetObject",\n'
                    '      "Resource": "*"\n'
                    "    }\n"
                    "  ]\n"
                    "}"
                ),
            )
        )
    elif not isinstance(policy_dict["Statement"], list):
        issues.append(
            ValidationIssue(
                severity="error",
                statement_index=-1,
                issue_type="invalid_statement_type",
                message=f"`Statement` field must be an array, not `{type(policy_dict['Statement']).__name__}`",
                suggestion="Wrap your statement in an array: [ {...} ]",
                example=(
                    "{\n"
                    '  "Version": "2012-10-17",\n'
                    '  "Statement": [\n'
                    "    {\n"
                    '      "Effect": "Allow",\n'
                    '      "Action": "s3:GetObject",\n'
                    '      "Resource": "*"\n'
                    "    }\n"
                    "  ]\n"
                    "}"
                ),
            )
        )
    elif len(policy_dict["Statement"]) == 0:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_index=-1,
                issue_type="empty_statement",
                message="Policy document has an empty `Statement` array",
                suggestion="Add at least one policy `Statement`",
                example=(
                    "{\n"
                    '  "Version": "2012-10-17",\n'
                    '  "Statement": [\n'
                    "    {\n"
                    '      "Effect": "Allow",\n'
                    '      "Action": "s3:GetObject",\n'
                    '      "Resource": "*"\n'
                    "    }\n"
                    "  ]\n"
                    "}"
                ),
            )
        )

    return issues


def validate_statement_structure(
    statement_dict: dict[str, Any], statement_idx: int, policy_type: str = "IDENTITY_POLICY"
) -> list[ValidationIssue]:
    """Validate the structure of a single statement.

    This implements validation similar to Parliament's analyze_statement function.

    Args:
        statement_dict: Raw statement dictionary
        statement_idx: Index of the statement in the policy
        policy_type: Type of policy being validated (affects missing Resource validation)

    Returns:
        List of validation issues
    """
    issues: list[ValidationIssue] = []
    sid = statement_dict.get("Sid")

    # Check for unknown fields
    unknown_fields = set(statement_dict.keys()) - VALID_STATEMENT_FIELDS
    if unknown_fields:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_sid=sid,
                statement_index=statement_idx,
                issue_type="unknown_field",
                message=f"`Statement` contains unknown field(s): {', '.join(sorted(f'`{f}`' for f in unknown_fields))}",
                suggestion=f"Remove the unknown field(s). Valid statement fields are: {', '.join(sorted(f'`{f}`' for f in VALID_STATEMENT_FIELDS))}",
            )
        )

    # Validate Effect field (required)
    if "Effect" not in statement_dict:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_sid=sid,
                statement_index=statement_idx,
                issue_type="missing_effect",
                message="`Statement` is missing the required `Effect` field",
                suggestion="Add an `Effect` field with value `Allow` or `Deny`",
                example='"Effect": "Allow"',
                field_name="effect",
            )
        )
    elif statement_dict["Effect"] not in VALID_EFFECTS:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_sid=sid,
                statement_index=statement_idx,
                issue_type="invalid_effect",
                message=f"Invalid `Effect` value: `{statement_dict['Effect']}`. Must be `Allow` or `Deny`",
                suggestion="Change `Effect` to either `Allow` or `Deny`",
                example='"Effect": "Allow"',
                field_name="effect",
            )
        )

    # Validate SID format (if present)
    if sid is not None:
        if not isinstance(sid, str):
            issues.append(
                ValidationIssue(
                    severity="error",
                    statement_sid=str(sid),
                    statement_index=statement_idx,
                    issue_type="invalid_sid_type",
                    message=f"`Sid` must be a `string`, not `{type(sid).__name__}`",
                    suggestion='Wrap the `Sid` value in quotes to make it a string: `"Sid": "AllowS3Access"`',
                    example='"Sid": "AllowS3Access"',
                    field_name="sid",
                )
            )
        elif not SID_PATTERN.match(sid):
            # According to AWS grammar, SID should be alphanumeric only
            # However, we issue a warning instead of error since some AWS services accept more
            invalid_chars = "".join(set(c for c in sid if not c.isalnum()))
            issues.append(
                ValidationIssue(
                    severity="warning",
                    statement_sid=sid,
                    statement_index=statement_idx,
                    issue_type="invalid_sid_format",
                    message=f"`Sid` `{sid}` contains non-alphanumeric characters: `{invalid_chars}`",
                    suggestion="According to AWS IAM policy grammar, `Sid` should contain only alphanumeric characters `(A-Z, a-z, 0-9)`.",
                    field_name="sid",
                )
            )

    # Validate Principal/NotPrincipal mutual exclusivity
    if "Principal" in statement_dict and "NotPrincipal" in statement_dict:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_sid=sid,
                statement_index=statement_idx,
                issue_type="principal_conflict",
                message="`Statement` contains both `Principal` and `NotPrincipal` fields",
                suggestion="Use either `Principal` or `NotPrincipal`, not both",
                field_name="principal",
            )
        )

    # Validate Action/NotAction mutual exclusivity and presence
    has_action = "Action" in statement_dict
    has_not_action = "NotAction" in statement_dict

    if has_action and has_not_action:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_sid=sid,
                statement_index=statement_idx,
                issue_type="action_conflict",
                message="`Statement` contains both `Action` and `NotAction` fields",
                suggestion="Use either `Action` or `NotAction`, not both",
                field_name="action",
            )
        )
    elif not has_action and not has_not_action:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_sid=sid,
                statement_index=statement_idx,
                issue_type="missing_action",
                message="`Statement` is missing both `Action` and `NotAction` fields",
                suggestion="Add either an `Action` or `NotAction` field to specify which AWS actions this statement applies to",
                example=('"Action": [\n  "s3:GetObject",\n  "s3:PutObject"\n]'),
                field_name="action",
            )
        )

    # Validate Resource/NotResource mutual exclusivity and presence
    has_resource = "Resource" in statement_dict
    has_not_resource = "NotResource" in statement_dict

    if has_resource and has_not_resource:
        issues.append(
            ValidationIssue(
                severity="error",
                statement_sid=sid,
                statement_index=statement_idx,
                issue_type="resource_conflict",
                message="`Statement` contains both `Resource` and `NotResource` fields",
                suggestion="Use either `Resource` or `NotResource`, not both",
                field_name="resource",
            )
        )
    elif not has_resource and not has_not_resource:
        # Trust policies don't need Resource field (role itself is the resource)
        if policy_type == "TRUST_POLICY":
            # Skip this check for trust policies - it's expected and correct
            pass
        else:
            # Resource/NotResource are optional in some contexts (e.g., resource policies with Principal)
            # Issue an info-level message
            issues.append(
                ValidationIssue(
                    severity="info",
                    statement_sid=sid,
                    statement_index=statement_idx,
                    issue_type="missing_resource",
                    message="`Statement` is missing both `Resource` and `NotResource` fields",
                    suggestion="Most policies require a `Resource` field. Add a `Resource` or `NotResource` field to specify which AWS resources this statement applies to.",
                    example=('"Resource": "*" OR "Resource": "arn:aws:s3:::my-bucket/*"'),
                    field_name="resource",
                )
            )

    return issues


class PolicyStructureCheck(PolicyCheck):
    """Validates fundamental IAM policy structure.

    This check ensures policies meet AWS IAM requirements for basic structure:
    - Required fields are present
    - Mutually exclusive fields aren't used together
    - Field values are valid
    - No unknown fields are present

    This check should run FIRST before all other checks to catch fundamental
    issues early.
    """

    check_id: ClassVar[str] = "policy_structure"
    description: ClassVar[str] = (
        "Validates fundamental IAM policy structure (required fields, field conflicts, valid values)"
    )
    default_severity: ClassVar[str] = "error"

    async def execute_policy(
        self,
        policy: IAMPolicy,
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        """Execute the policy structure check on the entire policy.

        This validates:
        1. Policy document structure (Version, Statement fields)
        2. Each statement's structure (required fields, conflicts, valid values)
        3. Auto-detects policy type for better validation

        Args:
            policy: The complete IAM policy to validate
            policy_file: Path to the policy file (unused)
            fetcher: AWS service fetcher (unused)
            config: Check configuration
            **kwargs: Additional arguments (may contain raw_policy_dict)

        Returns:
            List of ValidationIssue objects for structural problems
        """
        del policy_file, fetcher, config  # Unused
        issues: list[ValidationIssue] = []

        # Get policy_type from kwargs (passed by validation flow)
        policy_type = kwargs.get("policy_type", "IDENTITY_POLICY")

        # Validate policy document structure if raw dict is available
        raw_policy_dict = kwargs.get("raw_policy_dict")
        if raw_policy_dict:
            issues.extend(validate_policy_document(raw_policy_dict))

            # Validate each statement's structure
            if isinstance(raw_policy_dict.get("Statement"), list):
                for idx, stmt_dict in enumerate(raw_policy_dict["Statement"]):
                    if isinstance(stmt_dict, dict):
                        issues.extend(validate_statement_structure(stmt_dict, idx, policy_type))

        # Auto-detect policy type
        detected_type = detect_policy_type(policy)

        # Store detected type in kwargs for other checks to use
        # This allows checks like principal_validation to automatically apply
        if "detected_policy_type" not in kwargs:
            kwargs["detected_policy_type"] = detected_type

        return issues

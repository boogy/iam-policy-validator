"""Policy Type Validation Check.

This check validates policy-type-specific requirements:
- Resource policies (RESOURCE_POLICY) must have a Principal element
- Identity policies (IDENTITY_POLICY) should not have a Principal element
- Service Control Policies (SERVICE_CONTROL_POLICY) have specific requirements
- Resource Control Policies (RESOURCE_CONTROL_POLICY) have strict requirements

Registered as the ``policy_type_validation`` check (PolicyTypeValidationCheck).
The module-level ``execute_policy()`` function remains the implementation and
is kept importable for backwards compatibility.

Notes on AWS rules enforced here:
- SCP Allow statements support Condition, scoped resource ARNs, NotAction and
  NotResource since the 2025-09-19 "full IAM policy language for SCPs" launch,
  so those older restrictions are intentionally NOT flagged anymore.
- RCP supported services come from ``constants.RCP_SUPPORTED_SERVICES`` and can
  be extended per-run via the ``additional_rcp_services`` check config option.
"""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.constants import RCP_SUPPORTED_SERVICES
from iam_validator.core.models import IAMPolicy, Statement, ValidationIssue


def _statement_principal_is_wildcard(statement: Statement) -> bool:
    """Return True when the statement's Principal is exactly "*"."""
    return statement.principal == "*" or str(statement.principal) == "*"


def _looks_like_rcp(policy: IAMPolicy) -> bool:
    """Heuristic: does this policy have the shape of a customer-managed RCP?

    Customer RCPs must have Effect=Deny, Principal="*" and service-prefixed
    actions in every statement (bare "*" is not allowed in RCP Action).
    Requiring `Resource: "*"` too keeps the hint away from ordinary deny-style
    resource policies (e.g. S3 TLS-only bucket policies, which must scope
    their bucket ARNs).
    """
    if not policy.statement:
        return False

    for statement in policy.statement:
        if not statement.effect or statement.effect.lower() != "deny":
            return False
        if statement.principal is None or not _statement_principal_is_wildcard(statement):
            return False
        actions = statement.action if isinstance(statement.action, list) else [statement.action]
        if not actions or any(not isinstance(a, str) or ":" not in a for a in actions):
            return False
        if statement.get_resources() != ["*"]:
            return False
    return True


async def execute_policy(
    policy: IAMPolicy,
    policy_file: str,
    policy_type: str = "IDENTITY_POLICY",
    additional_rcp_services: list[str] | set[str] | frozenset[str] | None = None,
    **kwargs,
) -> list[ValidationIssue]:
    """Validate policy-type-specific requirements.

    Args:
        policy: IAM policy document
        policy_file: Path to policy file
        policy_type: Type of policy (IDENTITY_POLICY, RESOURCE_POLICY, TRUST_POLICY,
            SERVICE_CONTROL_POLICY, RESOURCE_CONTROL_POLICY)
        additional_rcp_services: Extra service prefixes to treat as RCP-supported,
            on top of ``constants.RCP_SUPPORTED_SERVICES`` (lets users track new
            AWS launches without waiting for a validator release)
        **kwargs: Additional context (fetcher, raw_policy_dict, etc.)

    Returns:
        List of validation issues
    """
    issues = []

    # Handle policies with no statements
    if not policy.statement:
        return issues

    # Check if any statement has Principal
    has_any_principal = any(stmt.principal is not None or stmt.not_principal is not None for stmt in policy.statement)

    # RCPs cannot be auto-detected (they share the resource-policy shape), so
    # hint whenever an un-declared policy matches the customer-RCP shape —
    # whether it fell through to IDENTITY_POLICY or auto-detected as
    # RESOURCE_POLICY (any Principal ⇒ RESOURCE_POLICY).
    if policy_type in ("IDENTITY_POLICY", "RESOURCE_POLICY") and _looks_like_rcp(policy):
        issues.append(
            ValidationIssue(
                severity="info",
                issue_type="policy_type_hint",
                message=(
                    "Policy matches the RESOURCE CONTROL POLICY shape (all statements are "
                    '`Deny` with `Principal: "*"`, service-prefixed actions and `Resource: "*"`). '
                    "Use `--policy-type RESOURCE_CONTROL_POLICY` (or a `policy_types:` config glob) "
                    "for RCP-specific validation; RCPs cannot be auto-detected."
                ),
                statement_index=0,
                statement_sid=None,
                line_number=None,
                suggestion="iam-validator validate --path <file> --policy-type RESOURCE_CONTROL_POLICY",
            )
        )
        if policy_type == "IDENTITY_POLICY":
            # Just hint — the identity-policy Principal warnings below would be noise.
            return issues

    # If policy has Principal but type is IDENTITY_POLICY (default), provide helpful info
    if has_any_principal and policy_type == "IDENTITY_POLICY":
        # Check if it's a trust policy
        from iam_validator.checks.policy_structure import is_trust_policy

        if is_trust_policy(policy):
            hint_msg = (
                "Policy contains assume role actions - this is a TRUST POLICY. "
                "Use `--policy-type TRUST_POLICY` for proper validation (suppresses missing Resource warnings, "
                "enables trust-specific validation)"
            )
            suggestion_msg = "iam-validator validate --path <file> --policy-type TRUST_POLICY"
        else:
            hint_msg = "Policy contains Principal element - this suggests it's a RESOURCE POLICY. Use `--policy-type RESOURCE_POLICY`"
            suggestion_msg = "iam-validator validate --path <file> --policy-type RESOURCE_POLICY"

        issues.append(
            ValidationIssue(
                severity="info",
                issue_type="policy_type_hint",
                message=hint_msg,
                statement_index=0,
                statement_sid=None,
                line_number=None,
                suggestion=suggestion_msg,
            )
        )
        # Don't run further checks if we're just hinting
        return issues

    # Resource policies and Trust policies MUST have Principal
    if policy_type in ("RESOURCE_POLICY", "TRUST_POLICY"):
        for idx, statement in enumerate(policy.statement):
            has_principal = statement.principal is not None or statement.not_principal is not None

            if not has_principal:
                issues.append(
                    ValidationIssue(
                        severity="error",
                        issue_type="missing_principal",
                        message="Resource policy statement missing required `Principal` element. "
                        "Resource-based policies (S3 bucket policies, SNS topic policies, etc.) "
                        "must include a `Principal` element to specify who can access the resource.",
                        statement_index=idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion="Add a `Principal` element to specify who can access this resource.\n"
                        "Example:\n"
                        "```json\n"
                        "{\n"
                        '  "Effect": "Allow",\n'
                        '  "Principal": {\n'
                        '    "AWS": "arn:aws:iam::123456789012:root"\n'
                        "  },\n"
                        '  "Action": "s3:GetObject",\n'
                        '  "Resource": "arn:aws:s3:::bucket/*"\n'
                        "}\n"
                        "```",
                        field_name="principal",
                    )
                )

    # Identity policies should NOT have Principal (warning, not error)
    elif policy_type == "IDENTITY_POLICY":
        for idx, statement in enumerate(policy.statement):
            has_principal = statement.principal is not None or statement.not_principal is not None

            if has_principal:
                issues.append(
                    ValidationIssue(
                        severity="warning",
                        issue_type="unexpected_principal",
                        message="Identity policy should not contain `Principal` element. "
                        "Identity-based policies (attached to IAM users, groups, or roles) "
                        "do not need a `Principal` element because the principal is implicit "
                        "(the entity the policy is attached to).",
                        statement_index=idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion="Remove the `Principal` element from this identity policy statement.\n"
                        "Example:\n"
                        "```json\n"
                        "{\n"
                        '  "Effect": "Allow",\n'
                        '  "Action": "s3:GetObject",\n'
                        '  "Resource": "arn:aws:s3:::bucket/*"\n'
                        "}\n"
                        "```",
                        field_name="principal",
                    )
                )

    # Service Control Policies (SCPs) should not have Principal
    elif policy_type == "SERVICE_CONTROL_POLICY":
        # SCP size limit validation (5,120 bytes, different from identity policies)
        import json
        import re

        raw_policy_dict = kwargs.get("raw_policy_dict")
        if raw_policy_dict:
            policy_string = json.dumps(raw_policy_dict, separators=(",", ":"))
            policy_size = len(re.sub(r"\s+", "", policy_string))
            scp_max_size = 5120
            if policy_size > scp_max_size:
                percentage_over = ((policy_size - scp_max_size) / scp_max_size) * 100
                issues.append(
                    ValidationIssue(
                        severity="error",
                        issue_type="scp_size_exceeded",
                        message=(
                            f"Service Control Policy size ({policy_size:,} characters) exceeds "
                            f"the SCP limit of {scp_max_size:,} characters. "
                            "SCPs have a stricter size limit than identity policies."
                        ),
                        statement_index=-1,
                        statement_sid=None,
                        line_number=None,
                        suggestion=(
                            f"The SCP is {policy_size - scp_max_size:,} characters over the limit "
                            f"({percentage_over:.1f}% too large). Consider:\n"
                            "  1. Splitting the SCP into multiple smaller policies\n"
                            "  2. Using more concise action patterns with wildcards\n"
                            "  3. Removing unnecessary statements or conditions"
                        ),
                    )
                )

        for idx, statement in enumerate(policy.statement):
            # Check for Principal element (SCPs don't use Principal - it's implicit)
            if statement.principal is not None:
                issues.append(
                    ValidationIssue(
                        severity="error",
                        issue_type="invalid_principal",
                        message="Service Control Policy must not contain `Principal` element. "
                        "Service Control Policies (SCPs) in AWS Organizations do not support "
                        "the `Principal` element. They apply to all principals in the organization or OU.",
                        statement_index=idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion="Remove the `Principal` element from this SCP statement.\n"
                        "Example:\n"
                        "```json\n"
                        "{\n"
                        '  "Effect": "Deny",\n'
                        '  "Action": "ec2:*",\n'
                        '  "Resource": "*",\n'
                        '  "Condition": {\n'
                        '    "StringNotEquals": {\n'
                        '      "ec2:Region": ["us-east-1", "us-west-2"]\n'
                        "    }\n"
                        "  }\n"
                        "}\n"
                        "```",
                        field_name="principal",
                    )
                )

            # Check for NotPrincipal element (SCPs don't support NotPrincipal)
            if statement.not_principal is not None:
                issues.append(
                    ValidationIssue(
                        severity="error",
                        issue_type="invalid_not_principal",
                        message="Service Control Policy must not contain `NotPrincipal` element. "
                        "Service Control Policies (SCPs) do not support the `NotPrincipal` element. "
                        "SCPs apply to all principals in the organization or OU.",
                        statement_index=idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion="Remove the `NotPrincipal` element from this SCP statement. "
                        "Use `Condition` elements to exclude specific principals if needed.",
                        field_name="principal",
                    )
                )

            # NOTE: SCP Allow statements previously required `Resource: "*"` and
            # forbade `Condition`. Since 2025-09-19, AWS Organizations supports
            # the full IAM policy language in SCPs (conditions, scoped resource
            # ARNs, NotAction/NotResource, leading/middle wildcards in Action),
            # so those restrictions are no longer validated.

    # Resource Control Policies (RCPs) have very strict requirements
    elif policy_type == "RESOURCE_CONTROL_POLICY":
        # Centralized list of RCP supported services, optionally extended via
        # the `additional_rcp_services` check config (new AWS launches).
        rcp_supported_services = frozenset(RCP_SUPPORTED_SERVICES)
        if additional_rcp_services:
            rcp_supported_services |= {str(s).strip().lower() for s in additional_rcp_services if str(s).strip()}

        for idx, statement in enumerate(policy.statement):
            # 1. Effect MUST be Deny (only RCPFullAWSAccess can use Allow)
            if statement.effect and statement.effect.lower() != "deny":
                issues.append(
                    ValidationIssue(
                        severity="error",
                        issue_type="invalid_rcp_effect",
                        message="Resource Control Policy statement must have `Effect: Deny`. "
                        "For RCPs that you create, the `Effect` value must be `Deny`. "
                        "Only the AWS-managed `RCPFullAWSAccess` policy can use `Allow`.",
                        statement_index=idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion="Change the `Effect` to `Deny` for this RCP statement.",
                        field_name="effect",
                    )
                )

            # 2. Principal MUST be "*" (and only "*")
            has_principal = statement.principal is not None
            has_not_principal = statement.not_principal is not None

            if has_not_principal:
                issues.append(
                    ValidationIssue(
                        severity="error",
                        issue_type="invalid_rcp_not_principal",
                        message="Resource Control Policy must not contain `NotPrincipal` element. "
                        "RCPs only support `Principal` with value `*`. Use `Condition` elements "
                        "to restrict specific principals.",
                        statement_index=idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion='Remove `NotPrincipal` and use `Principal: "*"` with `Condition` elements to restrict access.',
                        field_name="principal",
                    )
                )
            elif not has_principal:
                issues.append(
                    ValidationIssue(
                        severity="error",
                        issue_type="missing_rcp_principal",
                        message='Resource Control Policy statement must have `Principal: "*"`. '
                        'RCPs require the `Principal` element with value `"*"`. Use `Condition` '
                        "elements to restrict specific principals.",
                        statement_index=idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion='Add `Principal: "*"` to this RCP statement.',
                        field_name="principal",
                    )
                )
            elif statement.principal != "*":
                # Check if it's the dict format {"AWS": "*"} or other variations
                principal_str = str(statement.principal)
                if principal_str != "*":
                    issues.append(
                        ValidationIssue(
                            severity="error",
                            issue_type="invalid_rcp_principal",
                            message=f'Resource Control Policy `Principal` must be `"*"`. '
                            f'Found: `{statement.principal}`. RCPs can only specify `"*"` in the '
                            "`Principal` element. Use `Condition` elements to restrict specific principals.",
                            statement_index=idx,
                            statement_sid=statement.sid,
                            line_number=statement.line_number,
                            suggestion='Change `Principal` to `"*"` and use `Condition` elements to restrict access.',
                            field_name="principal",
                        )
                    )

            # 3. Check for unsupported actions (actions not in supported services)
            if statement.action:
                actions = statement.action if isinstance(statement.action, list) else [statement.action]
                unsupported_actions = []

                for action in actions:
                    if isinstance(action, str):
                        # Check if action uses wildcard "*" alone (not allowed in customer RCPs)
                        if action == "*":
                            issues.append(
                                ValidationIssue(
                                    severity="error",
                                    issue_type="invalid_rcp_wildcard_action",
                                    message="Resource Control Policy must not use `*` alone in `Action` element. "
                                    "Customer-managed RCPs cannot use `*` as the action wildcard. "
                                    "Use service-specific wildcards like `s3:*` instead.",
                                    statement_index=idx,
                                    statement_sid=statement.sid,
                                    line_number=statement.line_number,
                                    suggestion="Replace `*` with service-specific actions from supported "
                                    f"services: {', '.join(f'`{a}`' for a in sorted(rcp_supported_services))}",
                                    field_name="action",
                                )
                            )
                        else:
                            # Extract service from action (format: service:ActionName)
                            service = action.split(":")[0] if ":" in action else action
                            # Handle wildcards in service name
                            service_base = service.rstrip("*")

                            if service_base and service_base not in rcp_supported_services:
                                unsupported_actions.append(action)

                if unsupported_actions:
                    issues.append(
                        ValidationIssue(
                            severity="error",
                            issue_type="unsupported_rcp_service",
                            message=f"Resource Control Policy contains actions from unsupported services: "
                            f"{', '.join(f'`{a}`' for a in unsupported_actions)}. RCPs only support these services: "
                            f"{', '.join(f'`{a}`' for a in sorted(rcp_supported_services))}",
                            statement_index=idx,
                            statement_sid=statement.sid,
                            line_number=statement.line_number,
                            suggestion=f"Use only actions from supported RCP services: "
                            f"{', '.join(f'`{a}`' for a in sorted(rcp_supported_services))}. "
                            "If AWS added RCP support for a service after this validator release, "
                            "add its prefix to the `additional_rcp_services` config option of the "
                            "`policy_type_validation` check.",
                            field_name="action",
                        )
                    )

            # 4. NotAction is not supported in RCPs
            if statement.not_action:
                issues.append(
                    ValidationIssue(
                        severity="error",
                        issue_type="invalid_rcp_not_action",
                        message="Resource Control Policy must not contain `NotAction` element. "
                        "RCPs do not support `NotAction`. Use `Action` element instead.",
                        statement_index=idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion="Replace `NotAction` with `Action` element listing the specific actions to deny.",
                        field_name="action",
                    )
                )

            # 5. Resource or NotResource is required
            has_resource = statement.resource is not None
            has_not_resource = statement.not_resource is not None

            if not has_resource and not has_not_resource:
                issues.append(
                    ValidationIssue(
                        severity="error",
                        issue_type="missing_rcp_resource",
                        message="Resource Control Policy statement must have `Resource` or `NotResource` element.",
                        statement_index=idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion='Add `Resource: "*"` or specify specific resource ARNs.',
                        field_name="resource",
                    )
                )

    return issues


class PolicyTypeValidationCheck(PolicyCheck):
    """Registered wrapper around the policy-type validation logic.

    Config options (under ``checks.policy_type_validation.config``):
    - ``additional_rcp_services``: list of extra service prefixes to accept as
      RCP-supported (for AWS launches newer than this validator release).
    """

    check_id: ClassVar[str] = "policy_type_validation"
    description: ClassVar[str] = "Validates policies match declared type and enforces SCP/RCP requirements"
    default_severity: ClassVar[str] = "error"

    async def execute_policy(
        self,
        policy: IAMPolicy,
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        del fetcher  # AWS data not needed for structural type validation
        return await execute_policy(
            policy,
            policy_file,
            policy_type=kwargs.get("policy_type", "IDENTITY_POLICY"),
            additional_rcp_services=config.config.get("additional_rcp_services", []),
            raw_policy_dict=kwargs.get("raw_policy_dict"),
        )

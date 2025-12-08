"""Policy Type Validation Check.

This check validates policy-type-specific requirements:
- Resource policies (RESOURCE_POLICY) must have a Principal element
- Identity policies (IDENTITY_POLICY) should not have a Principal element
- Service Control Policies (SERVICE_CONTROL_POLICY) have specific requirements
- Resource Control Policies (RESOURCE_CONTROL_POLICY) have strict requirements

This check runs automatically based on:
1. The --policy-type flag value
2. Auto-detection: If any statement has a Principal, provides helpful guidance
"""

from iam_validator.core.constants import RCP_SUPPORTED_SERVICES
from iam_validator.core.models import IAMPolicy, ValidationIssue


async def execute_policy(
    policy: IAMPolicy, policy_file: str, policy_type: str = "IDENTITY_POLICY", **kwargs
) -> list[ValidationIssue]:
    """Validate policy-type-specific requirements.

    Args:
        policy: IAM policy document
        policy_file: Path to policy file
        policy_type: Type of policy (IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY)
        **kwargs: Additional context (fetcher, statement index, etc.)

    Returns:
        List of validation issues
    """
    issues = []

    # Handle policies with no statements
    if not policy.statement:
        return issues

    # Check if any statement has Principal
    has_any_principal = any(
        stmt.principal is not None or stmt.not_principal is not None for stmt in policy.statement
    )

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
        for idx, statement in enumerate(policy.statement):
            has_principal = statement.principal is not None or statement.not_principal is not None

            if has_principal:
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

    # Resource Control Policies (RCPs) have very strict requirements
    elif policy_type == "RESOURCE_CONTROL_POLICY":
        # Use the centralized list of RCP supported services from constants
        rcp_supported_services = RCP_SUPPORTED_SERVICES

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
                actions = (
                    statement.action if isinstance(statement.action, list) else [statement.action]
                )
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
                            f"{', '.join(f'`{a}`' for a in sorted(rcp_supported_services))}",
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

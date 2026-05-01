"""Curated examples / fix_steps per check_id.

`get_issue_guidance` and `get_check_details` consult this module for hand-written
copy-pasteable examples and remediation steps. For check_ids without a curated
entry, those tools fall back to registry-driven defaults.

When a new check is added in `iam_validator/checks/`, add an entry here if there
is a clear, short example. Checks without a clean example fall through to the
registry-driven path and still return useful (if generic) guidance.
"""

from typing import Any

from iam_validator.core.constants import IAM_POLICY_VERSION_CURRENT

# Curated examples per check_id. Keep entries short and copy-pastable.
CHECK_EXAMPLES: dict[str, dict[str, Any]] = {
    "wildcard_action": {
        "example_violation": {"Effect": "Allow", "Action": "*", "Resource": "*"},
        "example_fix": {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        },
        "fix_steps": [
            "Identify what the policy user actually needs to do",
            "Use suggest_actions or query_service_actions to find specific actions",
            "Replace '*' with the specific action list",
        ],
        "related": ["suggest_actions", "query_service_actions", "iam://templates"],
        "category": "security",
    },
    "wildcard_resource": {
        "example_violation": {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
        "example_fix": {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        },
        "fix_steps": [
            "Determine the exact resources the principal needs",
            "Use query_arn_formats('<service>') to get the ARN template",
            "Replace '*' with explicit ARN(s)",
        ],
        "related": ["query_arn_formats", "build_arn"],
        "category": "security",
    },
    "full_wildcard": {
        "example_violation": {"Effect": "Allow", "Action": "*", "Resource": "*"},
        "example_fix": {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        },
        "fix_steps": [
            "Treat as a critical finding — never deploy `*`/`*`.",
            "Replace both Action and Resource with explicit values.",
        ],
        "related": ["iam://templates", "build_minimal_policy"],
        "category": "security",
    },
    "service_wildcard": {
        "example_violation": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        "example_fix": {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        },
        "fix_steps": [
            "Replace `<service>:*` with the explicit subset.",
            "Use expand_wildcard_action to see what `s3:*` actually expands to before narrowing.",
        ],
        "related": ["expand_wildcard_action", "query_service_actions"],
        "category": "security",
    },
    "sensitive_action": {
        "example_violation": {
            "Effect": "Allow",
            "Action": "iam:CreateAccessKey",
            "Resource": "*",
        },
        "example_fix": {
            "Effect": "Allow",
            "Action": "iam:CreateAccessKey",
            "Resource": "arn:aws:iam::123456789012:user/${aws:username}",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        },
        "fix_steps": [
            "Confirm the sensitive action is truly required",
            "Use check_sensitive_actions to see the risk category",
            "Use get_required_conditions to see required guardrails",
            "Add Condition + scoped Resource",
        ],
        "related": ["check_sensitive_actions", "get_required_conditions"],
        "category": "security",
    },
    "action_validation": {
        "example_violation": {"Effect": "Allow", "Action": ["S3:GetObjects"], "Resource": "*"},
        "example_fix": {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
        "fix_steps": [
            "Lowercase the service prefix",
            "Verify the action exists with query_action_details",
            "Re-run validate_policy",
        ],
        "related": ["query_action_details", "query_service_actions", "expand_wildcard_action"],
        "category": "aws",
    },
    "policy_structure": {
        "example_violation": {"Statement": [{"Action": "s3:*"}]},
        "example_fix": {
            "Version": IAM_POLICY_VERSION_CURRENT,
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        },
        "fix_steps": [
            f'Add `Version: "{IAM_POLICY_VERSION_CURRENT}"`',
            "Each Statement needs Effect, Action, Resource",
            "Run fix_policy_issues for auto-fixes",
        ],
        "related": ["fix_policy_issues", "validate_policy"],
        "category": "structure",
    },
    "action_condition_enforcement": {
        "example_violation": {
            "Effect": "Allow",
            "Action": ["iam:CreateUser"],
            "Resource": "*",
        },
        "example_fix": {
            "Effect": "Allow",
            "Action": ["iam:CreateUser"],
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        },
        "fix_steps": [
            "Use get_required_conditions(['<action>'])",
            "Add the recommended Condition block",
        ],
        "related": ["get_required_conditions", "fix_policy_issues"],
        "category": "security",
    },
    "not_action_not_resource": {
        "example_violation": {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        "example_fix": {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
        "fix_steps": [
            "Prefer explicit allow-lists over NotAction/NotResource",
            "If you mean a deny, use Effect: Deny with Action",
        ],
        "related": ["validate_policy"],
        "category": "anti-pattern",
    },
    "sid_uniqueness": {
        "example_violation": {
            "Statement": [
                {"Sid": "A", "Effect": "Allow", "Action": "s3:Get*"},
                {"Sid": "A", "Effect": "Allow", "Action": "s3:Put*"},
            ]
        },
        "example_fix": {
            "Statement": [
                {"Sid": "AllowReads", "Effect": "Allow", "Action": "s3:Get*"},
                {"Sid": "AllowWrites", "Effect": "Allow", "Action": "s3:Put*"},
            ]
        },
        "fix_steps": [
            "Rename duplicates to be unique",
            "fix_policy_issues auto-renames by appending the index",
        ],
        "related": ["fix_policy_issues"],
        "category": "structure",
    },
    "principal_validation": {
        "example_violation": {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sts:AssumeRole",
        },
        "example_fix": {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:role/Trusted"},
            "Action": "sts:AssumeRole",
        },
        "fix_steps": [
            "Replace `*` with the specific principal ARN",
            "Add an aws:PrincipalOrgID condition for org-wide trust",
        ],
        "related": ["validate_policy"],
        "category": "security",
    },
    "trust_policy_validation": {
        "example_violation": {
            "Version": IAM_POLICY_VERSION_CURRENT,
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        "example_fix": {
            "Version": IAM_POLICY_VERSION_CURRENT,
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
                }
            ],
        },
        "fix_steps": [
            "Service principals: add aws:SourceAccount/aws:SourceArn to prevent confused deputy",
            "Cross-account: add ExternalId condition",
        ],
        "related": ["generate_policy_from_template"],
        "category": "security",
    },
}


def get_check_metadata(check_id: str) -> dict[str, Any]:
    """Return curated metadata for a check, or {} if no curated entry exists."""
    return CHECK_EXAMPLES.get(check_id, {})


__all__ = ["CHECK_EXAMPLES", "get_check_metadata"]

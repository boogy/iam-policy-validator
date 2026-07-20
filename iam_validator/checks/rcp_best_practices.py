"""RCP Best Practices Check.

Best-practice guidance for customer-managed Resource Control Policies (RCPs),
grounded in AWS's official example policies
(aws-samples/resource-control-policy-examples and the data-perimeter
identity_perimeter_rcp.json):

1. Blanket denies (low): a Deny statement with no Condition blocks EVERY
   principal — including the organization's own admins — for the listed
   actions. Legal (AWS's Block-Public-Access-protection example does this),
   but worth confirming intent.
2. Missing AWS-service carve-out (medium): a Deny that restricts principals
   to the organization (StringNotEquals* on aws:PrincipalOrgID /
   aws:PrincipalOrgPaths / aws:PrincipalAccount) without an
   aws:PrincipalIsAWSService carve-out can break AWS service-to-service
   calls. AWS's canonical identity-perimeter RCP always pairs them:

       "StringNotEqualsIfExists": {"aws:PrincipalOrgID": "o-..."},
       "BoolIfExists": {"aws:PrincipalIsAWSService": "false"}

Only runs when the resolved policy type is RESOURCE_CONTROL_POLICY.
"""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import IAMPolicy, Statement, ValidationIssue

# Principal-boundary keys that, when used with a negated operator in a Deny,
# scope the deny to "everyone outside my org/accounts".
_ORG_BOUNDARY_KEYS = frozenset(
    {
        "aws:principalorgid",
        "aws:principalorgpaths",
        "aws:principalaccount",
    }
)

_SERVICE_CARVEOUT_KEY = "aws:principalisawsservice"

_CANONICAL_CARVEOUT_EXAMPLE = (
    "{\n"
    '  "Effect": "Deny",\n'
    '  "Principal": "*",\n'
    '  "Action": "s3:*",\n'
    '  "Resource": "*",\n'
    '  "Condition": {\n'
    '    "StringNotEqualsIfExists": {\n'
    '      "aws:PrincipalOrgID": "o-123456789"\n'
    "    },\n"
    '    "BoolIfExists": {\n'
    '      "aws:PrincipalIsAWSService": "false"\n'
    "    }\n"
    "  }\n"
    "}"
)


def _condition_keys_by_operator(statement: Statement) -> list[tuple[str, set[str]]]:
    """Return (lowercased operator, lowercased condition keys) pairs."""
    pairs: list[tuple[str, set[str]]] = []
    if not statement.condition:
        return pairs
    for operator, keys_dict in statement.condition.items():
        if isinstance(keys_dict, dict):
            pairs.append((operator.lower(), {k.lower() for k in keys_dict.keys()}))
    return pairs


class RCPBestPracticesCheck(PolicyCheck):
    """Best-practice guidance for Resource Control Policies."""

    check_id: ClassVar[str] = "rcp_best_practices"
    description: ClassVar[str] = (
        "Flags RCP deny statements that block all principals or restrict to the "
        "organization without an aws:PrincipalIsAWSService carve-out"
    )
    default_severity: ClassVar[str] = "medium"

    async def execute_policy(
        self,
        policy: IAMPolicy,
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        del fetcher  # AWS data not needed
        if kwargs.get("policy_type") != "RESOURCE_CONTROL_POLICY":
            return []

        issues: list[ValidationIssue] = []
        for idx, statement in enumerate(policy.statement or []):
            if not statement.effect or statement.effect.lower() != "deny":
                continue

            condition_pairs = _condition_keys_by_operator(statement)
            all_condition_keys = {key for _, keys in condition_pairs for key in keys}

            # 1. Blanket deny: no Condition at all
            if not condition_pairs:
                issues.append(
                    ValidationIssue(
                        severity="low",
                        issue_type="rcp_blanket_deny",
                        message=(
                            "RCP Deny statement has no `Condition`, so it blocks these "
                            "actions for ALL principals — including your organization's "
                            "own users, roles, and admins. Confirm this blanket deny is "
                            "intended (it is a valid pattern for locking a setting, e.g. "
                            "denying `s3:PutBucketPublicAccessBlock` for everyone)."
                        ),
                        statement_index=idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion=(
                            "If only external access should be blocked, add an "
                            "organization boundary condition such as "
                            "`StringNotEqualsIfExists aws:PrincipalOrgID` with a "
                            "`BoolIfExists aws:PrincipalIsAWSService: false` carve-out."
                        ),
                        example=_CANONICAL_CARVEOUT_EXAMPLE,
                        field_name="condition",
                    )
                )
                continue

            # 2. Org-boundary deny without an AWS-service carve-out
            uses_org_boundary = any(
                "stringnotequals" in operator and keys & _ORG_BOUNDARY_KEYS for operator, keys in condition_pairs
            )
            if uses_org_boundary and _SERVICE_CARVEOUT_KEY not in all_condition_keys:
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        issue_type="rcp_missing_service_carveout",
                        message=(
                            "RCP Deny statement restricts principals to your organization "
                            "but has no `aws:PrincipalIsAWSService` carve-out. AWS service "
                            "principals (e.g. CloudTrail or S3 log delivery writing to your "
                            "buckets) do not carry `aws:PrincipalOrgID`, so this statement "
                            "can deny AWS service-to-service calls and break integrations."
                        ),
                        statement_index=idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion=(
                            "Pair the organization boundary with the canonical carve-out "
                            'used by AWS\'s identity-perimeter RCP: `"BoolIfExists": '
                            '{"aws:PrincipalIsAWSService": "false"}` (and consider '
                            "`aws:SourceOrgID` conditions for the service-call path)."
                        ),
                        example=_CANONICAL_CARVEOUT_EXAMPLE,
                        field_name="condition",
                    )
                )

        return issues

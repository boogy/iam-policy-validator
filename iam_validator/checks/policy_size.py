"""Policy size validation check.

This check validates that IAM policies don't exceed AWS's maximum size limits.
AWS enforces different size limits based on policy type:

- Managed policies: 6,144 bytes
- Inline user policies: 2,048 bytes
- Inline group policies: 5,120 bytes
- Inline role policies: 10,240 bytes
- Inline role trust policies: 2,048 bytes
- Service Control Policies (SCP): 5,120 bytes
- Resource Control Policies (RCP): 5,120 bytes

Resource-based policies (S3 bucket, SQS, SNS, Lambda, etc.) vary by service and
are not checked here unless the user configures an explicit limit.

Size is measured as the compact JSON representation (no inter-token whitespace),
counted in UTF-8 bytes — matching AWS's own measurement. Whitespace inside string
values (SIDs, condition values) is counted, as AWS counts those characters.
"""

import json
from typing import TYPE_CHECKING, ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.constants import AWS_POLICY_SIZE_LIMITS, AWS_POLICY_TYPE_TO_SIZE_KEY
from iam_validator.core.models import ValidationIssue

if TYPE_CHECKING:
    from iam_validator.core.models import IAMPolicy


# Human-readable descriptions keyed by size-limit key
_LIMIT_DESCRIPTIONS = {
    "managed": "managed policy",
    "inline_user": "inline policy for users",
    "inline_group": "inline policy for groups",
    "inline_role": "inline policy for roles",
    "inline_role_trust": "inline role trust policy",
    "scp": "Service Control Policy",
    "rcp": "Resource Control Policy",
}


class PolicySizeCheck(PolicyCheck):
    """Validates that IAM policies don't exceed AWS size limits."""

    # AWS IAM policy size limits (loaded from constants module)
    DEFAULT_LIMITS = AWS_POLICY_SIZE_LIMITS

    check_id: ClassVar[str] = "policy_size"
    description: ClassVar[str] = "Validates that IAM policies don't exceed AWS size limits"
    default_severity: ClassVar[str] = "error"

    async def execute_policy(
        self,
        policy: "IAMPolicy",
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        """Execute the policy size check on the entire policy.

        Calculates the policy's compact-JSON byte size (UTF-8) and validates it
        against the AWS limit appropriate for the policy type. The limit is
        resolved in this priority order:

        1. YAML config ``checks.policy_size.config.policy_type`` (explicit
           override for users who know the deployment target — e.g., a policy
           headed for an inline user attachment rather than a managed policy).
        2. The runtime ``policy_type`` kwarg (from ``--policy-type`` or
           auto-detection) mapped through ``AWS_POLICY_TYPE_TO_SIZE_KEY``.
        3. Fallback to ``managed`` (6,144 bytes).

        Args:
            policy: The complete IAM policy to validate
            policy_file: Path to the policy file (for context/reporting)
            fetcher: AWS service fetcher (unused for this check)
            config: Configuration for this check instance
            **kwargs: May include ``policy_type`` (AWS policy type) and
                ``raw_policy_dict`` (original parsed JSON/YAML, preferred for
                accurate size measurement).

        Returns:
            List of ValidationIssue objects if policy exceeds size limits
        """
        del policy_file, fetcher  # Unused
        issues: list[ValidationIssue] = []

        # Resolve size-limit key in priority order.
        size_limits = config.config.get("size_limits", self.DEFAULT_LIMITS.copy())
        explicit_key = config.config.get("policy_type")
        if explicit_key is not None:
            limit_key = explicit_key
        else:
            runtime_policy_type = kwargs.get("policy_type", "IDENTITY_POLICY")
            limit_key = AWS_POLICY_TYPE_TO_SIZE_KEY.get(runtime_policy_type, "managed")

        if limit_key not in size_limits:
            # User supplied an unknown key — fall back rather than crash.
            limit_key = "managed"

        max_size = size_limits[limit_key]

        # Prefer the raw parsed dict so we measure what AWS would actually
        # receive, not Pydantic's re-serialized view. Fall back to model_dump.
        raw_policy_dict = kwargs.get("raw_policy_dict")
        if raw_policy_dict is not None:
            policy_json = raw_policy_dict
        else:
            policy_json = policy.model_dump(by_alias=True, exclude_none=True)

        # Compact JSON strips inter-token whitespace; UTF-8 byte length matches
        # AWS's measurement (AWS counts bytes, not Unicode codepoints).
        policy_string = json.dumps(policy_json, separators=(",", ":"), ensure_ascii=False)
        policy_size = len(policy_string.encode("utf-8"))

        if policy_size <= max_size:
            return issues

        severity = self.get_severity(config)
        percentage_over = ((policy_size - max_size) / max_size) * 100
        policy_type_desc = _LIMIT_DESCRIPTIONS.get(limit_key, limit_key)

        issues.append(
            ValidationIssue(
                severity=severity,
                statement_sid=None,
                statement_index=-1,  # Policy-level issue
                issue_type="policy_size_exceeded",
                message=(
                    f"Policy size ({policy_size:,} bytes) exceeds AWS limit for {policy_type_desc} ({max_size:,} bytes)"
                ),
                suggestion=(
                    f"The policy is {policy_size - max_size:,} bytes over the limit "
                    f"({percentage_over:.1f}% too large). Consider:\n"
                    f"  1. Splitting the policy into multiple smaller policies\n"
                    f"  2. Using more concise action/resource patterns with wildcards\n"
                    f"  3. Removing unnecessary statements or conditions\n"
                    f"  4. For inline policies, consider using managed policies instead\n"
                    f"\nNote: AWS does not count whitespace in the size calculation."
                ),
                line_number=None,
            )
        )

        return issues

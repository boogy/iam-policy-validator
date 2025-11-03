"""Policy size validation check.

This check validates that IAM policies don't exceed AWS's maximum size limits.
AWS enforces different size limits based on policy type:
- Managed policies: 6,144 characters maximum
- Inline policies for users: 2,048 characters maximum
- Inline policies for groups: 5,120 characters maximum
- Inline policies for roles: 10,240 characters maximum

Note: AWS does not count whitespace when calculating policy size.
"""

import json
import re
from typing import TYPE_CHECKING

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue

if TYPE_CHECKING:
    from iam_validator.core.models import IAMPolicy


class PolicySizeCheck(PolicyCheck):
    """Validates that IAM policies don't exceed AWS size limits."""

    # AWS IAM policy size limits (in characters, excluding whitespace)
    DEFAULT_LIMITS = {
        "managed": 6144,
        "inline_user": 2048,
        "inline_group": 5120,
        "inline_role": 10240,
    }

    @property
    def check_id(self) -> str:
        return "policy_size"

    @property
    def description(self) -> str:
        return "Validates that IAM policies don't exceed AWS size limits"

    @property
    def default_severity(self) -> str:
        return "error"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute the policy size check at statement level.

        This is a policy-level check, so statement-level execution returns empty.
        The actual check runs in execute_policy() which has access to the full policy.

        Args:
            statement: The IAM policy statement (unused)
            statement_idx: Index of the statement in the policy (unused)
            fetcher: AWS service fetcher (unused for this check)
            config: Configuration for this check instance (unused)

        Returns:
            Empty list (actual check runs in execute_policy())
        """
        del statement, statement_idx, fetcher, config  # Unused
        # This is a policy-level check - execution happens in execute_policy()
        return []

    async def execute_policy(
        self,
        policy: "IAMPolicy",
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        """Execute the policy size check on the entire policy.

        This method calculates the policy size (excluding whitespace) and validates
        it against AWS limits based on the configured policy type.

        Args:
            policy: The complete IAM policy to validate
            policy_file: Path to the policy file (for context/reporting)
            fetcher: AWS service fetcher (unused for this check)
            config: Configuration for this check instance

        Returns:
            List of ValidationIssue objects if policy exceeds size limits
        """
        del policy_file, fetcher  # Unused
        issues = []

        # Get the policy type from config (default to managed)
        policy_type = config.config.get("policy_type", "managed")

        # Get custom limits if provided in config, otherwise use defaults
        size_limits = config.config.get("size_limits", self.DEFAULT_LIMITS.copy())

        # Determine the applicable limit
        limit_key = policy_type
        if limit_key not in size_limits:
            # If custom policy_type not found, default to managed
            limit_key = "managed"

        max_size = size_limits[limit_key]

        # Convert policy to JSON and calculate size (excluding whitespace)
        policy_json = policy.model_dump(by_alias=True, exclude_none=True)
        policy_string = json.dumps(policy_json, separators=(",", ":"))

        # Remove all whitespace as AWS doesn't count it
        policy_size = len(re.sub(r"\s+", "", policy_string))

        # Check if policy exceeds the limit
        if policy_size > max_size:
            severity = self.get_severity(config)

            # Calculate percentage over limit
            percentage_over = ((policy_size - max_size) / max_size) * 100

            # Determine policy type description
            policy_type_desc = {
                "managed": "managed policy",
                "inline_user": "inline policy for users",
                "inline_group": "inline policy for groups",
                "inline_role": "inline policy for roles",
            }.get(policy_type, policy_type)

            issues.append(
                ValidationIssue(
                    severity=severity,
                    statement_sid=None,  # Policy-level issue
                    statement_index=-1,  # -1 indicates policy-level issue
                    issue_type="policy_size_exceeded",
                    message=f"Policy size ({policy_size:,} characters) exceeds AWS limit for {policy_type_desc} ({max_size:,} characters)",
                    suggestion=f"The policy is {policy_size - max_size:,} characters over the limit ({percentage_over:.1f}% too large). Consider:\n"
                    f"  1. Splitting the policy into multiple smaller policies\n"
                    f"  2. Using more concise action/resource patterns with wildcards\n"
                    f"  3. Removing unnecessary statements or conditions\n"
                    f"  4. For inline policies, consider using managed policies instead\n"
                    f"\nNote: AWS does not count whitespace in the size calculation.",
                    line_number=None,
                )
            )

        return issues

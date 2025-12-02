"""Statement ID (SID) uniqueness and format check.

This check validates that Statement IDs (Sids):
1. Are unique within a policy
2. Follow AWS naming requirements (alphanumeric, hyphens, underscores only - no spaces)

According to AWS best practices, while not strictly required, having unique SIDs
makes it easier to reference specific statements and improves policy maintainability.

This is implemented as a policy-level check that runs once when processing the first
statement, examining all statements in the policy to find duplicates and format issues.
"""

import re
from collections import Counter
from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import IAMPolicy, ValidationIssue


def _check_sid_uniqueness_impl(policy: IAMPolicy, severity: str) -> list[ValidationIssue]:
    """Implementation of SID uniqueness and format checking.

    Args:
        policy: IAM policy to validate
        severity: Severity level for issues found

    Returns:
        List of ValidationIssue objects for duplicate or invalid SIDs
    """
    issues: list[ValidationIssue] = []

    # AWS SID requirements: alphanumeric characters, hyphens, and underscores only
    # No spaces allowed
    sid_pattern = re.compile(r"^[a-zA-Z0-9_-]+$")

    # Handle policies with no statements
    if not policy.statement:
        return []

    # Collect all SIDs (ignoring None/empty values) and check format
    sids_with_indices: list[tuple[str, int]] = []
    for idx, statement in enumerate(policy.statement):
        if statement.sid:  # Only check statements that have a SID
            # Check SID format
            if not sid_pattern.match(statement.sid):
                # Identify the issue
                if " " in statement.sid:
                    issue_msg = f"Statement ID `{statement.sid}` contains spaces, which are not allowed by AWS"
                    suggestion = (
                        f"Remove spaces from the SID. Example: `{statement.sid.replace(' ', '')}`"
                    )
                else:
                    invalid_chars = "".join(
                        set(c for c in statement.sid if not c.isalnum() and c not in "_-")
                    )
                    issue_msg = f"Statement ID `{statement.sid}` contains invalid characters: `{invalid_chars}`"
                    suggestion = (
                        "SIDs must contain only alphanumeric characters, hyphens, and underscores"
                    )

                issues.append(
                    ValidationIssue(
                        severity="error",  # Invalid SID format is an error
                        statement_sid=statement.sid,
                        statement_index=idx,
                        issue_type="invalid_sid_format",
                        message=issue_msg,
                        suggestion=suggestion,
                        line_number=statement.line_number,
                        field_name="sid",
                    )
                )

            sids_with_indices.append((statement.sid, idx))

    # Find duplicates
    sid_counts = Counter(sid for sid, _ in sids_with_indices)
    duplicate_sids = {sid: count for sid, count in sid_counts.items() if count > 1}

    # Create issues for each duplicate SID
    for duplicate_sid, count in duplicate_sids.items():
        # Find all statement indices with this SID
        indices = [idx for sid, idx in sids_with_indices if sid == duplicate_sid]

        # Create an issue for each occurrence except the first
        # (the first occurrence is "original", subsequent ones are "duplicates")
        for idx in indices[1:]:
            statement = policy.statement[idx]
            # Convert to 1-indexed statement numbers for user-facing message
            statement_numbers = ", ".join(f"#{i + 1}" for i in indices)
            issues.append(
                ValidationIssue(
                    severity=severity,
                    statement_sid=duplicate_sid,
                    statement_index=idx,
                    issue_type="duplicate_sid",
                    message=f"Statement ID `{duplicate_sid}` is used **{count} times** in this policy (found in statements `{statement_numbers}`)",
                    suggestion="Change this SID to a unique value. Statement IDs help identify and reference specific statements, so duplicates can cause confusion.",
                    line_number=statement.line_number,
                    field_name="sid",
                )
            )

    return issues


class SidUniquenessCheck(PolicyCheck):
    """Validates that Statement IDs (Sids) are unique within a policy.

    This is a special policy-level check that examines all statements together.
    It only runs once when processing the first statement to avoid duplicate work.
    """

    check_id: ClassVar[str] = "sid_uniqueness"
    description: ClassVar[str] = (
        "Validates that Statement IDs (Sids) are unique and follow AWS naming requirements (no spaces)"
    )
    default_severity: ClassVar[str] = "warning"

    async def execute_policy(
        self,
        policy: IAMPolicy,
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        """Execute the SID uniqueness check on the entire policy.

        This method examines all statements together to find duplicate SIDs.

        Args:
            policy: The complete IAM policy to validate
            policy_file: Path to the policy file (unused, kept for API consistency)
            fetcher: AWS service fetcher (unused for this check)
            config: Configuration for this check instance

        Returns:
            List of ValidationIssue objects for duplicate SIDs
        """
        del policy_file, fetcher  # Unused
        severity = self.get_severity(config)
        return _check_sid_uniqueness_impl(policy, severity)

"""Statement ID (SID) uniqueness check.

This check validates that Statement IDs (Sids) are unique within a policy.
According to AWS best practices, while not strictly required, having unique SIDs
makes it easier to reference specific statements and improves policy maintainability.

This is implemented as a policy-level check that runs once when processing the first
statement, examining all statements in the policy to find duplicates.
"""

from collections import Counter

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import IAMPolicy, Statement, ValidationIssue


def _check_sid_uniqueness_impl(policy: IAMPolicy, severity: str) -> list[ValidationIssue]:
    """Implementation of SID uniqueness checking.

    Args:
        policy: IAM policy to validate
        severity: Severity level for issues found

    Returns:
        List of ValidationIssue objects for duplicate SIDs
    """
    issues: list[ValidationIssue] = []

    # Collect all SIDs (ignoring None/empty values)
    sids_with_indices: list[tuple[str, int]] = []
    for idx, statement in enumerate(policy.statement):
        if statement.sid:  # Only check statements that have a SID
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
            issues.append(
                ValidationIssue(
                    severity=severity,
                    statement_sid=duplicate_sid,
                    statement_index=idx,
                    issue_type="duplicate_sid",
                    message=f"Statement ID '{duplicate_sid}' is used {count} times in this policy (found in statements {', '.join(f'[{i}]' for i in indices)})",
                    suggestion="Change this SID to a unique value. Statement IDs help identify and reference specific statements, so duplicates can cause confusion.",
                    line_number=statement.line_number,
                )
            )

    return issues


class SidUniquenessCheck(PolicyCheck):
    """Validates that Statement IDs (Sids) are unique within a policy.

    This is a special policy-level check that examines all statements together.
    It only runs once when processing the first statement to avoid duplicate work.
    """

    @property
    def check_id(self) -> str:
        return "sid_uniqueness"

    @property
    def description(self) -> str:
        return "Validates that Statement IDs (Sids) are unique within the policy"

    @property
    def default_severity(self) -> str:
        return "warning"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute the SID uniqueness check at statement level.

        This is a policy-level check, so statement-level execution returns empty.
        The actual check runs in execute_policy() which has access to all statements.

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
        policy: IAMPolicy,
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
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

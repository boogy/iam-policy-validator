"""Finding fingerprint generation for stable issue identification.

This module provides a way to generate unique, deterministic identifiers
for validation findings that survive code changes within a PR. These
fingerprints are used to track which findings have been ignored by CODEOWNERS.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from iam_validator.core.models import ValidationIssue


def compute_finding_hash(
    file_path: str,
    check_id: str | None,
    issue_type: str,
    statement_sid: str | None,
    statement_index: int,
    action: str | None = None,
    resource: str | None = None,
    condition_key: str | None = None,
) -> str:
    """Compute a deterministic 16-character hash for a finding.

    This is a standalone function to avoid cyclic imports when called
    from models.py.

    Args:
        file_path: Relative path to the policy file
        check_id: Check that found the issue
        issue_type: Type of issue
        statement_sid: Statement ID if available
        statement_index: Statement index
        action: Specific action (optional)
        resource: Specific resource (optional)
        condition_key: Condition key (optional)

    Returns:
        16-character hex string uniquely identifying this finding
    """
    # Use SID if available, otherwise fall back to index
    statement_id = statement_sid if statement_sid else f"idx:{statement_index}"

    components = [
        file_path,
        check_id or "",
        issue_type,
        statement_id,
        action or "",
        resource or "",
        condition_key or "",
    ]
    combined = "|".join(components)
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class FindingFingerprint:
    """Unique identifier for a validation finding across runs.

    The fingerprint is based on stable attributes of the finding that
    are unlikely to change when code is modified within the same PR.
    Uses frozen=True for immutability and slots=True for memory efficiency.

    Attributes:
        file_path: Relative path to the policy file
        check_id: Check that found the issue (e.g., "sensitive_action")
        issue_type: Type of issue (e.g., "invalid_action")
        statement_sid: Statement ID if available (more stable than index)
        statement_index: Fallback when no SID is present
        action: Specific action (for action-related issues)
        resource: Specific resource (for resource-related issues)
        condition_key: Specific condition key (for condition issues)
    """

    file_path: str
    check_id: str
    issue_type: str
    statement_sid: str | None
    statement_index: int
    action: str | None
    resource: str | None
    condition_key: str | None

    def to_hash(self) -> str:
        """Generate deterministic 16-character hash for storage.

        The hash is based on all fingerprint components joined with a
        delimiter. Uses SHA-256 truncated to 16 characters for a good
        balance between uniqueness and storage efficiency.

        Returns:
            16-character hex string uniquely identifying this finding
        """
        return compute_finding_hash(
            file_path=self.file_path,
            check_id=self.check_id,
            issue_type=self.issue_type,
            statement_sid=self.statement_sid,
            statement_index=self.statement_index,
            action=self.action,
            resource=self.resource,
            condition_key=self.condition_key,
        )

    @classmethod
    def from_issue(cls, issue: ValidationIssue, file_path: str) -> FindingFingerprint:
        """Create fingerprint from a ValidationIssue.

        Args:
            issue: The validation issue to fingerprint
            file_path: Relative path to the policy file

        Returns:
            FindingFingerprint instance for the issue
        """
        return cls(
            file_path=file_path,
            check_id=issue.check_id or "",
            issue_type=issue.issue_type,
            statement_sid=issue.statement_sid,
            statement_index=issue.statement_index,
            action=issue.action,
            resource=issue.resource,
            condition_key=issue.condition_key,
        )

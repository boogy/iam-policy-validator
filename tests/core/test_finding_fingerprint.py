"""Tests for finding fingerprint generation."""

import pytest

from iam_validator.core.finding_fingerprint import FindingFingerprint
from iam_validator.core.models import ValidationIssue


class TestFindingFingerprint:
    """Tests for FindingFingerprint class."""

    def test_fingerprint_from_issue_basic(self):
        """Test creating fingerprint from basic issue."""
        issue = ValidationIssue(
            severity="high",
            issue_type="sensitive_action",
            message="Test message",
            statement_index=0,
            action="iam:CreateUser",
        )

        fingerprint = FindingFingerprint.from_issue(issue, "policies/admin.json")

        assert fingerprint.file_path == "policies/admin.json"
        assert fingerprint.check_id == ""
        assert fingerprint.issue_type == "sensitive_action"
        assert fingerprint.statement_index == 0
        assert fingerprint.action == "iam:CreateUser"

    def test_fingerprint_from_issue_with_all_fields(self):
        """Test creating fingerprint from issue with all fields."""
        issue = ValidationIssue(
            severity="high",
            issue_type="sensitive_action",
            message="Test message",
            statement_index=1,
            statement_sid="AllowAdmin",
            action="s3:PutObject",
            resource="arn:aws:s3:::bucket/*",
            condition_key="aws:SourceIp",
            check_id="sensitive_action",
        )

        fingerprint = FindingFingerprint.from_issue(issue, "policies/s3.json")

        assert fingerprint.file_path == "policies/s3.json"
        assert fingerprint.check_id == "sensitive_action"
        assert fingerprint.issue_type == "sensitive_action"
        assert fingerprint.statement_sid == "AllowAdmin"
        assert fingerprint.statement_index == 1
        assert fingerprint.action == "s3:PutObject"
        assert fingerprint.resource == "arn:aws:s3:::bucket/*"
        assert fingerprint.condition_key == "aws:SourceIp"

    def test_fingerprint_hash_deterministic(self):
        """Test that hash is deterministic."""
        issue = ValidationIssue(
            severity="high",
            issue_type="sensitive_action",
            message="Test",
            statement_index=0,
            action="iam:CreateUser",
        )

        fp1 = FindingFingerprint.from_issue(issue, "policy.json")
        fp2 = FindingFingerprint.from_issue(issue, "policy.json")

        assert fp1.to_hash() == fp2.to_hash()

    def test_fingerprint_hash_length(self):
        """Test that hash is 16 characters."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
        )

        fingerprint = FindingFingerprint.from_issue(issue, "policy.json")
        hash_value = fingerprint.to_hash()

        assert len(hash_value) == 16
        assert all(c in "0123456789abcdef" for c in hash_value)

    def test_fingerprint_different_files(self):
        """Test that different files produce different hashes."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
        )

        fp1 = FindingFingerprint.from_issue(issue, "policy1.json")
        fp2 = FindingFingerprint.from_issue(issue, "policy2.json")

        assert fp1.to_hash() != fp2.to_hash()

    def test_fingerprint_different_actions(self):
        """Test that different actions produce different hashes."""
        issue1 = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
            action="iam:CreateUser",
        )
        issue2 = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
            action="iam:DeleteUser",
        )

        fp1 = FindingFingerprint.from_issue(issue1, "policy.json")
        fp2 = FindingFingerprint.from_issue(issue2, "policy.json")

        assert fp1.to_hash() != fp2.to_hash()

    def test_fingerprint_different_statement_index(self):
        """Test that different statement indices produce different hashes."""
        issue1 = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
        )
        issue2 = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=1,
        )

        fp1 = FindingFingerprint.from_issue(issue1, "policy.json")
        fp2 = FindingFingerprint.from_issue(issue2, "policy.json")

        assert fp1.to_hash() != fp2.to_hash()

    def test_fingerprint_with_sid_preferred(self):
        """Test that SID is used instead of index when available."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
            statement_sid="MyStatement",
        )

        fingerprint = FindingFingerprint.from_issue(issue, "policy.json")
        hash1 = fingerprint.to_hash()

        # Change statement index - hash should be same due to SID
        issue2 = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=5,  # Different index
            statement_sid="MyStatement",  # Same SID
        )

        fingerprint2 = FindingFingerprint.from_issue(issue2, "policy.json")
        hash2 = fingerprint2.to_hash()

        assert hash1 == hash2

    def test_fingerprint_message_not_in_hash(self):
        """Test that message does not affect hash (allows message changes)."""
        issue1 = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Original message",
            statement_index=0,
            action="iam:CreateUser",
        )
        issue2 = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Different message",
            statement_index=0,
            action="iam:CreateUser",
        )

        fp1 = FindingFingerprint.from_issue(issue1, "policy.json")
        fp2 = FindingFingerprint.from_issue(issue2, "policy.json")

        assert fp1.to_hash() == fp2.to_hash()

    def test_fingerprint_severity_not_in_hash(self):
        """Test that severity does not affect hash."""
        issue1 = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
        )
        issue2 = ValidationIssue(
            severity="critical",
            issue_type="test",
            message="Test",
            statement_index=0,
        )

        fp1 = FindingFingerprint.from_issue(issue1, "policy.json")
        fp2 = FindingFingerprint.from_issue(issue2, "policy.json")

        assert fp1.to_hash() == fp2.to_hash()

    def test_fingerprint_immutable(self):
        """Test that fingerprint is immutable (frozen dataclass)."""
        fingerprint = FindingFingerprint(
            file_path="policy.json",
            check_id="test",
            issue_type="test",
            statement_sid=None,
            statement_index=0,
            action=None,
            resource=None,
            condition_key=None,
        )

        with pytest.raises(Exception):  # FrozenInstanceError
            fingerprint.file_path = "other.json" # type: ignore

    def test_fingerprint_hashable(self):
        """Test that fingerprint can be used in sets (hashable)."""
        fp1 = FindingFingerprint(
            file_path="policy.json",
            check_id="test",
            issue_type="test",
            statement_sid=None,
            statement_index=0,
            action=None,
            resource=None,
            condition_key=None,
        )
        fp2 = FindingFingerprint(
            file_path="policy.json",
            check_id="test",
            issue_type="test",
            statement_sid=None,
            statement_index=0,
            action=None,
            resource=None,
            condition_key=None,
        )

        # Should be usable in set
        fingerprints = {fp1, fp2}
        assert len(fingerprints) == 1  # Same fingerprint, one entry


class TestFindingFingerprintEdgeCases:
    """Edge case tests for FindingFingerprint."""

    def test_fingerprint_with_none_values(self):
        """Test fingerprint with None values."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
            action=None,
            resource=None,
            condition_key=None,
            statement_sid=None,
            check_id=None,
        )

        fingerprint = FindingFingerprint.from_issue(issue, "policy.json")
        hash_value = fingerprint.to_hash()

        assert len(hash_value) == 16

    def test_fingerprint_with_special_characters(self):
        """Test fingerprint with special characters in values."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
            action="s3:*",
            resource="arn:aws:s3:::bucket/*",
            statement_sid="Allow|Special&Chars",
        )

        fingerprint = FindingFingerprint.from_issue(issue, "path/with spaces/policy.json")
        hash_value = fingerprint.to_hash()

        # Should still produce valid hash
        assert len(hash_value) == 16
        assert all(c in "0123456789abcdef" for c in hash_value)

    def test_fingerprint_unicode_handling(self):
        """Test fingerprint handles unicode characters."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test with émoji 🔐",
            statement_index=0,
            statement_sid="Téléchargement",
        )

        fingerprint = FindingFingerprint.from_issue(issue, "polícy.json")
        hash_value = fingerprint.to_hash()

        assert len(hash_value) == 16

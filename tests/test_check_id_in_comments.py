"""Tests for check_id injection and display in PR comments."""

import pytest

from iam_validator.core.models import ValidationIssue


class TestCheckIDInComments:
    """Test suite for check_id in review comments."""

    def test_validation_issue_has_check_id_field(self):
        """Test that ValidationIssue model has check_id field."""
        issue = ValidationIssue(
            severity="error",
            statement_index=0,
            issue_type="invalid_action",
            message="Test issue",
            check_id="action_validation",
        )
        assert issue.check_id == "action_validation"

    def test_to_pr_comment_includes_check_id(self):
        """Test that to_pr_comment includes check_id at the bottom."""
        issue = ValidationIssue(
            severity="error",
            statement_index=0,
            issue_type="invalid_action",
            message="Invalid action 's3:GetObjekt' does not exist",
            check_id="action_validation",
        )

        comment = issue.to_pr_comment(include_identifier=False)

        # Should include check ID at the bottom
        assert "*Check: `action_validation`*" in comment
        # Should have separator before check ID
        assert "---" in comment

    def test_to_pr_comment_without_check_id(self):
        """Test that to_pr_comment works when check_id is None."""
        issue = ValidationIssue(
            severity="error",
            statement_index=0,
            issue_type="invalid_action",
            message="Invalid action",
            check_id=None,
        )

        comment = issue.to_pr_comment(include_identifier=False)

        # Should NOT include check ID section
        assert "*Check:" not in comment

    def test_to_pr_comment_check_id_with_details(self):
        """Test check_id placement with collapsible details section."""
        issue = ValidationIssue(
            severity="error",
            statement_index=0,
            issue_type="invalid_action",
            message="Invalid action",
            action="s3:GetObjekt",
            suggestion="Use s3:GetObject instead",
            check_id="action_validation",
        )

        comment = issue.to_pr_comment(include_identifier=False)

        # Check ID should be after the closing details tag
        details_end = comment.find("</details>")
        check_id_pos = comment.find("*Check: `action_validation`*")

        assert details_end != -1, "Should have details section"
        assert check_id_pos != -1, "Should have check ID"
        assert check_id_pos > details_end, "Check ID should be after details section"

    def test_to_pr_comment_check_id_without_details(self):
        """Test check_id placement without collapsible details section."""
        issue = ValidationIssue(
            severity="error",
            statement_index=0,
            issue_type="policy_size_exceeded",
            message="Policy size exceeds limit",
            check_id="policy_size",
        )

        comment = issue.to_pr_comment(include_identifier=False)

        # Should NOT have details section
        assert "<details>" not in comment
        assert "</details>" not in comment

        # But should still have check ID at the end
        assert "*Check: `policy_size`*" in comment
        assert comment.strip().endswith("*Check: `policy_size`*")

    def test_check_id_format_in_comment(self):
        """Test that check_id is properly formatted in comment."""
        issue = ValidationIssue(
            severity="high",
            statement_index=0,
            issue_type="sensitive_action",
            message="Sensitive action without conditions",
            check_id="sensitive_action",
        )

        comment = issue.to_pr_comment(include_identifier=False)

        # Check format
        assert "\n---\n" in comment  # Separator
        assert "*Check: `sensitive_action`*" in comment  # Formatted with backticks and italics

    def test_different_check_ids(self):
        """Test various check IDs are displayed correctly."""
        check_ids = [
            "action_validation",
            "policy_size",
            "sensitive_action",
            "wildcard_action",
            "condition_key_validation",
            "principal_validation",
        ]

        for check_id in check_ids:
            issue = ValidationIssue(
                severity="error",
                statement_index=0,
                issue_type="test",
                message="Test message",
                check_id=check_id,
            )

            comment = issue.to_pr_comment(include_identifier=False)
            assert f"*Check: `{check_id}`*" in comment

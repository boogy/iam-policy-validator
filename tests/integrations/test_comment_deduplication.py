"""Tests for PR comment deduplication logic."""

import pytest
from unittest.mock import AsyncMock, patch

from iam_validator.integrations.github_integration import GitHubIntegration, ReviewEvent


class TestCommentDeduplication:
    """Test that PR comments are properly deduplicated."""

    @pytest.fixture
    def github_integration(self):
        """Create a GitHubIntegration with mocked environment."""
        with patch.dict(
            "os.environ",
            {
                "GITHUB_TOKEN": "test-token",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_PR_NUMBER": "123",
            },
        ):
            return GitHubIntegration()

    @pytest.mark.asyncio
    async def test_fingerprint_mismatch_uses_location_fallback(self, github_integration):
        """Test that when fingerprints don't match, location-based matching is used.

        This prevents duplicate comments when:
        - The file path used in fingerprint calculation changed (e.g., absolute vs relative)
        - The check_id or other fingerprint fields changed
        - The configuration changed between runs
        """
        # Existing comment at line 5 with one fingerprint
        existing_comments = [
            {
                "id": 100,
                "path": "policy.json",
                "line": 5,
                "body": (
                    "<!-- iam-validator-review -->\n"
                    "<!-- iam-policy-validator-bot -->\n"
                    "<!-- issue-type: invalid_action -->\n"
                    "<!-- finding-id: aaaa111122223333 -->\n"  # Old fingerprint
                    "Error: Invalid action"
                ),
            }
        ]

        # New comment with DIFFERENT fingerprint but SAME location and issue type
        new_comments = [
            {
                "path": "policy.json",
                "line": 5,
                "body": (
                    "<!-- iam-validator-review -->\n"
                    "<!-- iam-policy-validator-bot -->\n"
                    "<!-- issue-type: invalid_action -->\n"
                    "<!-- finding-id: bbbb444455556666 -->\n"  # New fingerprint (different!)
                    "Error: Invalid action (updated message)"
                ),
            }
        ]

        # Mock the methods
        github_integration.get_review_comments = AsyncMock(return_value=existing_comments)
        github_integration.update_review_comment = AsyncMock(return_value=True)
        github_integration.create_review_with_comments = AsyncMock(return_value=True)
        github_integration.get_pr_files = AsyncMock(return_value=[{"filename": "policy.json"}])

        result = await github_integration.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier="<!-- iam-policy-validator-bot -->",
            validated_files={"policy.json"},
        )

        assert result is True
        # Should UPDATE the existing comment, NOT create a new one
        github_integration.update_review_comment.assert_called_once_with(
            100, new_comments[0]["body"]
        )
        # Should NOT create any new comments
        github_integration.create_review_with_comments.assert_not_called()

    @pytest.mark.asyncio
    async def test_same_fingerprint_updates_in_place(self, github_integration):
        """Test that matching fingerprints result in updates, not new comments."""
        fingerprint = "aaaa111122223333"
        existing_comments = [
            {
                "id": 100,
                "path": "policy.json",
                "line": 5,
                "body": (
                    f"<!-- iam-validator-review -->\n"
                    f"<!-- iam-policy-validator-bot -->\n"
                    f"<!-- issue-type: invalid_action -->\n"
                    f"<!-- finding-id: {fingerprint} -->\n"
                    "Error: Invalid action"
                ),
            }
        ]

        new_comments = [
            {
                "path": "policy.json",
                "line": 5,  # Same line
                "body": (
                    f"<!-- iam-validator-review -->\n"
                    f"<!-- iam-policy-validator-bot -->\n"
                    f"<!-- issue-type: invalid_action -->\n"
                    f"<!-- finding-id: {fingerprint} -->\n"  # SAME fingerprint
                    "Error: Invalid action (updated)"
                ),
            }
        ]

        github_integration.get_review_comments = AsyncMock(return_value=existing_comments)
        github_integration.update_review_comment = AsyncMock(return_value=True)
        github_integration.create_review_with_comments = AsyncMock(return_value=True)
        github_integration.get_pr_files = AsyncMock(return_value=[{"filename": "policy.json"}])

        result = await github_integration.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier="<!-- iam-policy-validator-bot -->",
            validated_files={"policy.json"},
        )

        assert result is True
        github_integration.update_review_comment.assert_called_once()
        github_integration.create_review_with_comments.assert_not_called()

    @pytest.mark.asyncio
    async def test_resolved_issue_comment_deleted(self, github_integration):
        """Test that comments for resolved issues are deleted."""
        # Existing comment for an issue that no longer exists
        existing_comments = [
            {
                "id": 100,
                "path": "policy.json",
                "line": 5,
                "body": (
                    "<!-- iam-validator-review -->\n"
                    "<!-- iam-policy-validator-bot -->\n"
                    "<!-- issue-type: invalid_action -->\n"
                    "<!-- finding-id: aaaa111122223333 -->\n"
                    "Error: Invalid action"
                ),
            }
        ]

        # No new comments (issue was fixed)
        new_comments = []

        github_integration.get_review_comments = AsyncMock(return_value=existing_comments)
        github_integration.delete_review_comment = AsyncMock(return_value=True)
        github_integration.create_review_with_comments = AsyncMock(return_value=True)
        github_integration.get_pr_files = AsyncMock(return_value=[{"filename": "policy.json"}])

        result = await github_integration.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier="<!-- iam-policy-validator-bot -->",
            validated_files={"policy.json"},
        )

        assert result is True
        # Should delete the stale comment
        github_integration.delete_review_comment.assert_called_once_with(100)

    @pytest.mark.asyncio
    async def test_new_comment_created_for_new_issue(self, github_integration):
        """Test that new issues get new comments created."""
        # No existing comments
        existing_comments = []

        new_comments = [
            {
                "path": "policy.json",
                "line": 10,
                "body": (
                    "<!-- iam-validator-review -->\n"
                    "<!-- iam-policy-validator-bot -->\n"
                    "<!-- issue-type: invalid_action -->\n"
                    "<!-- finding-id: aaaa111122223333 -->\n"
                    "Error: New issue"
                ),
            }
        ]

        github_integration.get_review_comments = AsyncMock(return_value=existing_comments)
        github_integration.create_review_with_comments = AsyncMock(return_value=True)
        github_integration.get_pr_files = AsyncMock(return_value=[{"filename": "policy.json"}])

        result = await github_integration.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier="<!-- iam-policy-validator-bot -->",
            validated_files={"policy.json"},
        )

        assert result is True
        github_integration.create_review_with_comments.assert_called_once_with(
            new_comments,
            body="",
            event=ReviewEvent.COMMENT,
        )

    @pytest.mark.asyncio
    async def test_multiple_issues_same_line_different_types(self, github_integration):
        """Test that multiple issues at the same line with different types are handled."""
        existing_comments = [
            {
                "id": 100,
                "path": "policy.json",
                "line": 5,
                "body": (
                    "<!-- iam-validator-review -->\n"
                    "<!-- iam-policy-validator-bot -->\n"
                    "<!-- issue-type: invalid_action -->\n"
                    "<!-- finding-id: aaaa111122223333 -->\n"
                    "Error: Invalid action"
                ),
            },
            {
                "id": 101,
                "path": "policy.json",
                "line": 5,
                "body": (
                    "<!-- iam-validator-review -->\n"
                    "<!-- iam-policy-validator-bot -->\n"
                    "<!-- issue-type: resource_mismatch -->\n"  # Different issue type
                    "<!-- finding-id: bbbb444455556666 -->\n"
                    "Error: Resource mismatch"
                ),
            },
        ]

        # Only one issue remains (the other was fixed)
        new_comments = [
            {
                "path": "policy.json",
                "line": 5,
                "body": (
                    "<!-- iam-validator-review -->\n"
                    "<!-- iam-policy-validator-bot -->\n"
                    "<!-- issue-type: invalid_action -->\n"
                    "<!-- finding-id: aaaa111122223333 -->\n"
                    "Error: Invalid action (still there)"
                ),
            },
        ]

        github_integration.get_review_comments = AsyncMock(return_value=existing_comments)
        github_integration.update_review_comment = AsyncMock(return_value=True)
        github_integration.delete_review_comment = AsyncMock(return_value=True)
        github_integration.create_review_with_comments = AsyncMock(return_value=True)
        github_integration.get_pr_files = AsyncMock(return_value=[{"filename": "policy.json"}])

        result = await github_integration.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier="<!-- iam-policy-validator-bot -->",
            validated_files={"policy.json"},
        )

        assert result is True
        # Should update the existing invalid_action comment
        github_integration.update_review_comment.assert_called_once()
        # Should delete the resource_mismatch comment (it's resolved)
        github_integration.delete_review_comment.assert_called_once_with(101)

    @pytest.mark.asyncio
    async def test_location_matched_comment_not_deleted(self, github_integration):
        """Test that a comment updated via location fallback is NOT deleted.

        This is a critical test for the bug fix: when fingerprints don't match,
        we use location-based matching to update the comment. The old fingerprint
        should NOT cause the comment to be deleted afterwards.
        """
        old_fingerprint = "aaaa111122223333"
        new_fingerprint = "bbbb444455556666"

        existing_comments = [
            {
                "id": 100,
                "path": "policy.json",
                "line": 5,
                "body": (
                    "<!-- iam-validator-review -->\n"
                    "<!-- iam-policy-validator-bot -->\n"
                    "<!-- issue-type: invalid_action -->\n"
                    f"<!-- finding-id: {old_fingerprint} -->\n"
                    "Error: Invalid action"
                ),
            }
        ]

        # New comment with DIFFERENT fingerprint (simulating path change)
        new_comments = [
            {
                "path": "policy.json",
                "line": 5,
                "body": (
                    "<!-- iam-validator-review -->\n"
                    "<!-- iam-policy-validator-bot -->\n"
                    "<!-- issue-type: invalid_action -->\n"
                    f"<!-- finding-id: {new_fingerprint} -->\n"
                    "Error: Invalid action (updated)"
                ),
            }
        ]

        github_integration.get_review_comments = AsyncMock(return_value=existing_comments)
        github_integration.update_review_comment = AsyncMock(return_value=True)
        github_integration.delete_review_comment = AsyncMock(return_value=True)
        github_integration.create_review_with_comments = AsyncMock(return_value=True)
        github_integration.get_pr_files = AsyncMock(return_value=[{"filename": "policy.json"}])

        result = await github_integration.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier="<!-- iam-policy-validator-bot -->",
            validated_files={"policy.json"},
        )

        assert result is True
        # Should UPDATE the existing comment via location fallback
        github_integration.update_review_comment.assert_called_once_with(
            100, new_comments[0]["body"]
        )
        # Should NOT delete it (it was matched and updated)
        github_integration.delete_review_comment.assert_not_called()
        # Should NOT create any new comments
        github_integration.create_review_with_comments.assert_not_called()

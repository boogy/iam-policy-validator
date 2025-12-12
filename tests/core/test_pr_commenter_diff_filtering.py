"""Integration tests for PR commenter diff filtering functionality."""

import os
import tempfile
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.models import PolicyValidationResult, ValidationIssue, ValidationReport
from iam_validator.core.pr_commenter import PRCommenter
from iam_validator.integrations.github_integration import GitHubIntegration


class TestPRCommenterDiffFiltering:
    """Integration tests for diff filtering in PR comments."""

    @pytest.fixture
    def mock_github(self):
        """Create a mock GitHub integration."""
        github = MagicMock(spec=GitHubIntegration)
        github.is_configured = MagicMock(return_value=True)
        github.get_pr_files = AsyncMock(return_value=[])
        github.update_or_create_review_comments = AsyncMock(return_value=True)
        github.post_multipart_comments = AsyncMock(return_value=True)
        github.cleanup_bot_review_comments = AsyncMock(return_value=None)
        return github

    @pytest.fixture
    def sample_policy_file(self):
        """Create a temporary policy file for testing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(
                """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3Read",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    },
    {
      "Sid": "AllowDynamoDB",
      "Effect": "Allow",
      "Action": "dynamodb:*",
      "Resource": "arn:aws:dynamodb:*:*:table/*"
    }
  ]
}"""
            )
            policy_file = f.name

        yield policy_file
        Path(policy_file).unlink()

    @pytest.fixture
    def validation_report_with_issues(self, sample_policy_file):
        """Create a validation report with issues in multiple statements."""
        # Issue in Statement 0, line 7 (Action)
        issue1 = ValidationIssue(
            policy_file=sample_policy_file,
            statement_index=0,
            severity="warning",
            issue_type="overly_broad_action",
            message="Action should be more specific",
            action="s3:GetObject",
            line_number=7,
        )

        # Issue in Statement 0, line 8 (Resource)
        issue2 = ValidationIssue(
            policy_file=sample_policy_file,
            statement_index=0,
            severity="error",
            issue_type="wildcard_resource",
            message="Resource should not use wildcard",
            resource="*",
            line_number=8,
        )

        # Issue in Statement 1, line 14 (Action wildcard)
        issue3 = ValidationIssue(
            policy_file=sample_policy_file,
            statement_index=1,
            severity="critical",
            issue_type="wildcard_action",
            message="Action uses dangerous wildcard",
            action="dynamodb:*",
            line_number=14,
        )

        result = PolicyValidationResult(
            policy_file=sample_policy_file,
            is_valid=False,
            issues=[issue1, issue2, issue3],
            policy_type="IDENTITY_POLICY",
        )

        return ValidationReport(
            results=[result],
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            valid_count=0,
            invalid_count=1,
            total_issues=3,
            policies_with_security_issues=1,
            validity_issues=0,
            security_issues=3,
        )

    @pytest.mark.asyncio
    async def test_no_diff_filtering_when_pr_files_empty(
        self, mock_github, validation_report_with_issues
    ):
        """Test that when PR files can't be fetched, filtering falls back gracefully."""
        mock_github.get_pr_files.return_value = []

        # With cleanup_old_comments=False (streaming mode), cleanup is skipped
        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": tempfile.gettempdir()}):
            success = await commenter._post_review_comments(validation_report_with_issues)

        assert success is True
        # With cleanup_old_comments=False, no call is made when there are no inline comments
        # (cleanup happens at the end of streaming mode, not per-file)
        mock_github.update_or_create_review_comments.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_diff_filtering_with_cleanup_enabled(
        self, mock_github, validation_report_with_issues
    ):
        """Test that when cleanup is enabled and no inline comments, cleanup still runs."""
        mock_github.get_pr_files.return_value = []

        # With cleanup_old_comments=True (batch mode), cleanup should run even with no comments
        commenter = PRCommenter(github=mock_github, cleanup_old_comments=True)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": tempfile.gettempdir()}):
            success = await commenter._post_review_comments(validation_report_with_issues)

        assert success is True
        # Should call update_or_create_review_comments for cleanup with empty comments
        mock_github.update_or_create_review_comments.assert_called_once()
        call_args = mock_github.update_or_create_review_comments.call_args
        assert call_args.kwargs["comments"] == []  # No inline comments (diff filtering)
        assert call_args.kwargs["validated_files"] is not None  # But validated_files passed for cleanup

    @pytest.mark.asyncio
    async def test_strict_filtering_inline_comments_only_changed_lines(
        self, mock_github, validation_report_with_issues, sample_policy_file
    ):
        """Test that inline comments only appear on changed lines."""
        # Mock PR diff: only line 7 was changed (Action field in Statement 0)
        mock_github.get_pr_files.return_value = [
            {
                "filename": Path(sample_policy_file).name,
                "status": "modified",
                "patch": """@@ -4,7 +4,7 @@
     {
       "Sid": "AllowS3Read",
       "Effect": "Allow",
-      "Action": "s3:GetObject",
+      "Action": "s3:*",
       "Resource": "*"
     },
     {""",
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            success = await commenter._post_review_comments(validation_report_with_issues)

        assert success is True
        mock_github.update_or_create_review_comments.assert_called_once()

        # Check the comments passed to GitHub
        call_args = mock_github.update_or_create_review_comments.call_args
        comments = call_args.kwargs["comments"]

        # Should only have comment for line 7 (the changed line)
        assert len(comments) == 1
        assert comments[0]["line"] == 7

        # Line 8 issue should be in context_issues
        assert len(commenter._context_issues) == 1
        assert commenter._context_issues[0].line_number == 8
        assert commenter._context_issues[0].statement_index == 0

    @pytest.mark.asyncio
    async def test_context_issues_for_modified_statement_unchanged_lines(
        self, mock_github, validation_report_with_issues, sample_policy_file
    ):
        """Test that issues in modified statements but unchanged lines go to context."""
        # Mock PR diff: line 7 changed (Statement 0)
        mock_github.get_pr_files.return_value = [
            {
                "filename": Path(sample_policy_file).name,
                "status": "modified",
                "patch": "@@ -4,7 +4,7 @@\n     {\n       \"Sid\": \"AllowS3Read\",\n       \"Effect\": \"Allow\",\n-      \"Action\": \"s3:GetObject\",\n+      \"Action\": \"s3:*\",\n       \"Resource\": \"*\"\n     },\n     {",
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(validation_report_with_issues)

        # Line 7 (changed) - inline comment
        # Line 8 (unchanged but in modified statement) - context issue
        # Line 14 (unchanged statement) - skipped entirely

        call_args = mock_github.update_or_create_review_comments.call_args
        comments = call_args.kwargs["comments"]

        assert len(comments) == 1  # Only line 7
        assert comments[0]["line"] == 7

        # Check context issues
        assert len(commenter._context_issues) == 1
        context_issue = commenter._context_issues[0]
        assert context_issue.line_number == 8
        assert context_issue.statement_index == 0
        assert context_issue.issue.severity == "error"

    @pytest.mark.asyncio
    async def test_unchanged_statement_issues_ignored(
        self, mock_github, validation_report_with_issues, sample_policy_file
    ):
        """Test that issues in completely unchanged statements are ignored."""
        # Mock PR diff: only line 7 changed (Statement 0)
        # Statement 1 (lines 11-16) is completely unchanged
        mock_github.get_pr_files.return_value = [
            {
                "filename": Path(sample_policy_file).name,
                "status": "modified",
                "patch": "@@ -4,7 +4,7 @@\n     {\n       \"Sid\": \"AllowS3Read\",\n       \"Effect\": \"Allow\",\n-      \"Action\": \"s3:GetObject\",\n+      \"Action\": \"s3:*\",\n       \"Resource\": \"*\"\n     },\n     {",
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(validation_report_with_issues)

        # Check that line 14 (Statement 1) is NOT in context issues
        context_issue_lines = [ci.line_number for ci in commenter._context_issues]
        assert 14 not in context_issue_lines

        # Only line 8 should be in context (modified statement, unchanged line)
        assert len(commenter._context_issues) == 1
        assert commenter._context_issues[0].line_number == 8

    @pytest.mark.asyncio
    async def test_multiple_statements_modified(
        self, mock_github, validation_report_with_issues, sample_policy_file
    ):
        """Test filtering when multiple statements are modified."""
        # Mock PR diff: changes in both Statement 0 and Statement 1
        mock_github.get_pr_files.return_value = [
            {
                "filename": Path(sample_policy_file).name,
                "status": "modified",
                "patch": """@@ -4,7 +4,7 @@
     {
       "Sid": "AllowS3Read",
       "Effect": "Allow",
-      "Action": "s3:GetObject",
+      "Action": "s3:*",
       "Resource": "*"
     },
@@ -11,7 +11,7 @@
     {
       "Sid": "AllowDynamoDB",
       "Effect": "Allow",
-      "Action": "dynamodb:*",
+      "Action": "dynamodb:Query",
       "Resource": "arn:aws:dynamodb:*:*:table/*"
     }
   ]""",
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(validation_report_with_issues)

        call_args = mock_github.update_or_create_review_comments.call_args
        comments = call_args.kwargs["comments"]

        # Should have inline comments for lines 7 and 14 (both changed)
        comment_lines = [c["line"] for c in comments]
        assert 7 in comment_lines
        assert 14 in comment_lines

        # Line 8 should be in context (Statement 0 modified, line 8 unchanged)
        context_issue_lines = [ci.line_number for ci in commenter._context_issues]
        assert 8 in context_issue_lines

    @pytest.mark.asyncio
    async def test_new_file_all_lines_commented(
        self, mock_github, validation_report_with_issues, sample_policy_file
    ):
        """Test that all issues get inline comments for completely new files."""
        # Mock PR diff: entire file is new (status: added)
        with open(sample_policy_file, encoding="utf-8") as f:
            content = f.read()
            lines = content.split("\n")

        # Generate patch with all lines as additions
        patch_lines = ["@@ -0,0 +1,{} @@".format(len(lines))]
        for line in lines:
            patch_lines.append(f"+{line}")
        patch = "\n".join(patch_lines)

        mock_github.get_pr_files.return_value = [
            {
                "filename": Path(sample_policy_file).name,
                "status": "added",
                "patch": patch,
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(validation_report_with_issues)

        call_args = mock_github.update_or_create_review_comments.call_args
        comments = call_args.kwargs["comments"]

        # All 3 issues should have inline comments (lines 7, 8, 14)
        comment_lines = sorted([c["line"] for c in comments])
        assert comment_lines == [7, 8, 14]

        # No context issues (all lines are new)
        assert len(commenter._context_issues) == 0

    @pytest.mark.skip(reason="Logging test needs caplog setup")
    @pytest.mark.asyncio
    async def test_logging_output(
        self, mock_github, validation_report_with_issues, sample_policy_file, caplog
    ):
        """Test that appropriate logging messages are generated."""
        mock_github.get_pr_files.return_value = [
            {
                "filename": Path(sample_policy_file).name,
                "status": "modified",
                "patch": "@@ -4,7 +4,7 @@\n     {\n       \"Sid\": \"AllowS3Read\",\n       \"Effect\": \"Allow\",\n-      \"Action\": \"s3:GetObject\",\n+      \"Action\": \"s3:*\",\n       \"Resource\": \"*\"\n     },\n     {",
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(validation_report_with_issues)

        # Check for expected log messages
        log_messages = [rec.message for rec in caplog.records]
        assert any("Fetching PR diff information" in msg for msg in log_messages)
        assert any("Parsed diffs for" in msg for msg in log_messages)
        assert any("Diff filtering results" in msg for msg in log_messages)


class TestPRCommenterBlockingIssuesIgnored:
    """Tests for _are_all_blocking_issues_ignored method."""

    @pytest.fixture
    def mock_github(self):
        """Create a mock GitHub integration."""
        github = MagicMock(spec=GitHubIntegration)
        github.is_configured = MagicMock(return_value=True)
        return github

    def test_no_blocking_issues_returns_true(self, mock_github):
        """Test that no blocking issues returns True."""
        commenter = PRCommenter(
            github=mock_github,
            fail_on_severities=["error", "critical"],
        )

        # Report with only warnings (no blocking issues)
        report = ValidationReport(
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            total_issues=1,
            results=[
                PolicyValidationResult(
                    policy_file="/test/policy.json",
                    is_valid=False,
                    issues=[
                        ValidationIssue(
                            severity="warning",
                            issue_type="test_warning",
                            message="Test warning",
                            statement_index=0,
                        )
                    ],
                )
            ],
        )

        result = commenter._are_all_blocking_issues_ignored(report)
        assert result is True

    def test_blocking_issues_not_ignored_returns_false(self, mock_github):
        """Test that unignored blocking issues return False."""
        commenter = PRCommenter(
            github=mock_github,
            fail_on_severities=["error", "critical"],
        )

        # Report with an error (blocking issue, not ignored)
        report = ValidationReport(
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            total_issues=1,
            results=[
                PolicyValidationResult(
                    policy_file="/test/policy.json",
                    is_valid=False,
                    issues=[
                        ValidationIssue(
                            severity="error",
                            issue_type="test_error",
                            message="Test error",
                            statement_index=0,
                        )
                    ],
                )
            ],
        )

        result = commenter._are_all_blocking_issues_ignored(report)
        assert result is False

    def test_all_blocking_issues_ignored_returns_true(self, mock_github):
        """Test that all blocking issues being ignored returns True."""
        from iam_validator.core.finding_fingerprint import FindingFingerprint

        commenter = PRCommenter(
            github=mock_github,
            fail_on_severities=["error", "critical"],
        )

        # Create an issue
        issue = ValidationIssue(
            severity="error",
            issue_type="test_error",
            message="Test error",
            statement_index=0,
        )

        # Calculate the fingerprint for this issue
        fingerprint = FindingFingerprint.from_issue(issue, "policy.json")
        fingerprint_hash = fingerprint.to_hash()

        # Set the ignored finding IDs to include this issue
        commenter._ignored_finding_ids = frozenset([fingerprint_hash])

        report = ValidationReport(
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            total_issues=1,
            results=[
                PolicyValidationResult(
                    policy_file="policy.json",  # Relative path matching the fingerprint
                    is_valid=False,
                    issues=[issue],
                )
            ],
        )

        result = commenter._are_all_blocking_issues_ignored(report)
        assert result is True

    def test_some_blocking_issues_ignored_returns_false(self, mock_github):
        """Test that partial ignored blocking issues returns False."""
        from iam_validator.core.finding_fingerprint import FindingFingerprint

        commenter = PRCommenter(
            github=mock_github,
            fail_on_severities=["error", "critical"],
        )

        # Create two issues
        issue1 = ValidationIssue(
            severity="error",
            issue_type="test_error_1",
            message="Test error 1",
            statement_index=0,
        )
        issue2 = ValidationIssue(
            severity="error",
            issue_type="test_error_2",
            message="Test error 2",
            statement_index=1,
        )

        # Only ignore the first issue
        fingerprint1 = FindingFingerprint.from_issue(issue1, "policy.json")
        commenter._ignored_finding_ids = frozenset([fingerprint1.to_hash()])

        report = ValidationReport(
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            total_issues=2,
            results=[
                PolicyValidationResult(
                    policy_file="policy.json",
                    is_valid=False,
                    issues=[issue1, issue2],
                )
            ],
        )

        result = commenter._are_all_blocking_issues_ignored(report)
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

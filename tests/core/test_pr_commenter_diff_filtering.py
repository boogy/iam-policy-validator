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
        github.create_review_comment = AsyncMock(return_value=False)
        github.create_file_level_comment = AsyncMock(return_value=False)
        github.get_pr_info = AsyncMock(return_value={"head": {"sha": "abc123"}})
        github._get_bot_comments_by_fingerprint = AsyncMock(return_value={})
        github.update_review_comment = AsyncMock(return_value=True)
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
    async def test_no_diff_filtering_when_pr_files_empty(self, mock_github, validation_report_with_issues):
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
    async def test_no_diff_filtering_with_cleanup_enabled(self, mock_github, validation_report_with_issues):
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

        # Line 8 (modified statement, unchanged line) and line 14 (unchanged statement)
        # are both collected as context issues for off-diff posting
        context_issue_lines = sorted([ci.line_number for ci in commenter._context_issues])
        assert 8 in context_issue_lines
        assert 14 in context_issue_lines

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
                "patch": '@@ -4,7 +4,7 @@\n     {\n       "Sid": "AllowS3Read",\n       "Effect": "Allow",\n-      "Action": "s3:GetObject",\n+      "Action": "s3:*",\n       "Resource": "*"\n     },\n     {',
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(validation_report_with_issues)

        # Line 7 (changed) - inline comment
        # Line 8 (unchanged but in modified statement) - context issue
        # Line 14 (unchanged statement) - also collected as context issue

        call_args = mock_github.update_or_create_review_comments.call_args
        comments = call_args.kwargs["comments"]

        assert len(comments) == 1  # Only line 7
        assert comments[0]["line"] == 7

        # Check context issues - both line 8 and line 14 are collected
        context_issue_lines = sorted([ci.line_number for ci in commenter._context_issues])
        assert 8 in context_issue_lines
        assert 14 in context_issue_lines

        # Verify the modified-statement issue has the right properties
        line_8_issue = next(ci for ci in commenter._context_issues if ci.line_number == 8)
        assert line_8_issue.statement_index == 0
        assert line_8_issue.issue.severity == "error"

    @pytest.mark.asyncio
    async def test_unchanged_statement_issues_collected_not_dropped(
        self, mock_github, validation_report_with_issues, sample_policy_file
    ):
        """Test that issues in completely unchanged statements are collected for off-diff posting."""
        # Mock PR diff: only line 7 changed (Statement 0)
        # Statement 1 (lines 11-16) is completely unchanged
        mock_github.get_pr_files.return_value = [
            {
                "filename": Path(sample_policy_file).name,
                "status": "modified",
                "patch": '@@ -4,7 +4,7 @@\n     {\n       "Sid": "AllowS3Read",\n       "Effect": "Allow",\n-      "Action": "s3:GetObject",\n+      "Action": "s3:*",\n       "Resource": "*"\n     },\n     {',
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(validation_report_with_issues)

        # Both line 8 (modified statement, unchanged line) and line 14 (unchanged statement)
        # should be in context issues (off-diff posting failed since mocks return False)
        context_issue_lines = [ci.line_number for ci in commenter._context_issues]
        assert 8 in context_issue_lines
        assert 14 in context_issue_lines
        assert len(commenter._context_issues) == 2

    @pytest.mark.asyncio
    async def test_multiple_statements_modified(self, mock_github, validation_report_with_issues, sample_policy_file):
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
    async def test_new_file_all_lines_commented(self, mock_github, validation_report_with_issues, sample_policy_file):
        """Test that all issues get inline comments for completely new files."""
        # Mock PR diff: entire file is new (status: added)
        with open(sample_policy_file, encoding="utf-8") as f:
            content = f.read()
            lines = content.split("\n")

        # Generate patch with all lines as additions
        patch_lines = [f"@@ -0,0 +1,{len(lines)} @@"]
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
    async def test_logging_output(self, mock_github, validation_report_with_issues, sample_policy_file, caplog):
        """Test that appropriate logging messages are generated."""
        mock_github.get_pr_files.return_value = [
            {
                "filename": Path(sample_policy_file).name,
                "status": "modified",
                "patch": '@@ -4,7 +4,7 @@\n     {\n       "Sid": "AllowS3Read",\n       "Effect": "Allow",\n-      "Action": "s3:GetObject",\n+      "Action": "s3:*",\n       "Resource": "*"\n     },\n     {',
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


class TestPRCommenterOffDiffPipeline:
    """Tests for the off-diff comment posting pipeline."""

    @pytest.fixture
    def mock_github(self):
        """Create a mock GitHub integration."""
        github = MagicMock(spec=GitHubIntegration)
        github.is_configured = MagicMock(return_value=True)
        github.get_pr_files = AsyncMock(return_value=[])
        github.update_or_create_review_comments = AsyncMock(return_value=True)
        github.post_multipart_comments = AsyncMock(return_value=True)
        github.cleanup_bot_review_comments = AsyncMock(return_value=None)
        github.create_review_comment = AsyncMock(return_value=False)
        github.create_file_level_comment = AsyncMock(return_value=False)
        github.get_pr_info = AsyncMock(return_value={"head": {"sha": "abc123"}})
        github._get_bot_comments_by_fingerprint = AsyncMock(return_value={})
        github.update_review_comment = AsyncMock(return_value=True)
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

    @pytest.mark.asyncio
    async def test_off_diff_falls_back_to_file_level(self, mock_github, sample_policy_file):
        """Test that off-diff pipeline falls back to file-level comments when line-level fails."""
        # Line-level fails, file-level succeeds
        mock_github.create_review_comment.return_value = False
        mock_github.create_file_level_comment.return_value = True

        issue = ValidationIssue(
            policy_file=sample_policy_file,
            statement_index=1,
            severity="critical",
            issue_type="wildcard_action",
            message="Action uses dangerous wildcard",
            action="dynamodb:*",
            line_number=14,
        )

        report = ValidationReport(
            results=[
                PolicyValidationResult(
                    policy_file=sample_policy_file,
                    is_valid=False,
                    issues=[issue],
                    policy_type="IDENTITY_POLICY",
                )
            ],
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            total_issues=1,
        )

        # Mock diff: only line 7 changed so line 14 goes to off-diff
        mock_github.get_pr_files.return_value = [
            {
                "filename": Path(sample_policy_file).name,
                "status": "modified",
                "patch": '@@ -4,7 +4,7 @@\n     {\n       "Sid": "AllowS3Read",\n       "Effect": "Allow",\n-      "Action": "s3:GetObject",\n+      "Action": "s3:*",\n       "Resource": "*"\n     },\n     {',
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False, off_diff_comment_mode="individual")

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(report)

        # Line-level should have been attempted first
        mock_github.create_review_comment.assert_called_once()
        call_args = mock_github.create_review_comment.call_args
        assert call_args[0][0] == "abc123"  # commit_id
        assert call_args[0][2] == 14  # line number

        # File-level should have been called as fallback
        mock_github.create_file_level_comment.assert_called_once()
        file_call_args = mock_github.create_file_level_comment.call_args
        assert call_args[0][0] == "abc123"  # commit_id
        assert Path(sample_policy_file).name in file_call_args[0][1]  # file_path

        # Context issues should be empty (successfully posted via file-level)
        assert len(commenter._context_issues) == 0

    @pytest.mark.asyncio
    async def test_off_diff_remaining_issues_stay_in_context(self, mock_github, sample_policy_file):
        """Test that issues that fail both posting methods remain in context_issues."""
        # Both methods fail
        mock_github.create_review_comment.return_value = False
        mock_github.create_file_level_comment.return_value = False

        issue = ValidationIssue(
            policy_file=sample_policy_file,
            statement_index=1,
            severity="critical",
            issue_type="wildcard_action",
            message="Action uses dangerous wildcard",
            action="dynamodb:*",
            line_number=14,
        )

        report = ValidationReport(
            results=[
                PolicyValidationResult(
                    policy_file=sample_policy_file,
                    is_valid=False,
                    issues=[issue],
                    policy_type="IDENTITY_POLICY",
                )
            ],
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            total_issues=1,
        )

        mock_github.get_pr_files.return_value = [
            {
                "filename": Path(sample_policy_file).name,
                "status": "modified",
                "patch": '@@ -4,7 +4,7 @@\n     {\n       "Sid": "AllowS3Read",\n       "Effect": "Allow",\n-      "Action": "s3:GetObject",\n+      "Action": "s3:*",\n       "Resource": "*"\n     },\n     {',
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(report)

        # Both methods failed, so issue remains in context_issues for summary
        assert len(commenter._context_issues) == 1
        assert commenter._context_issues[0].line_number == 14

    @pytest.mark.asyncio
    async def test_context_issues_passed_to_summary(self, mock_github, sample_policy_file):
        """Test that remaining context issues are passed to summary generation."""
        # Both off-diff methods fail so issues stay in context
        mock_github.create_review_comment.return_value = False
        mock_github.create_file_level_comment.return_value = False

        issue = ValidationIssue(
            policy_file=sample_policy_file,
            statement_index=1,
            severity="critical",
            issue_type="wildcard_action",
            message="Action uses dangerous wildcard",
            action="dynamodb:*",
            line_number=14,
        )

        report = ValidationReport(
            results=[
                PolicyValidationResult(
                    policy_file=sample_policy_file,
                    is_valid=False,
                    issues=[issue],
                    policy_type="IDENTITY_POLICY",
                )
            ],
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            total_issues=1,
        )

        mock_github.get_pr_files.return_value = [
            {
                "filename": Path(sample_policy_file).name,
                "status": "modified",
                "patch": '@@ -4,7 +4,7 @@\n     {\n       "Sid": "AllowS3Read",\n       "Effect": "Allow",\n-      "Action": "s3:GetObject",\n+      "Action": "s3:*",\n       "Resource": "*"\n     },\n     {',
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False)

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(report)

        # After _post_review_comments, context_issues should be non-empty
        assert len(commenter._context_issues) >= 1

        # Verify the context issue has the right data for summary display
        ctx = commenter._context_issues[0]
        assert ctx.file_path == Path(sample_policy_file).name
        assert ctx.line_number == 14
        assert ctx.issue.severity == "critical"
        assert ctx.issue.issue_type == "wildcard_action"

    @pytest.mark.asyncio
    async def test_off_diff_skips_existing_unchanged_comment(self, mock_github, sample_policy_file):
        """Test that off-diff pipeline skips posting when identical comment already exists."""
        from iam_validator.core.finding_fingerprint import FindingFingerprint

        issue = ValidationIssue(
            policy_file=sample_policy_file,
            statement_index=1,
            severity="critical",
            issue_type="wildcard_action",
            message="Action uses dangerous wildcard",
            action="dynamodb:*",
            line_number=14,
        )

        relative_path = Path(sample_policy_file).name
        fp_hash = FindingFingerprint.from_issue(issue, relative_path).to_hash()

        # Build the expected body (same as what _post_off_diff_comments would generate)
        expected_body = issue.to_pr_comment(file_path=relative_path)
        expected_body += "\n\n> **Note:** This finding is on line 14, which was not modified in this PR."

        # Mock existing comment with same fingerprint and same body
        mock_github._get_bot_comments_by_fingerprint.return_value = {
            fp_hash: {
                "id": 42,
                "body": expected_body,
                "path": relative_path,
                "line": 14,
            }
        }

        report = ValidationReport(
            results=[
                PolicyValidationResult(
                    policy_file=sample_policy_file,
                    is_valid=False,
                    issues=[issue],
                    policy_type="IDENTITY_POLICY",
                )
            ],
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            total_issues=1,
        )

        mock_github.get_pr_files.return_value = [
            {
                "filename": relative_path,
                "status": "modified",
                "patch": '@@ -4,7 +4,7 @@\n     {\n       "Sid": "AllowS3Read",\n       "Effect": "Allow",\n-      "Action": "s3:GetObject",\n+      "Action": "s3:*",\n       "Resource": "*"\n     },\n     {',
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False, off_diff_comment_mode="individual")

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(report)

        # Should NOT create a new comment (dedup skipped it)
        mock_github.create_review_comment.assert_not_called()
        mock_github.create_file_level_comment.assert_not_called()
        # Should NOT update (body unchanged)
        mock_github.update_review_comment.assert_not_called()

    @pytest.mark.asyncio
    async def test_off_diff_updates_existing_changed_comment(self, mock_github, sample_policy_file):
        """Test that off-diff pipeline updates comment when body has changed."""
        from iam_validator.core.finding_fingerprint import FindingFingerprint

        issue = ValidationIssue(
            policy_file=sample_policy_file,
            statement_index=1,
            severity="critical",
            issue_type="wildcard_action",
            message="Action uses dangerous wildcard",
            action="dynamodb:*",
            line_number=14,
        )

        relative_path = Path(sample_policy_file).name
        fp_hash = FindingFingerprint.from_issue(issue, relative_path).to_hash()

        # Mock existing comment with same fingerprint but DIFFERENT body (stale)
        mock_github._get_bot_comments_by_fingerprint.return_value = {
            fp_hash: {
                "id": 42,
                "body": "old stale body content",
                "path": relative_path,
                "line": 14,
            }
        }

        report = ValidationReport(
            results=[
                PolicyValidationResult(
                    policy_file=sample_policy_file,
                    is_valid=False,
                    issues=[issue],
                    policy_type="IDENTITY_POLICY",
                )
            ],
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            total_issues=1,
        )

        mock_github.get_pr_files.return_value = [
            {
                "filename": relative_path,
                "status": "modified",
                "patch": '@@ -4,7 +4,7 @@\n     {\n       "Sid": "AllowS3Read",\n       "Effect": "Allow",\n-      "Action": "s3:GetObject",\n+      "Action": "s3:*",\n       "Resource": "*"\n     },\n     {',
            }
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False, off_diff_comment_mode="individual")

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(report)

        # Should NOT create a new comment
        mock_github.create_review_comment.assert_not_called()
        mock_github.create_file_level_comment.assert_not_called()
        # Should UPDATE existing comment with new body
        mock_github.update_review_comment.assert_called_once()
        call_args = mock_github.update_review_comment.call_args
        assert call_args[0][0] == 42  # comment ID


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


class TestOffDiffCommentMode:
    """Tests for the off_diff_comment_mode setting."""

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
    def mock_github(self):
        """Create a mock GitHub integration."""
        github = MagicMock(spec=GitHubIntegration)
        github.is_configured = MagicMock(return_value=True)
        github.get_pr_files = AsyncMock(return_value=[])
        github.update_or_create_review_comments = AsyncMock(return_value=True)
        github.post_multipart_comments = AsyncMock(return_value=True)
        github.create_review_comment = AsyncMock(return_value=False)
        github.create_file_level_comment = AsyncMock(return_value=False)
        github.get_pr_info = AsyncMock(return_value={"head": {"sha": "abc123"}})
        github.get_existing_review_comments = AsyncMock(return_value=[])
        github.update_review_comment = AsyncMock(return_value=True)
        return github

    @pytest.fixture
    def report_with_off_diff_issues(self, sample_policy_file):
        """Report with issues on lines that won't match the diff (off-diff)."""
        return ValidationReport(
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            total_issues=2,
            results=[
                PolicyValidationResult(
                    policy_file=sample_policy_file,
                    is_valid=False,
                    issues=[
                        # Issue on line 8 (Resource in statement 0, modified statement but unchanged line)
                        ValidationIssue(
                            severity="medium",
                            issue_type="wildcard_resource",
                            message="Wildcard resource",
                            statement_index=0,
                            line_number=8,
                        ),
                        # Issue on line 14 (unchanged statement 1)
                        ValidationIssue(
                            severity="high",
                            issue_type="service_wildcard",
                            message="Service wildcard",
                            statement_index=1,
                            line_number=14,
                        ),
                    ],
                    policy_type="IDENTITY_POLICY",
                )
            ],
        )

    @pytest.fixture
    def diff_patch(self):
        """Diff patch that only changes line 7 in statement 0."""
        return (
            "@@ -4,7 +4,7 @@\n"
            "     {\n"
            '       "Sid": "AllowS3Read",\n'
            '       "Effect": "Allow",\n'
            '-      "Action": "s3:GetObject",\n'
            '+      "Action": "s3:*",\n'
            '       "Resource": "*"\n'
            "     },\n"
            "     {"
        )

    @pytest.mark.asyncio
    async def test_summary_only_skips_off_diff_posting(
        self, mock_github, sample_policy_file, report_with_off_diff_issues, diff_patch
    ):
        """summary_only mode should not call _post_off_diff_comments."""
        mock_github.get_pr_files.return_value = [
            {"filename": Path(sample_policy_file).name, "status": "modified", "patch": diff_patch}
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False, off_diff_comment_mode="summary_only")

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            with mock.patch.object(commenter, "_post_off_diff_comments", new_callable=AsyncMock) as mock_post:
                await commenter._post_review_comments(report_with_off_diff_issues)
                mock_post.assert_not_called()

        # Context issues should remain for summary (both off-diff issues)
        assert len(commenter._context_issues) >= 1

    @pytest.mark.asyncio
    async def test_individual_posts_all_off_diff(
        self, mock_github, sample_policy_file, report_with_off_diff_issues, diff_patch
    ):
        """individual mode should pass all context issues to _post_off_diff_comments."""
        mock_github.get_pr_files.return_value = [
            {"filename": Path(sample_policy_file).name, "status": "modified", "patch": diff_patch}
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False, off_diff_comment_mode="individual")

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            with mock.patch.object(
                commenter, "_post_off_diff_comments", new_callable=AsyncMock, return_value=(set(), [])
            ) as mock_post:
                await commenter._post_review_comments(report_with_off_diff_issues)
                mock_post.assert_called_once()
                # Should pass all context issues (both modified-statement and unchanged-statement)
                assert len(mock_post.call_args[0][0]) >= 1

    @pytest.mark.asyncio
    async def test_modified_statements_only_splits_correctly(
        self, mock_github, sample_policy_file, report_with_off_diff_issues, diff_patch
    ):
        """modified_statements_only should only post issues from modified statements."""
        mock_github.get_pr_files.return_value = [
            {"filename": Path(sample_policy_file).name, "status": "modified", "patch": diff_patch}
        ]

        commenter = PRCommenter(
            github=mock_github, cleanup_old_comments=False, off_diff_comment_mode="modified_statements_only"
        )

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            with mock.patch.object(
                commenter, "_post_off_diff_comments", new_callable=AsyncMock, return_value=(set(), [])
            ) as mock_post:
                await commenter._post_review_comments(report_with_off_diff_issues)
                mock_post.assert_called_once()
                # Should only pass modified-statement issues (in_modified_statement=True)
                posted_issues = mock_post.call_args[0][0]
                assert all(ci.in_modified_statement for ci in posted_issues)

        # Unchanged-statement issues should remain in _context_issues for summary
        assert any(not ci.in_modified_statement for ci in commenter._context_issues)

    @pytest.mark.asyncio
    async def test_in_modified_statement_flag_set_correctly(
        self, mock_github, sample_policy_file, report_with_off_diff_issues, diff_patch
    ):
        """Verify in_modified_statement flag is set correctly on ContextIssue during diff filtering."""
        mock_github.get_pr_files.return_value = [
            {"filename": Path(sample_policy_file).name, "status": "modified", "patch": diff_patch}
        ]

        commenter = PRCommenter(github=mock_github, cleanup_old_comments=False, off_diff_comment_mode="summary_only")

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": Path(sample_policy_file).parent.as_posix()}):
            await commenter._post_review_comments(report_with_off_diff_issues)

        # Should have context issues with both in_modified_statement=True and False
        modified = [ci for ci in commenter._context_issues if ci.in_modified_statement]
        unchanged = [ci for ci in commenter._context_issues if not ci.in_modified_statement]
        # Statement 0 was modified (line 7 changed), so its off-diff issue (line 8) is in_modified_statement=True
        assert len(modified) >= 1
        # Statement 1 was NOT modified, so its issue (line 14) is in_modified_statement=False
        assert len(unchanged) >= 1

    def test_default_mode_is_summary_only(self, mock_github):
        """PRCommenter should default to summary_only mode."""
        commenter = PRCommenter(github=mock_github)
        assert commenter.off_diff_comment_mode == "summary_only"


class TestOffDiffCommentModeConfigValidation:
    """Tests for off_diff_comment_mode config validation."""

    def test_valid_modes_accepted(self):
        """All valid modes should be accepted by schema validation."""
        from iam_validator.core.config.config_loader import SettingsSchema

        for mode in ["summary_only", "individual", "modified_statements_only"]:
            schema = SettingsSchema(off_diff_comment_mode=mode)
            assert schema.off_diff_comment_mode == mode

    def test_invalid_mode_rejected(self):
        """Invalid modes should raise ValidationError."""
        from pydantic import ValidationError

        from iam_validator.core.config.config_loader import SettingsSchema

        with pytest.raises(ValidationError, match="Invalid off_diff_comment_mode"):
            SettingsSchema(off_diff_comment_mode="invalid_mode")

    def test_default_is_summary_only(self):
        """Default mode in schema should be summary_only."""
        from iam_validator.core.config.config_loader import SettingsSchema

        schema = SettingsSchema()
        assert schema.off_diff_comment_mode == "summary_only"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""End-to-end tests for the "everything was fixed" run.

When a PR's findings are all resolved, the next run must leave the PR clean:
severity labels removed, inline comments cleaned up, the summary reporting a
pass, and no leftover "Ignored Findings" table for issues that are gone.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.constants import IGNORED_FINDINGS_IDENTIFIER
from iam_validator.core.models import PolicyValidationResult, ValidationIssue
from iam_validator.core.pr_commenter import PRCommenter
from iam_validator.core.report import ReportGenerator

SEVERITY_LABELS = {"critical": "security-critical", "high": "security-high"}


def ignore_storage_comment(*findings: dict) -> dict:
    payload = json.dumps({"version": 1, "ignored_findings": list(findings)})
    return {
        "id": 999,
        "body": f"{IGNORED_FINDINGS_IDENTIFIER}\n\n```json\n{payload}\n```\n",
    }


def ignore_record(finding_id: str, file_path: str, issue_type: str) -> dict:
    return {
        "finding_id": finding_id,
        "file_path": file_path,
        "check_id": issue_type,
        "issue_type": issue_type,
        "ignored_by": "owner",
        "ignored_at": "2024-01-15T10:30:00Z",
        "reason": "approved by security",
    }


@pytest.fixture
def mock_github():
    """A PR carrying a severity label and a stale inline comment from run 1."""
    github = MagicMock()
    github.is_configured = MagicMock(return_value=True)
    github.get_labels = AsyncMock(return_value=["security-critical", "unrelated"])
    github.add_labels = AsyncMock(return_value=True)
    github.remove_label = AsyncMock(return_value=True)
    github.get_pr_files = AsyncMock(return_value=[{"filename": "policy.json", "patch": "@@ -1 +1,2 @@\n+ x\n"}])
    github.get_pr_info = AsyncMock(return_value={"head": {"sha": "sha1"}})
    github.get_issue_comments = AsyncMock(return_value=[])
    github.get_review_comments = AsyncMock(return_value=[])
    github.post_comment = AsyncMock(return_value=True)
    github._update_comment = AsyncMock(return_value=True)
    github.post_multipart_comments = AsyncMock(return_value=True)
    github.update_or_create_review_comments = AsyncMock(return_value=True)
    github.scan_for_ignore_commands = AsyncMock(return_value=[])
    return github


def clean_report():
    return ReportGenerator().generate_report(
        [PolicyValidationResult(policy_file="policy.json", is_valid=True, issues=[])]
    )


def summary_body(mock_github: MagicMock) -> str:
    mock_github.post_multipart_comments.assert_awaited_once()
    parts = mock_github.post_multipart_comments.await_args.args[0]
    assert len(parts) == 1
    return parts[0]


@pytest.mark.asyncio
async def test_resolved_run_removes_labels_and_cleans_comments(mock_github):
    commenter = PRCommenter(
        mock_github,
        cleanup_old_comments=True,
        severity_labels=SEVERITY_LABELS,
        enable_codeowners_ignore=False,
    )

    assert await commenter.post_findings_to_pr(clean_report()) is True

    mock_github.remove_label.assert_awaited_once_with("security-critical")
    mock_github.add_labels.assert_not_awaited()
    # Cleanup must still run so run-1 inline comments are deleted.
    kwargs = mock_github.update_or_create_review_comments.await_args.kwargs
    assert kwargs["comments"] == []
    assert kwargs["skip_cleanup"] is False
    assert kwargs["validated_files"] == {"policy.json"}
    assert "IAM Policy Validation Passed" in summary_body(mock_github)


@pytest.mark.asyncio
async def test_resolved_run_clears_stale_ignored_findings(mock_github):
    """The regression: ignore records outlived the findings they silenced."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=[ignore_storage_comment(ignore_record("deadbeefdeadbeef", "policy.json", "full_wildcard"))]
    )
    commenter = PRCommenter(
        mock_github,
        cleanup_old_comments=True,
        severity_labels=SEVERITY_LABELS,
        enable_codeowners_ignore=True,
    )

    assert await commenter.post_findings_to_pr(clean_report()) is True

    # Storage comment rewritten without the resolved record.
    mock_github._update_comment.assert_awaited_once()
    saved_body = mock_github._update_comment.await_args.args[1]
    assert "deadbeefdeadbeef" not in saved_body

    body = summary_body(mock_github)
    assert "Ignored Findings" not in body
    assert "full_wildcard" not in body
    assert "IAM Policy Validation Passed" in body


@pytest.mark.asyncio
async def test_still_reported_ignored_finding_survives(mock_github):
    """An ignored finding that is still present keeps its record and display."""
    issue = ValidationIssue(
        severity="critical",
        statement_index=0,
        issue_type="full_wildcard",
        message="Full wildcard",
        check_id="full_wildcard",
    )
    result = PolicyValidationResult(policy_file="policy.json", is_valid=False, issues=[issue])
    report = ReportGenerator().generate_report([result])

    from iam_validator.core.finding_fingerprint import FindingFingerprint

    finding_id = FindingFingerprint.from_issue(issue, "policy.json").to_hash()
    mock_github.get_issue_comments = AsyncMock(
        return_value=[ignore_storage_comment(ignore_record(finding_id, "policy.json", "full_wildcard"))]
    )

    commenter = PRCommenter(
        mock_github,
        cleanup_old_comments=True,
        severity_labels=SEVERITY_LABELS,
        enable_codeowners_ignore=True,
    )

    assert await commenter.post_findings_to_pr(report) is True

    mock_github._update_comment.assert_not_awaited()
    assert "Ignored Findings" in summary_body(mock_github)


@pytest.mark.asyncio
async def test_partial_run_keeps_ignores_for_unvalidated_files(mock_github):
    """A run over one file must not drop ignores belonging to another."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=[
            ignore_storage_comment(
                ignore_record("aaaaaaaaaaaaaaaa", "policy.json", "full_wildcard"),
                ignore_record("bbbbbbbbbbbbbbbb", "other.json", "sensitive_action"),
            )
        ]
    )
    commenter = PRCommenter(
        mock_github,
        cleanup_old_comments=True,
        enable_codeowners_ignore=True,
    )

    assert await commenter.post_findings_to_pr(clean_report()) is True

    saved_body = mock_github._update_comment.await_args.args[1]
    assert "aaaaaaaaaaaaaaaa" not in saved_body
    assert "bbbbbbbbbbbbbbbb" in saved_body

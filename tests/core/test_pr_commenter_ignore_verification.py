"""End-to-end: a forged or revoked ignore stops silencing its finding.

The store is a PR comment anyone with write access can edit. Verification is
what makes the stored `ignored_by` mean something, so these tests assert the
consequence that matters — the finding counts against the PR again — rather
than just that a record was deleted.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.constants import IGNORED_FINDINGS_IDENTIFIER
from iam_validator.core.finding_fingerprint import FindingFingerprint
from iam_validator.core.models import PolicyValidationResult, ValidationIssue
from iam_validator.core.pr_commenter import PRCommenter
from iam_validator.core.report import ReportGenerator

OWNER = "code-owner"
REPLY_ID = 555
POLICY = "policy.json"


@pytest.fixture
def issue():
    return ValidationIssue(
        severity="critical",
        statement_index=0,
        issue_type="full_wildcard",
        message="Full wildcard",
        check_id="full_wildcard",
    )


@pytest.fixture
def report(issue):
    return ReportGenerator().generate_report(
        [PolicyValidationResult(policy_file=POLICY, is_valid=False, issues=[issue])]
    )


@pytest.fixture
def finding_id(issue):
    return FindingFingerprint.from_issue(issue, POLICY).to_hash()


def storage_comment(finding_id: str, *, ignored_by: str, reply_comment_id: int | None) -> dict:
    payload = json.dumps(
        {
            "version": 1,
            "ignored_findings": [
                {
                    "finding_id": finding_id,
                    "file_path": POLICY,
                    "check_id": "full_wildcard",
                    "issue_type": "full_wildcard",
                    "ignored_by": ignored_by,
                    "ignored_at": "2024-01-15T10:30:00Z",
                    "reason": "approved",
                    "reply_comment_id": reply_comment_id,
                }
            ],
        }
    )
    return {"id": 999, "body": f"{IGNORED_FINDINGS_IDENTIFIER}\n\n```json\n{payload}\n```\n"}


@pytest.fixture
def mock_github():
    github = MagicMock()
    github.is_configured = MagicMock(return_value=True)
    github.get_labels = AsyncMock(return_value=[])
    github.add_labels = AsyncMock(return_value=True)
    github.remove_label = AsyncMock(return_value=True)
    github.get_pr_files = AsyncMock(return_value=[{"filename": POLICY, "patch": "@@ -1 +1,2 @@\n+ x\n"}])
    github.get_pr_info = AsyncMock(return_value={"head": {"sha": "sha1"}})
    github.get_review_comments = AsyncMock(return_value=[])
    github.post_comment = AsyncMock(return_value=True)
    github._update_comment = AsyncMock(return_value=True)
    github.post_multipart_comments = AsyncMock(return_value=True)
    github.update_or_create_review_comments = AsyncMock(return_value=True)
    github.scan_for_ignore_commands = AsyncMock(return_value=[])
    return github


def commenter_for(github):
    return PRCommenter(
        github,
        cleanup_old_comments=True,
        fail_on_severities=["error", "critical"],
        enable_codeowners_ignore=True,
    )


@pytest.mark.asyncio
async def test_forged_ignore_no_longer_silences_the_finding(mock_github, issue, report, finding_id):
    """A hand-edited ignored_by must not suppress anything."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=[storage_comment(finding_id, ignored_by="attacker", reply_comment_id=REPLY_ID)]
    )
    # The reply exists, but it belongs to the code owner, not "attacker".
    mock_github.get_review_comment_authors = AsyncMock(return_value={REPLY_ID: OWNER})

    commenter = commenter_for(mock_github)
    assert await commenter.post_findings_to_pr(report) is True

    assert commenter._ignored_finding_ids == frozenset()
    assert not commenter._is_issue_ignored(issue, POLICY)
    # The critical finding blocks the PR again.
    assert commenter._are_all_blocking_issues_ignored(report) is False
    # The forged record is gone from storage.
    assert finding_id not in mock_github._update_comment.await_args.args[1]


@pytest.mark.asyncio
async def test_deleted_reply_revokes_the_ignore(mock_github, issue, report, finding_id):
    """Deleting the "ignore" reply revokes the ignore."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=[storage_comment(finding_id, ignored_by=OWNER, reply_comment_id=REPLY_ID)]
    )
    mock_github.get_review_comment_authors = AsyncMock(return_value={})

    commenter = commenter_for(mock_github)
    assert await commenter.post_findings_to_pr(report) is True

    assert commenter._ignored_finding_ids == frozenset()
    assert commenter._are_all_blocking_issues_ignored(report) is False


@pytest.mark.asyncio
async def test_genuine_ignore_keeps_suppressing(mock_github, issue, report, finding_id):
    """The whole point: a real ignore must survive verification."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=[storage_comment(finding_id, ignored_by=OWNER, reply_comment_id=REPLY_ID)]
    )
    mock_github.get_review_comment_authors = AsyncMock(return_value={REPLY_ID: OWNER})

    commenter = commenter_for(mock_github)
    assert await commenter.post_findings_to_pr(report) is True

    assert finding_id in commenter._ignored_finding_ids
    assert commenter._is_issue_ignored(issue, POLICY)
    assert commenter._are_all_blocking_issues_ignored(report) is True
    mock_github._update_comment.assert_not_awaited()
    assert "Ignored Findings" in mock_github.post_multipart_comments.await_args.args[0][0]


@pytest.mark.asyncio
async def test_case_differing_author_keeps_suppressing(mock_github, report, finding_id):
    """GitHub logins are case-insensitive; a case difference is not tampering."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=[storage_comment(finding_id, ignored_by="Code-Owner", reply_comment_id=REPLY_ID)]
    )
    mock_github.get_review_comment_authors = AsyncMock(return_value={REPLY_ID: "code-owner"})

    commenter = commenter_for(mock_github)
    assert await commenter.post_findings_to_pr(report) is True

    assert finding_id in commenter._ignored_finding_ids
    mock_github._update_comment.assert_not_awaited()


@pytest.mark.asyncio
async def test_unavailable_listing_keeps_suppressing(mock_github, report, finding_id):
    """A transient API failure must not revoke a valid ignore."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=[storage_comment(finding_id, ignored_by=OWNER, reply_comment_id=REPLY_ID)]
    )
    mock_github.get_review_comment_authors = AsyncMock(return_value=None)

    commenter = commenter_for(mock_github)
    assert await commenter.post_findings_to_pr(report) is True

    assert finding_id in commenter._ignored_finding_ids
    assert commenter._are_all_blocking_issues_ignored(report) is True
    mock_github._update_comment.assert_not_awaited()


@pytest.mark.asyncio
async def test_legacy_record_without_reply_id_keeps_suppressing(mock_github, report, finding_id):
    """Records predating reply tracking cannot be verified, so they stand."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=[storage_comment(finding_id, ignored_by=OWNER, reply_comment_id=None)]
    )
    mock_github.get_review_comment_authors = AsyncMock(return_value={})

    commenter = commenter_for(mock_github)
    assert await commenter.post_findings_to_pr(report) is True

    assert finding_id in commenter._ignored_finding_ids
    mock_github._update_comment.assert_not_awaited()

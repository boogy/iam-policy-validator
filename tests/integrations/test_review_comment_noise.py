"""Tests that pin the noise-minimization invariants of inline review comments.

`update_or_create_review_comments` is the inline-comment counterpart of the
summary-comment lifecycle. It must follow the same principles:

  1. UPDATE existing comments in place wherever possible (preserve comment id).
  2. SKIP the API call entirely when the body hasn't changed (zero noise).
  3. CREATE only for genuinely new findings.
  4. DELETE only when a finding is no longer present AND the file is in scope.

These invariants are already implemented in github_integration.py — these
tests pin them so they cannot regress silently.
"""

from unittest.mock import AsyncMock, patch

import pytest

from iam_validator.core.constants import (
    BOT_IDENTIFIER,
    FINDING_ID_MARKER_FORMAT,
    ISSUE_TYPE_MARKER_FORMAT,
    REVIEW_IDENTIFIER,
)
from iam_validator.integrations.github_integration import GitHubIntegration, ReviewEvent


def _body(finding_id: str, issue_type: str, message: str) -> str:
    """Build a review-comment body matching what production constructs in models.py."""
    return (
        f"{REVIEW_IDENTIFIER}\n"
        f"{BOT_IDENTIFIER}\n"
        f"{ISSUE_TYPE_MARKER_FORMAT.format(issue_type=issue_type)}\n"
        f"{FINDING_ID_MARKER_FORMAT.format(finding_id=finding_id)}\n"
        f"{message}"
    )


@pytest.fixture
def gh():
    with patch.dict(
        "os.environ",
        {
            "GITHUB_TOKEN": "test-token",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_PR_NUMBER": "123",
        },
    ):
        return GitHubIntegration()


def _wire_mocks(
    gh: GitHubIntegration,
    *,
    existing: list[dict],
    pr_files: list[str] | None = None,
):
    """Wire the standard mock surface for update_or_create_review_comments."""
    gh.get_review_comments = AsyncMock(return_value=existing)
    gh.update_review_comment = AsyncMock(return_value=True)
    gh.delete_review_comment = AsyncMock(return_value=True)
    gh.create_review_with_comments = AsyncMock(return_value=True)
    gh.get_pr_files = AsyncMock(return_value=[{"filename": f} for f in (pr_files or [])])


class TestUnchangedBodyIsNoop:
    """Invariant 2: identical body must NOT trigger a PATCH (zero noise)."""

    @pytest.mark.asyncio
    async def test_identical_body_skips_update(self, gh):
        body = _body("aaaa111122223333", "invalid_action", "Error: Invalid action")
        existing = [{"id": 100, "path": "policy.json", "line": 5, "body": body}]
        new_comments = [{"path": "policy.json", "line": 5, "body": body}]

        _wire_mocks(gh, existing=existing, pr_files=["policy.json"])

        ok = await gh.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier=REVIEW_IDENTIFIER,
            validated_files={"policy.json"},
        )

        assert ok is True
        # No PATCH, no POST, no DELETE — pure no-op scan.
        gh.update_review_comment.assert_not_called()
        gh.create_review_with_comments.assert_not_called()
        gh.delete_review_comment.assert_not_called()

    @pytest.mark.asyncio
    async def test_changed_body_triggers_single_update(self, gh):
        existing_body = _body("aaaa111122223333", "invalid_action", "Error: old wording")
        new_body = _body("aaaa111122223333", "invalid_action", "Error: new wording")
        existing = [{"id": 100, "path": "policy.json", "line": 5, "body": existing_body}]
        new_comments = [{"path": "policy.json", "line": 5, "body": new_body}]

        _wire_mocks(gh, existing=existing, pr_files=["policy.json"])

        ok = await gh.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier=REVIEW_IDENTIFIER,
            validated_files={"policy.json"},
        )

        assert ok is True
        gh.update_review_comment.assert_called_once_with(100, new_body)
        gh.create_review_with_comments.assert_not_called()
        gh.delete_review_comment.assert_not_called()


class TestLineShiftPreservesCommentId:
    """Invariant 1: same finding at new line → UPDATE (id preserved), NOT delete+create."""

    @pytest.mark.asyncio
    async def test_finding_moved_to_different_line_updates_in_place(self, gh):
        finding_id = "aaaa111122223333"
        old_body = _body(finding_id, "invalid_action", "Error: Invalid action")
        new_body = _body(finding_id, "invalid_action", "Error: Invalid action (still here, shifted)")

        # Existing at line 5, finding now at line 12 — same fingerprint.
        existing = [{"id": 100, "path": "policy.json", "line": 5, "body": old_body}]
        new_comments = [{"path": "policy.json", "line": 12, "body": new_body}]

        _wire_mocks(gh, existing=existing, pr_files=["policy.json"])

        ok = await gh.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier=REVIEW_IDENTIFIER,
            validated_files={"policy.json"},
        )

        assert ok is True
        # UPDATE in place — comment id 100 stays.
        gh.update_review_comment.assert_called_once_with(100, new_body)
        # Critical: no DELETE + CREATE churn for a moved finding.
        gh.delete_review_comment.assert_not_called()
        gh.create_review_with_comments.assert_not_called()


class TestNonPrFilesPreserved:
    """Invariant 4: comments on files NOT in the PR must never be deleted.

    Prevents accidentally deleting bot comments that belong to other branches
    or PRs running against the same repo.
    """

    @pytest.mark.asyncio
    async def test_comment_on_file_outside_pr_is_kept(self, gh):
        # Existing comment lives on a file NOT in the current PR.
        existing = [
            {
                "id": 100,
                "path": "other_branch_policy.json",
                "line": 5,
                "body": _body("aaaa111122223333", "invalid_action", "Error from another branch"),
            }
        ]
        new_comments: list[dict] = []  # current scan has no findings

        # PR contains a different file — `other_branch_policy.json` is out of scope.
        _wire_mocks(gh, existing=existing, pr_files=["policy.json"])

        ok = await gh.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier=REVIEW_IDENTIFIER,
            validated_files={"policy.json"},
        )

        assert ok is True
        gh.delete_review_comment.assert_not_called()


class TestSkipCleanupStreamingMode:
    """Invariant 4b: streaming mode must never delete (single-file scope per call)."""

    @pytest.mark.asyncio
    async def test_skip_cleanup_preserves_unmatched_comments(self, gh):
        existing = [
            {
                "id": 100,
                "path": "a.json",
                "line": 5,
                "body": _body("aaaa111122223333", "invalid_action", "Error A"),
            },
            {
                "id": 101,
                "path": "b.json",
                "line": 7,
                "body": _body("bbbb222244445555", "invalid_action", "Error B"),
            },
        ]
        # Streaming run only sees a.json this iteration; b.json must NOT be deleted
        # just because it has no findings in this single call.
        new_comments = [
            {
                "path": "a.json",
                "line": 5,
                "body": _body("aaaa111122223333", "invalid_action", "Error A (updated)"),
            }
        ]

        _wire_mocks(gh, existing=existing, pr_files=["a.json", "b.json"])

        ok = await gh.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier=REVIEW_IDENTIFIER,
            validated_files={"a.json"},
            skip_cleanup=True,
        )

        assert ok is True
        gh.update_review_comment.assert_called_once()  # a.json updated
        gh.delete_review_comment.assert_not_called()  # b.json preserved


class TestProtectedFingerprintsPreserved:
    """Invariant 4c: protected_fingerprints must survive cleanup.

    Off-diff context-comments are managed by a separate pipeline and registered
    via protected_fingerprints. They must not be deleted by the diff-aware
    cleanup pass even when they aren't in the new comment list.
    """

    @pytest.mark.asyncio
    async def test_protected_fingerprint_is_not_deleted(self, gh):
        protected_fp = "eeee5555aaaa6666"
        existing = [
            {
                "id": 200,
                "path": "policy.json",
                "line": 99,  # off-diff line
                "body": _body(protected_fp, "wildcard_action", "Off-diff context note"),
            }
        ]
        new_comments: list[dict] = []  # this pipeline produced nothing

        _wire_mocks(gh, existing=existing, pr_files=["policy.json"])

        ok = await gh.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier=REVIEW_IDENTIFIER,
            validated_files={"policy.json"},
            protected_fingerprints={protected_fp},
        )

        assert ok is True
        gh.delete_review_comment.assert_not_called()

    @pytest.mark.asyncio
    async def test_unprotected_fingerprint_is_deleted(self, gh):
        existing = [
            {
                "id": 200,
                "path": "policy.json",
                "line": 5,
                "body": _body("dddd444488889999", "wildcard_action", "Stale finding"),
            }
        ]
        _wire_mocks(gh, existing=existing, pr_files=["policy.json"])

        ok = await gh.update_or_create_review_comments(
            comments=[],
            body="",
            event=ReviewEvent.COMMENT,
            identifier=REVIEW_IDENTIFIER,
            validated_files={"policy.json"},
            # No protection — must be deleted.
        )

        assert ok is True
        gh.delete_review_comment.assert_called_once_with(200)


class TestMixedBatchExactCounts:
    """Invariant 5: a mixed batch produces the minimum API churn.

    Setup:
      - finding_unchanged: same body as before → 0 PATCH
      - finding_modified:  new body            → 1 PATCH
      - finding_new:       not seen before     → 1 POST (via review)
      - finding_resolved:  no longer reported  → 1 DELETE
    """

    @pytest.mark.asyncio
    async def test_mixed_batch_minimum_api_churn(self, gh):
        unchanged_body = _body("aaaa111122223333", "invalid_action", "Same as before")
        modified_old = _body("bbbb222244445555", "wildcard_action", "Old wording")
        modified_new = _body("bbbb222244445555", "wildcard_action", "New wording")
        resolved_body = _body("cccc333366667777", "missing_condition", "Now resolved")
        new_finding_body = _body("dddd444488889999", "sensitive_action", "Brand new finding")

        existing = [
            {"id": 1, "path": "p.json", "line": 5, "body": unchanged_body},
            {"id": 2, "path": "p.json", "line": 10, "body": modified_old},
            {"id": 3, "path": "p.json", "line": 15, "body": resolved_body},
        ]
        new_comments = [
            {"path": "p.json", "line": 5, "body": unchanged_body},
            {"path": "p.json", "line": 10, "body": modified_new},
            {"path": "p.json", "line": 20, "body": new_finding_body},
        ]

        _wire_mocks(gh, existing=existing, pr_files=["p.json"])

        ok = await gh.update_or_create_review_comments(
            comments=new_comments,
            body="",
            event=ReviewEvent.COMMENT,
            identifier=REVIEW_IDENTIFIER,
            validated_files={"p.json"},
        )

        assert ok is True
        # Exactly one UPDATE — for the modified finding only.
        gh.update_review_comment.assert_called_once_with(2, modified_new)
        # Exactly one CREATE batch — containing the brand-new finding only.
        gh.create_review_with_comments.assert_called_once()
        created = gh.create_review_with_comments.call_args.args[0]
        assert len(created) == 1
        assert created[0]["body"] == new_finding_body
        # Exactly one DELETE — for the resolved finding only.
        gh.delete_review_comment.assert_called_once_with(3)

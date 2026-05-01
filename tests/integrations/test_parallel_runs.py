"""Tests for parallel-run support via ``comment_tag`` (issue #103).

When the validator runs more than once on the same PR (e.g. one run for
identity policies and another for trust policies, in parallel), each run
must address its own canonical comment instead of overwriting the other.
The fix is a scoped HTML marker; this file pins the contract.

Scope:

- ``_sync_comments_with_identifier`` only matches comments whose body
  contains the *exact* scoped identifier — comments tagged ``policy``
  must not match a lookup for ``role``.
- ``update_or_create_review_comments`` honours the same scoping for
  inline review comments.
- ``IgnoredFindingsStore`` with distinct ``comment_tag`` values reads
  and writes distinct hidden storage comments.
- A ``PRCommenter`` constructed without a tag is byte-identical to
  pre-tag behaviour (regression guard for the un-tagged path).
"""

from unittest.mock import AsyncMock, patch

import pytest

from iam_validator.core.constants import (
    IGNORED_FINDINGS_IDENTIFIER,
    REVIEW_IDENTIFIER,
    SUMMARY_IDENTIFIER,
    scoped_marker,
)
from iam_validator.core.ignored_findings import IgnoredFinding, IgnoredFindingsStore
from iam_validator.core.pr_commenter import PRCommenter
from iam_validator.integrations.github_integration import GitHubIntegration


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


# ---------------------------------------------------------------------------
# PRCommenter — identifier resolution
# ---------------------------------------------------------------------------


class TestPRCommenterIdentifierResolution:
    @pytest.mark.parametrize("tag", [None, ""])
    def test_no_or_empty_tag_keeps_legacy_markers(self, tag):
        # Empty string must behave exactly like ``None`` so users wiring
        # the GitHub Action input through to the CLI without checking
        # emptiness don't accidentally scope every run with an empty tag.
        commenter = PRCommenter(comment_tag=tag)
        assert commenter.SUMMARY_IDENTIFIER == SUMMARY_IDENTIFIER
        assert commenter.REVIEW_IDENTIFIER == REVIEW_IDENTIFIER

    def test_tag_scopes_both_identifiers(self):
        commenter = PRCommenter(comment_tag="role")
        assert commenter.SUMMARY_IDENTIFIER == scoped_marker(SUMMARY_IDENTIFIER, "role")
        assert commenter.REVIEW_IDENTIFIER == scoped_marker(REVIEW_IDENTIFIER, "role")
        assert commenter.SUMMARY_IDENTIFIER != SUMMARY_IDENTIFIER
        assert commenter.REVIEW_IDENTIFIER != REVIEW_IDENTIFIER

    def test_invalid_tag_raises(self):
        with pytest.raises(ValueError, match="Invalid comment tag"):
            PRCommenter(comment_tag="has space")


# ---------------------------------------------------------------------------
# Summary comment lifecycle — scoped identifiers must not collide
# ---------------------------------------------------------------------------


class TestSummaryParallelRuns:
    """Two runs with different tags must NOT see each other's comments.

    Substring-level isolation (``identifier in body`` lookups) is pinned
    by ``test_constants_scoped_marker.test_scoped_does_not_match_unscoped_substring``
    and existing ``test_summary_comment_staleness`` tests; this class
    exercises the end-to-end ``post_multipart_comments`` flow.
    """

    @pytest.mark.asyncio
    async def test_role_run_does_not_overwrite_policy_summary(self, gh):
        """Bug from issue #103 reproduced and fixed.

        Pre-fix: two runs share ``SUMMARY_IDENTIFIER``; the second run's
        ``post_multipart_comments`` matches the first's comment and PATCHes
        it. Post-fix: scoped markers split the lookups so each run only
        touches its own comment id.
        """
        policy_marker = scoped_marker(SUMMARY_IDENTIFIER, "policy")
        role_marker = scoped_marker(SUMMARY_IDENTIFIER, "role")

        # Existing: policy run's summary lives on the PR.
        existing = [
            {"id": 100, "body": policy_marker + "\npolicy summary", "created_at": "2026-04-01T10:00:00Z"},
        ]
        with (
            patch.object(gh, "_make_paginated_request", AsyncMock(return_value=existing)),
            patch.object(gh, "post_comment", AsyncMock(return_value=True)) as mock_post,
            patch.object(gh, "_update_comment", AsyncMock(return_value=True)) as mock_update,
            patch.object(gh, "_make_request", AsyncMock(return_value={})) as mock_req,
        ):
            # Role run posts under its own marker.
            ok = await gh.post_multipart_comments(["role summary updated"], role_marker)

        assert ok is True
        # Critical: the role run must NOT have updated the policy run's id=100.
        mock_update.assert_not_awaited()
        # It must have POSTed a brand-new comment under the role marker.
        mock_post.assert_awaited_once()
        new_body = mock_post.await_args.args[0]
        assert role_marker in new_body
        assert "role summary updated" in new_body
        # And it must NOT have deleted the policy run's comment as an "orphan".
        delete_calls = [c for c in mock_req.await_args_list if c.args and c.args[0] == "DELETE"]
        assert delete_calls == []

    @pytest.mark.asyncio
    async def test_rerun_same_tag_updates_in_place(self, gh):
        """Within the same scope, the existing in-place update behaviour
        must keep working — that's the property we don't want to lose by
        introducing scoping."""
        policy_marker = scoped_marker(SUMMARY_IDENTIFIER, "policy")
        existing = [
            {"id": 100, "body": policy_marker + "\nold body", "created_at": "2026-04-01T10:00:00Z"},
        ]
        with (
            patch.object(gh, "_make_paginated_request", AsyncMock(return_value=existing)),
            patch.object(gh, "post_comment", AsyncMock(return_value=True)) as mock_post,
            patch.object(gh, "_update_comment", AsyncMock(return_value=True)) as mock_update,
            patch.object(gh, "_make_request", AsyncMock(return_value={})),
        ):
            ok = await gh.post_multipart_comments(["new body"], policy_marker)

        assert ok is True
        mock_update.assert_awaited_once()
        assert mock_update.await_args.args[0] == 100
        mock_post.assert_not_awaited()


# ---------------------------------------------------------------------------
# Inline review comments — fingerprint lookups are scoped
# ---------------------------------------------------------------------------


class TestReviewParallelRuns:
    @pytest.mark.asyncio
    async def test_fingerprint_index_filtered_by_scoped_marker(self, gh):
        """``_get_bot_comments_by_fingerprint`` must only return rows whose
        body contains the exact scoped identifier. Rows tagged for another
        run leak across runs without this filter and trigger spurious
        ``update_review_comment`` calls."""
        policy_marker = scoped_marker(REVIEW_IDENTIFIER, "policy")
        role_marker = scoped_marker(REVIEW_IDENTIFIER, "role")
        finding_id = "a" * 16  # canonical 16-char hex hash

        comments = [
            {
                "id": 1,
                "body": f"{policy_marker}\n<!-- finding-id: {finding_id} -->\npolicy",
                "path": "policy.json",
                "line": 5,
            },
            {
                "id": 2,
                "body": f"{role_marker}\n<!-- finding-id: {finding_id} -->\nrole",
                "path": "trust.json",
                "line": 3,
            },
        ]
        with patch.object(gh, "get_review_comments", AsyncMock(return_value=comments)):
            policy_idx = await gh._get_bot_comments_by_fingerprint(policy_marker)
            role_idx = await gh._get_bot_comments_by_fingerprint(role_marker)

        # Same fingerprint hash, but different scoped runs index different
        # comment ids — the role run will not "claim" the policy run's row.
        assert policy_idx[finding_id]["id"] == 1
        assert role_idx[finding_id]["id"] == 2


# ---------------------------------------------------------------------------
# End-to-end producer/consumer contract — bodies POSTed to GitHub must
# carry the scoped REVIEW_IDENTIFIER so subsequent runs can find them.
# ---------------------------------------------------------------------------


class TestReviewBodyEndToEnd:
    """Regression guard for issue #103.

    Pre-fix, ``ValidationIssue.to_pr_comment`` hard-coded the un-scoped
    ``REVIEW_IDENTIFIER`` into every inline review comment body. A
    ``PRCommenter(comment_tag="role")`` therefore POSTed bodies with the
    un-scoped marker, while looking up existing comments by the scoped
    marker. The lookup missed every time, so each rerun POSTed a fresh
    duplicate of every comment.

    The fix: ``to_pr_comment`` accepts ``review_identifier`` and the
    three call sites in ``PRCommenter`` thread ``self.REVIEW_IDENTIFIER``
    through. This test exercises the producer end-to-end via the real
    ``_post_off_diff_comments`` path (no synthetic body fabrication).
    """

    @pytest.mark.asyncio
    async def test_off_diff_body_carries_scoped_review_identifier(self):
        from iam_validator.core.models import ValidationIssue
        from iam_validator.core.pr_commenter import ContextIssue

        scoped = scoped_marker(REVIEW_IDENTIFIER, "role")
        github = AsyncMock()
        github.get_pr_info = AsyncMock(return_value={"head": {"sha": "deadbeef"}})
        github._get_bot_comments_by_fingerprint = AsyncMock(return_value={})
        github.create_review_comment = AsyncMock(return_value=True)
        github.create_file_level_comment = AsyncMock(return_value=False)

        commenter = PRCommenter(github=github, comment_tag="role")
        issue = ValidationIssue(
            policy_file="role.json",
            statement_index=0,
            severity="warning",
            issue_type="overly_broad_action",
            message="Action should be more specific",
            action="s3:*",
            line_number=7,
            check_id="wildcard_action",
        )
        ctx = ContextIssue("role.json", 0, 7, issue)

        await commenter._post_off_diff_comments([ctx])

        github.create_review_comment.assert_awaited_once()
        # Signature: create_review_comment(commit_id, file_path, line, body)
        body = github.create_review_comment.await_args.args[3]
        # Producer/consumer contract: the body MUST carry the scoped marker
        # so the next run's `_get_bot_comments_by_fingerprint(scoped)`
        # lookup actually finds it.
        assert scoped in body, (
            f"Body did not include scoped marker {scoped!r}. "
            "This is the issue #103 regression — the inline comment body "
            "must carry the same identifier the lookup will search for. "
            f"Body was:\n{body[:200]}..."
        )

    @pytest.mark.asyncio
    async def test_no_tag_body_uses_legacy_marker(self):
        """Backward-compat regression: untagged commenter must still emit
        the un-scoped REVIEW_IDENTIFIER — no accidental scoping."""
        from iam_validator.core.models import ValidationIssue
        from iam_validator.core.pr_commenter import ContextIssue

        github = AsyncMock()
        github.get_pr_info = AsyncMock(return_value={"head": {"sha": "deadbeef"}})
        github._get_bot_comments_by_fingerprint = AsyncMock(return_value={})
        github.create_review_comment = AsyncMock(return_value=True)
        github.create_file_level_comment = AsyncMock(return_value=False)

        commenter = PRCommenter(github=github)  # no tag
        issue = ValidationIssue(
            policy_file="p.json",
            statement_index=0,
            severity="warning",
            issue_type="x",
            message="m",
            check_id="c",
        )
        ctx = ContextIssue("p.json", 0, 5, issue)

        await commenter._post_off_diff_comments([ctx])

        body = github.create_review_comment.await_args.args[3]
        assert REVIEW_IDENTIFIER in body
        # And no accidental ":-->" or partial scope tail.
        assert ":-->" not in body

    @pytest.mark.asyncio
    async def test_in_diff_inline_body_carries_scoped_review_identifier(self, tmp_path):
        """E2E for the IN-DIFF inline path (``pr_commenter.py:412`` for
        statement-level findings). Removing ``review_identifier=...`` from
        that call site would let a tagged run POST inline comments under
        the un-scoped marker, and the lookup ``identifier in body`` in
        ``_get_bot_comments_by_fingerprint`` would never match → duplicates
        on every rerun. ``test_off_diff_body_carries_...`` only covers the
        off-diff path; this test covers the most common on-diff path.
        """
        import os
        from unittest import mock as umock

        from iam_validator.core.models import (
            PolicyValidationResult,
            ValidationIssue,
            ValidationReport,
        )

        scoped = scoped_marker(REVIEW_IDENTIFIER, "role")

        policy_file = tmp_path / "role.json"
        policy_file.write_text(
            "{\n"
            '  "Version": "2012-10-17",\n'
            '  "Statement": [\n'
            "    {\n"
            '      "Sid": "Demo",\n'
            '      "Effect": "Allow",\n'
            '      "Action": "s3:*",\n'
            '      "Resource": "*"\n'
            "    }\n"
            "  ]\n"
            "}\n"
        )

        github = AsyncMock()
        github.is_configured = lambda: True
        github.get_pr_files = AsyncMock(
            return_value=[
                {
                    "filename": policy_file.name,
                    "status": "modified",
                    # The "+" line is line 7 in the new file (Action).
                    "patch": (
                        "@@ -4,5 +4,5 @@\n"
                        "     {\n"
                        '       "Sid": "Demo",\n'
                        '       "Effect": "Allow",\n'
                        '-      "Action": "s3:GetObject",\n'
                        '+      "Action": "s3:*",\n'
                    ),
                }
            ]
        )
        github.update_or_create_review_comments = AsyncMock(return_value=True)

        issue = ValidationIssue(
            policy_file=str(policy_file),
            statement_index=0,
            severity="warning",
            issue_type="overly_broad_action",
            message="Action is overly broad",
            action="s3:*",
            line_number=7,
            check_id="wildcard_action",
        )
        report = ValidationReport(
            results=[
                PolicyValidationResult(
                    policy_file=str(policy_file),
                    is_valid=False,
                    issues=[issue],
                    policy_type="IDENTITY_POLICY",
                )
            ],
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            valid_count=0,
            invalid_count=1,
            total_issues=1,
            policies_with_security_issues=1,
            validity_issues=0,
            security_issues=1,
        )

        commenter = PRCommenter(github=github, comment_tag="role", cleanup_old_comments=False)
        with umock.patch.dict(os.environ, {"GITHUB_WORKSPACE": str(tmp_path)}):
            ok = await commenter._post_review_comments(report)
        assert ok is True

        github.update_or_create_review_comments.assert_called_once()
        kwargs = github.update_or_create_review_comments.call_args.kwargs
        comments = kwargs["comments"]
        assert len(comments) == 1, f"Expected 1 inline comment, got {len(comments)}"
        body = comments[0]["body"]
        # Producer/consumer contract: the body POSTed for an in-diff line
        # must carry the SAME scoped marker the consumer will look up by.
        assert scoped in body, (
            f"In-diff inline body did not include scoped marker {scoped!r}. "
            "Removing review_identifier=self.REVIEW_IDENTIFIER from "
            "pr_commenter.py:_post_review_comments would put the un-scoped "
            "marker in the body and break duplicate-suppression for tagged runs."
            f"\nBody was:\n{body[:200]}..."
        )
        # Cleanup-side check: the identifier passed to the cleanup API is
        # also scoped (so producer/consumer use the same key).
        assert kwargs["identifier"] == scoped


# ---------------------------------------------------------------------------
# Ignored findings storage — scoping isolates the JSON stores
# ---------------------------------------------------------------------------


class TestIgnoredFindingsScoped:
    @pytest.mark.asyncio
    async def test_finds_only_own_storage_comment(self):
        """Two stores with different tags must read distinct payloads even
        when both storage comments coexist on the same PR."""
        policy_marker = scoped_marker(IGNORED_FINDINGS_IDENTIFIER, "policy")
        role_marker = scoped_marker(IGNORED_FINDINGS_IDENTIFIER, "role")

        # Different ignored finding under each scope.
        policy_body = (
            policy_marker
            + "\n```json\n"
            + '{"version": 1, "ignored_findings": [{"finding_id": "policyhash0000000", '
            + '"file_path": "p.json", "check_id": "c", "issue_type": "t", '
            + '"ignored_by": "u", "ignored_at": "2026-04-01T00:00:00Z"}]}\n```\n'
        )
        role_body = (
            role_marker
            + "\n```json\n"
            + '{"version": 1, "ignored_findings": [{"finding_id": "rolehash0000000000", '
            + '"file_path": "r.json", "check_id": "c", "issue_type": "t", '
            + '"ignored_by": "u", "ignored_at": "2026-04-01T00:00:00Z"}]}\n```\n'
        )
        comments = [
            {"id": 10, "body": policy_body},
            {"id": 11, "body": role_body},
        ]

        github = AsyncMock()
        github.get_issue_comments = AsyncMock(return_value=comments)

        policy_store = IgnoredFindingsStore(github, comment_tag="policy")
        role_store = IgnoredFindingsStore(github, comment_tag="role")

        policy_loaded = await policy_store.load()
        role_loaded = await role_store.load()

        assert "policyhash0000000" in policy_loaded
        assert "rolehash0000000000" not in policy_loaded
        assert "rolehash0000000000" in role_loaded
        assert "policyhash0000000" not in role_loaded

    @pytest.mark.asyncio
    async def test_no_tag_finds_legacy_un_scoped_storage(self):
        """Critical regression guard: existing storage comments stored
        under the un-scoped marker before this feature shipped must still
        be loadable by stores constructed without a tag."""
        comments = [
            {
                "id": 1,
                "body": (
                    IGNORED_FINDINGS_IDENTIFIER
                    + "\n```json\n"
                    + '{"version": 1, "ignored_findings": [{"finding_id": "legacyhash0000000", '
                    + '"file_path": "p.json", "check_id": "c", "issue_type": "t", '
                    + '"ignored_by": "u", "ignored_at": "2026-04-01T00:00:00Z"}]}\n```\n'
                ),
            }
        ]
        github = AsyncMock()
        github.get_issue_comments = AsyncMock(return_value=comments)

        store = IgnoredFindingsStore(github)  # no comment_tag
        loaded = await store.load()
        assert "legacyhash0000000" in loaded

    @pytest.mark.asyncio
    async def test_pr_commenter_loads_from_tagged_store(self):
        """Plumbing regression guard.

        ``PRCommenter._load_ignored_findings`` must construct
        ``IgnoredFindingsStore(self.github, comment_tag=self.comment_tag)``
        — not just ``IgnoredFindingsStore(self.github)``. If someone drops
        the ``comment_tag=`` kwarg, the commenter would read ignored
        findings from the wrong (un-tagged) store and silently drop
        scope-specific ignores. None of the unit-level store tests catch
        this; this test pins the integration.

        The PR has BOTH an un-tagged storage comment (with `legacyhash...`)
        AND a role-tagged storage comment (with `rolehash...`). A
        ``PRCommenter(comment_tag="role")`` must load only the role one.
        """
        legacy_body = (
            IGNORED_FINDINGS_IDENTIFIER
            + "\n```json\n"
            + '{"version": 1, "ignored_findings": [{"finding_id": "legacyhash0000000", '
            + '"file_path": "p.json", "check_id": "c", "issue_type": "t", '
            + '"ignored_by": "u", "ignored_at": "2026-04-01T00:00:00Z"}]}\n```\n'
        )
        role_marker = scoped_marker(IGNORED_FINDINGS_IDENTIFIER, "role")
        role_body = (
            role_marker
            + "\n```json\n"
            + '{"version": 1, "ignored_findings": [{"finding_id": "rolehash00000000", '
            + '"file_path": "r.json", "check_id": "c", "issue_type": "t", '
            + '"ignored_by": "u", "ignored_at": "2026-04-01T00:00:00Z"}]}\n```\n'
        )

        github = AsyncMock()
        github.get_issue_comments = AsyncMock(
            return_value=[
                {"id": 1, "body": legacy_body},
                {"id": 2, "body": role_body},
            ]
        )

        commenter = PRCommenter(github=github, comment_tag="role")
        await commenter._load_ignored_findings()

        # The role-tagged commenter must see ONLY the role store. If the
        # plumbing is broken (no comment_tag forwarded), it would load the
        # legacy store and `legacyhash...` would appear here.
        assert "rolehash00000000" in commenter._ignored_finding_ids
        assert "legacyhash0000000" not in commenter._ignored_finding_ids

    @pytest.mark.asyncio
    async def test_save_writes_scoped_marker(self):
        """The persisted comment body must carry the scoped marker so the
        next run's ``load()`` can find it."""
        github = AsyncMock()
        github.get_issue_comments = AsyncMock(return_value=[])
        github.post_comment = AsyncMock(return_value=True)

        store = IgnoredFindingsStore(github, comment_tag="role")
        store._cache = {
            "f" * 16: IgnoredFinding(
                finding_id="f" * 16,
                file_path="r.json",
                check_id="c",
                issue_type="t",
                ignored_by="u",
                ignored_at="2026-04-01T00:00:00Z",
            )
        }
        # Save calls ``_find_storage_comment`` after posting; mock it to
        # avoid a second ``get_issue_comments`` round-trip.
        with patch.object(store, "_find_storage_comment", AsyncMock(return_value=None)):
            ok = await store.save()
        assert ok is True

        body = github.post_comment.await_args.args[0]
        assert scoped_marker(IGNORED_FINDINGS_IDENTIFIER, "role") in body
        # The bare un-scoped marker must not appear standalone.
        assert IGNORED_FINDINGS_IDENTIFIER not in body.replace(scoped_marker(IGNORED_FINDINGS_IDENTIFIER, "role"), "")

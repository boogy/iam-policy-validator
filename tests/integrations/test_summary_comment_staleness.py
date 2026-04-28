"""Tests for summary comment lifecycle.

Goals enforced here:

  1. UPDATE existing comments in place wherever possible (preserve comment id,
     minimize PR-timeline noise).
  2. POST only when there is no existing slot to update.
  3. DELETE existing comments that are no longer relevant to the latest scan.

Regression coverage:

  Bug A — orphan parts after a multi-part → single-part transition:
    A previous run posted N comments sharing the summary identifier
    (multi-part). The next run is single-part. The orphans must be deleted.

  Bug B — finder was not paginated:
    On busy PRs the prior summary lives on page 2+ and was missed,
    causing a duplicate "new" summary to be posted instead of an update.

  Bug C — multi-part previously did delete-and-repost on every run:
    `post_multipart_comments` must update parts in place when the part count
    is unchanged across runs (zero POSTs, zero DELETEs).
"""

from unittest.mock import AsyncMock, patch

import pytest

from iam_validator.core.constants import SUMMARY_IDENTIFIER
from iam_validator.integrations.github_integration import GitHubIntegration

IDENTIFIER = SUMMARY_IDENTIFIER


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


class TestUpdateOrCreateCommentLifecycle:
    """Guarantee exactly one summary comment per PR after each call."""

    @pytest.mark.asyncio
    async def test_creates_when_none_exist(self, gh):
        with (
            patch.object(gh, "_make_paginated_request", AsyncMock(return_value=[])),
            patch.object(gh, "post_comment", AsyncMock(return_value=True)) as mock_post,
            patch.object(gh, "_update_comment", AsyncMock(return_value=True)) as mock_update,
            patch.object(gh, "_make_request", AsyncMock(return_value={})) as mock_req,
        ):
            ok = await gh.update_or_create_comment("body", IDENTIFIER)

        assert ok is True
        mock_post.assert_awaited_once()
        mock_update.assert_not_awaited()
        # No DELETEs issued
        delete_calls = [c for c in mock_req.await_args_list if c.args and c.args[0] == "DELETE"]
        assert delete_calls == []

    @pytest.mark.asyncio
    async def test_updates_in_place_when_one_exists(self, gh):
        existing = [{"id": 42, "body": IDENTIFIER + "\nold", "created_at": "2026-01-01T00:00:00Z"}]
        with (
            patch.object(gh, "_make_paginated_request", AsyncMock(return_value=existing)),
            patch.object(gh, "post_comment", AsyncMock(return_value=True)) as mock_post,
            patch.object(gh, "_update_comment", AsyncMock(return_value=True)) as mock_update,
            patch.object(gh, "_make_request", AsyncMock(return_value={})) as mock_req,
        ):
            ok = await gh.update_or_create_comment("body", IDENTIFIER)

        assert ok is True
        mock_update.assert_awaited_once()
        assert mock_update.await_args.args[0] == 42
        mock_post.assert_not_awaited()
        # No DELETEs (single existing → just update)
        delete_calls = [c for c in mock_req.await_args_list if c.args and c.args[0] == "DELETE"]
        assert delete_calls == []

    @pytest.mark.asyncio
    async def test_orphan_cleanup_after_multipart_to_single(self, gh):
        """Bug A: previous run was multi-part; this run is single-part."""
        existing = [
            {"id": 10, "body": IDENTIFIER + "\nPart 1/3", "created_at": "2026-04-01T10:00:00Z"},
            {"id": 11, "body": IDENTIFIER + "\nPart 2/3", "created_at": "2026-04-01T10:00:01Z"},
            {"id": 12, "body": IDENTIFIER + "\nPart 3/3", "created_at": "2026-04-01T10:00:02Z"},
        ]
        with (
            patch.object(gh, "_make_paginated_request", AsyncMock(return_value=existing)),
            patch.object(gh, "_update_comment", AsyncMock(return_value=True)) as mock_update,
            patch.object(gh, "_make_request", AsyncMock(return_value={})) as mock_req,
        ):
            ok = await gh.update_or_create_comment("fresh body", IDENTIFIER)

        assert ok is True
        # Oldest (id=10) is updated in place
        mock_update.assert_awaited_once()
        assert mock_update.await_args.args[0] == 10
        # The two younger orphans are deleted
        delete_calls = [c for c in mock_req.await_args_list if c.args and c.args[0] == "DELETE"]
        deleted_paths = sorted(c.args[1] for c in delete_calls)
        assert deleted_paths == ["issues/comments/11", "issues/comments/12"]

    @pytest.mark.asyncio
    async def test_finds_summary_on_later_page(self, gh):
        """Bug B: summary is on page 2+, must still be found and updated."""
        # Simulate paginated request returning many comments; the matching
        # summary appears mid-list (i.e., would NOT be on page 1 of a
        # non-paginated call).
        comments = [
            {"id": i, "body": f"unrelated comment {i}", "created_at": f"2026-04-{(i % 28) + 1:02d}T00:00:00Z"}
            for i in range(50)
        ]
        comments.append({"id": 9999, "body": IDENTIFIER + "\nold summary", "created_at": "2026-04-15T00:00:00Z"})
        with (
            patch.object(gh, "_make_paginated_request", AsyncMock(return_value=comments)) as mock_pag,
            patch.object(gh, "_update_comment", AsyncMock(return_value=True)) as mock_update,
            patch.object(gh, "post_comment", AsyncMock(return_value=True)) as mock_post,
        ):
            ok = await gh.update_or_create_comment("fresh body", IDENTIFIER)

        assert ok is True
        # Used paginated lookup, not single-page
        mock_pag.assert_awaited_once()
        # Found and updated the existing summary — NOT posted as new
        mock_update.assert_awaited_once()
        assert mock_update.await_args.args[0] == 9999
        mock_post.assert_not_awaited()


class TestPostMultipartComments:
    """Multi-part lifecycle — update in place, post extras, delete orphans."""

    @pytest.mark.asyncio
    async def test_initial_run_posts_all_parts(self, gh):
        """First run: no existing comments → POST every part, no UPDATEs/DELETEs."""
        with (
            patch.object(gh, "_make_paginated_request", AsyncMock(return_value=[])),
            patch.object(gh, "post_comment", AsyncMock(return_value=True)) as mock_post,
            patch.object(gh, "_update_comment", AsyncMock(return_value=True)) as mock_update,
            patch.object(gh, "_make_request", AsyncMock(return_value={})) as mock_req,
        ):
            ok = await gh.post_multipart_comments(["part1", "part2", "part3"], IDENTIFIER)

        assert ok is True
        assert mock_post.await_count == 3
        mock_update.assert_not_awaited()
        delete_calls = [c for c in mock_req.await_args_list if c.args and c.args[0] == "DELETE"]
        assert delete_calls == []

    @pytest.mark.asyncio
    async def test_same_part_count_updates_in_place_no_noise(self, gh):
        """Bug C: 3 existing → 3 new = all UPDATE, zero POST, zero DELETE."""
        existing = [
            {"id": 100, "body": IDENTIFIER + "\nold 1", "created_at": "2026-04-01T10:00:00Z"},
            {"id": 101, "body": IDENTIFIER + "\nold 2", "created_at": "2026-04-01T10:00:01Z"},
            {"id": 102, "body": IDENTIFIER + "\nold 3", "created_at": "2026-04-01T10:00:02Z"},
        ]
        with (
            patch.object(gh, "_make_paginated_request", AsyncMock(return_value=existing)),
            patch.object(gh, "post_comment", AsyncMock(return_value=True)) as mock_post,
            patch.object(gh, "_update_comment", AsyncMock(return_value=True)) as mock_update,
            patch.object(gh, "_make_request", AsyncMock(return_value={})) as mock_req,
        ):
            ok = await gh.post_multipart_comments(["new 1", "new 2", "new 3"], IDENTIFIER)

        assert ok is True
        # All three updated in place, IDs preserved (oldest-first)
        updated_ids = [call.args[0] for call in mock_update.await_args_list]
        assert updated_ids == [100, 101, 102]
        mock_post.assert_not_awaited()
        delete_calls = [c for c in mock_req.await_args_list if c.args and c.args[0] == "DELETE"]
        assert delete_calls == []

    @pytest.mark.asyncio
    async def test_more_parts_than_existing_updates_then_posts(self, gh):
        """2 existing → 4 new: UPDATE first 2 (preserve ids), POST the extra 2."""
        existing = [
            {"id": 200, "body": IDENTIFIER + "\nold 1", "created_at": "2026-04-01T10:00:00Z"},
            {"id": 201, "body": IDENTIFIER + "\nold 2", "created_at": "2026-04-01T10:00:01Z"},
        ]
        with (
            patch.object(gh, "_make_paginated_request", AsyncMock(return_value=existing)),
            patch.object(gh, "post_comment", AsyncMock(return_value=True)) as mock_post,
            patch.object(gh, "_update_comment", AsyncMock(return_value=True)) as mock_update,
            patch.object(gh, "_make_request", AsyncMock(return_value={})) as mock_req,
        ):
            ok = await gh.post_multipart_comments(["a", "b", "c", "d"], IDENTIFIER)

        assert ok is True
        updated_ids = [call.args[0] for call in mock_update.await_args_list]
        assert updated_ids == [200, 201]
        assert mock_post.await_count == 2
        delete_calls = [c for c in mock_req.await_args_list if c.args and c.args[0] == "DELETE"]
        assert delete_calls == []

    @pytest.mark.asyncio
    async def test_fewer_parts_than_existing_updates_then_deletes_stale(self, gh):
        """4 existing → 2 new: UPDATE first 2, DELETE the leftover 2 (no longer relevant)."""
        existing = [
            {"id": 300, "body": IDENTIFIER + "\nold 1", "created_at": "2026-04-01T10:00:00Z"},
            {"id": 301, "body": IDENTIFIER + "\nold 2", "created_at": "2026-04-01T10:00:01Z"},
            {"id": 302, "body": IDENTIFIER + "\nold 3", "created_at": "2026-04-01T10:00:02Z"},
            {"id": 303, "body": IDENTIFIER + "\nold 4", "created_at": "2026-04-01T10:00:03Z"},
        ]
        with (
            patch.object(gh, "_make_paginated_request", AsyncMock(return_value=existing)),
            patch.object(gh, "post_comment", AsyncMock(return_value=True)) as mock_post,
            patch.object(gh, "_update_comment", AsyncMock(return_value=True)) as mock_update,
            patch.object(gh, "_make_request", AsyncMock(return_value={})) as mock_req,
        ):
            ok = await gh.post_multipart_comments(["only 1", "only 2"], IDENTIFIER)

        assert ok is True
        updated_ids = [call.args[0] for call in mock_update.await_args_list]
        assert updated_ids == [300, 301]
        mock_post.assert_not_awaited()
        delete_calls = [c for c in mock_req.await_args_list if c.args and c.args[0] == "DELETE"]
        deleted_paths = sorted(c.args[1] for c in delete_calls)
        assert deleted_paths == ["issues/comments/302", "issues/comments/303"]

    @pytest.mark.asyncio
    async def test_part_indicators_added_for_multipart_only(self, gh):
        """1 part: no indicator. 2+ parts: each gets '(Part i/N)' header."""
        with (
            patch.object(gh, "_make_paginated_request", AsyncMock(return_value=[])),
            patch.object(gh, "post_comment", AsyncMock(return_value=True)) as mock_post,
        ):
            await gh.post_multipart_comments(["solo body"], IDENTIFIER)
            single_body = mock_post.await_args_list[0].args[0]
            assert "Part" not in single_body
            assert "solo body" in single_body

            mock_post.reset_mock()
            await gh.post_multipart_comments(["A", "B"], IDENTIFIER)
            bodies = [call.args[0] for call in mock_post.await_args_list]
            assert "(Part 1/2)" in bodies[0]
            assert "(Part 2/2)" in bodies[1]


class TestFindAllCommentsWithIdentifier:
    """The paginated finder helper itself."""

    @pytest.mark.asyncio
    async def test_filters_to_matching_only(self, gh):
        comments = [
            {"id": 1, "body": "just a regular comment", "created_at": "2026-04-01T00:00:00Z"},
            {"id": 2, "body": IDENTIFIER + "\nsummary A", "created_at": "2026-04-02T00:00:00Z"},
            {"id": 3, "body": "<!-- some-other-bot -->\nfoo", "created_at": "2026-04-03T00:00:00Z"},
            {"id": 4, "body": IDENTIFIER + "\nsummary B", "created_at": "2026-04-04T00:00:00Z"},
        ]
        with patch.object(gh, "_make_paginated_request", AsyncMock(return_value=comments)):
            matches = await gh._find_all_comments_with_identifier(IDENTIFIER)

        assert [c["id"] for c in matches] == [2, 4]

    @pytest.mark.asyncio
    async def test_sorted_oldest_first(self, gh):
        # Created out of order — must be sorted by created_at ascending.
        comments = [
            {"id": 99, "body": IDENTIFIER + "\nlater", "created_at": "2026-04-10T00:00:00Z"},
            {"id": 5, "body": IDENTIFIER + "\nearlier", "created_at": "2026-04-01T00:00:00Z"},
        ]
        with patch.object(gh, "_make_paginated_request", AsyncMock(return_value=comments)):
            matches = await gh._find_all_comments_with_identifier(IDENTIFIER)

        assert [c["id"] for c in matches] == [5, 99]

    @pytest.mark.asyncio
    async def test_skips_malformed_entries(self, gh):
        comments = [
            "not a dict",
            {"id": "not-an-int", "body": IDENTIFIER},
            {"body": IDENTIFIER + "\nno id"},
            {"id": 7, "body": IDENTIFIER + "\nvalid", "created_at": "2026-04-01T00:00:00Z"},
        ]
        with patch.object(gh, "_make_paginated_request", AsyncMock(return_value=comments)):
            matches = await gh._find_all_comments_with_identifier(IDENTIFIER)

        assert [c["id"] for c in matches] == [7]

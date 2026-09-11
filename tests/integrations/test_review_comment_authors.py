"""Tests for the review comment author listing used by ignore verification.

The listing drives a revocation decision, so an incomplete one must be
reported as unavailable rather than returned as a shorter list — a caller
would otherwise read the missing entries as deleted comments.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from iam_validator.integrations.github_integration import GitHubIntegration


@pytest.fixture
def github():
    with patch.dict(
        "os.environ",
        {
            "GITHUB_TOKEN": "ghp_" + "x" * 36,
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_PR_NUMBER": "42",
        },
        clear=False,
    ):
        integration = GitHubIntegration()
    assert integration.is_configured()
    return integration


def page(items, next_url=None):
    response = MagicMock()
    response.status_code = 200
    response.json = MagicMock(return_value=items)
    response.raise_for_status = MagicMock()
    response.headers = {"Link": f'<{next_url}>; rel="next"'} if next_url else {}
    return response


@pytest.mark.asyncio
async def test_maps_ids_to_logins_across_pages(github):
    pages = [
        page([{"id": 1, "user": {"login": "alice"}}], next_url="https://api.github.com/next"),
        page([{"id": 2, "user": {"login": "bob"}}]),
    ]
    client = MagicMock()
    client.request = AsyncMock(side_effect=pages)
    github._client = client

    assert await github.get_review_comment_authors() == {1: "alice", 2: "bob"}


@pytest.mark.asyncio
async def test_skips_entries_without_a_usable_author(github):
    client = MagicMock()
    client.request = AsyncMock(
        return_value=page(
            [
                {"id": 1, "user": {"login": "alice"}},
                {"id": 2, "user": None},
                {"id": 3},
                {"user": {"login": "carol"}},
                "junk",
            ]
        )
    )
    github._client = client

    assert await github.get_review_comment_authors() == {1: "alice"}


@pytest.mark.asyncio
async def test_returns_none_when_a_page_fails(github):
    """A partial listing must be reported as unavailable, not as fewer comments."""
    failing = MagicMock()
    failing.status_code = 500
    failing.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError("boom", request=MagicMock(), response=MagicMock(status_code=500))
    )
    client = MagicMock()
    client.request = AsyncMock(
        side_effect=[
            page([{"id": 1, "user": {"login": "alice"}}], next_url="https://api.github.com/next"),
            failing,
        ]
    )
    github._client = client

    assert await github.get_review_comment_authors() is None


@pytest.mark.asyncio
async def test_returns_none_on_connection_error(github):
    client = MagicMock()
    client.request = AsyncMock(side_effect=httpx.ConnectError("no route"))
    github._client = client

    assert await github.get_review_comment_authors() is None


@pytest.mark.asyncio
async def test_empty_pr_maps_to_an_empty_dict_not_none(github):
    """A PR with no review comments is known-empty, which is not the same as unknown."""
    client = MagicMock()
    client.request = AsyncMock(return_value=page([]))
    github._client = client

    assert await github.get_review_comment_authors() == {}


@pytest.mark.asyncio
async def test_paginated_request_raises_when_truncated(github):
    """Hitting the page cap with more pages pending is an incomplete listing."""
    client = MagicMock()
    client.request = AsyncMock(return_value=page([{"id": 1}], next_url="https://api.github.com/next"))
    github._client = client

    with pytest.raises(RuntimeError, match="truncated"):
        await github._make_paginated_request("pulls/42/comments", max_pages=2, raise_on_error=True)


@pytest.mark.asyncio
async def test_paginated_request_still_swallows_errors_by_default(github):
    """Existing callers keep the old best-effort behaviour."""
    client = MagicMock()
    client.request = AsyncMock(side_effect=httpx.ConnectError("no route"))
    github._client = client

    assert await github._make_paginated_request("pulls/42/comments") == []

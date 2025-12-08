"""Tests for GitHub API pagination."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from iam_validator.integrations.github_integration import GitHubIntegration


class TestGitHubPagination:
    """Test GitHub API pagination for comments."""

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
    async def test_paginated_request_single_page(self, github_integration):
        """Test pagination with single page of results."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"id": 1, "body": "comment 1"},
            {"id": 2, "body": "comment 2"},
        ]
        mock_response.headers = {}  # No Link header = single page
        mock_response.raise_for_status = MagicMock()

        with patch.object(
            github_integration, "_client", None
        ):
            with patch("httpx.AsyncClient") as mock_client_class:
                mock_client = MagicMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.request = AsyncMock(return_value=mock_response)
                mock_client_class.return_value = mock_client

                result = await github_integration._make_paginated_request(
                    "pulls/123/comments"
                )

        assert len(result) == 2
        assert result[0]["id"] == 1
        assert result[1]["id"] == 2

    @pytest.mark.asyncio
    async def test_paginated_request_multiple_pages(self, github_integration):
        """Test pagination with multiple pages of results."""
        # Page 1 response
        page1_response = MagicMock()
        page1_response.status_code = 200
        page1_response.json.return_value = [{"id": i, "body": f"comment {i}"} for i in range(1, 101)]
        page1_response.headers = {
            "Link": '<https://api.github.com/repos/owner/repo/pulls/123/comments?page=2&per_page=100>; rel="next", <https://api.github.com/repos/owner/repo/pulls/123/comments?page=2&per_page=100>; rel="last"'
        }
        page1_response.raise_for_status = MagicMock()

        # Page 2 response (last page)
        page2_response = MagicMock()
        page2_response.status_code = 200
        page2_response.json.return_value = [{"id": i, "body": f"comment {i}"} for i in range(101, 153)]
        page2_response.headers = {}  # No next link
        page2_response.raise_for_status = MagicMock()

        with patch.object(github_integration, "_client", None):
            with patch("httpx.AsyncClient") as mock_client_class:
                mock_client = MagicMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.request = AsyncMock(side_effect=[page1_response, page2_response])
                mock_client_class.return_value = mock_client

                result = await github_integration._make_paginated_request(
                    "pulls/123/comments"
                )

        assert len(result) == 152  # 100 + 52
        assert result[0]["id"] == 1
        assert result[100]["id"] == 101
        assert result[151]["id"] == 152

    @pytest.mark.asyncio
    async def test_paginated_request_respects_max_pages(self, github_integration):
        """Test that pagination respects max_pages limit."""
        # Create responses that always have a next page
        def make_response(page_num):
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = [{"id": page_num, "body": f"page {page_num}"}]
            response.headers = {
                "Link": f'<https://api.github.com/next?page={page_num + 1}>; rel="next"'
            }
            response.raise_for_status = MagicMock()
            return response

        with patch.object(github_integration, "_client", None):
            with patch("httpx.AsyncClient") as mock_client_class:
                mock_client = MagicMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.request = AsyncMock(side_effect=[make_response(i) for i in range(1, 10)])
                mock_client_class.return_value = mock_client

                result = await github_integration._make_paginated_request(
                    "pulls/123/comments", max_pages=3
                )

        assert len(result) == 3  # Should stop at 3 pages

    @pytest.mark.asyncio
    async def test_get_review_comments_uses_pagination(self, github_integration):
        """Test that get_review_comments uses pagination."""
        with patch.object(
            github_integration,
            "_make_paginated_request",
            new_callable=AsyncMock,
            return_value=[{"id": 1}, {"id": 2}],
        ) as mock_paginated:
            result = await github_integration.get_review_comments()

        mock_paginated.assert_called_once_with("pulls/123/comments")
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_issue_comments_uses_pagination(self, github_integration):
        """Test that get_issue_comments uses pagination."""
        with patch.object(
            github_integration,
            "_make_paginated_request",
            new_callable=AsyncMock,
            return_value=[{"id": 1}, {"id": 2}, {"id": 3}],
        ) as mock_paginated:
            result = await github_integration.get_issue_comments()

        mock_paginated.assert_called_once_with("issues/123/comments")
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_paginated_request_handles_http_error(self, github_integration):
        """Test that pagination handles HTTP errors gracefully."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server error", request=MagicMock(), response=mock_response
        )

        with patch.object(github_integration, "_client", None):
            with patch("httpx.AsyncClient") as mock_client_class:
                mock_client = MagicMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.request = AsyncMock(return_value=mock_response)
                mock_client_class.return_value = mock_client

                result = await github_integration._make_paginated_request(
                    "pulls/123/comments"
                )

        assert result == []  # Should return empty list on error

    @pytest.mark.asyncio
    async def test_paginated_request_adds_per_page_param(self, github_integration):
        """Test that pagination adds per_page=100 parameter."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_response.headers = {}
        mock_response.raise_for_status = MagicMock()

        with patch.object(github_integration, "_client", None):
            with patch("httpx.AsyncClient") as mock_client_class:
                mock_client = MagicMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.request = AsyncMock(return_value=mock_response)
                mock_client_class.return_value = mock_client

                await github_integration._make_paginated_request("pulls/123/comments")

        # Check that the URL includes per_page=100
        call_args = mock_client.request.call_args
        url = call_args[0][1]  # Second positional arg is URL
        assert "per_page=100" in url

    @pytest.mark.asyncio
    async def test_paginated_request_not_configured(self, github_integration):
        """Test pagination returns empty list when not configured."""
        with patch.object(github_integration, "is_configured", return_value=False):
            result = await github_integration._make_paginated_request("pulls/123/comments")

        assert result == []


class TestParallelDeletion:
    """Test parallel comment deletion with semaphore."""

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
    async def test_delete_comments_parallel_empty_list(self, github_integration):
        """Test parallel deletion with empty list returns zeros."""
        successful, failed = await github_integration._delete_comments_parallel([])
        assert successful == 0
        assert failed == 0

    @pytest.mark.asyncio
    async def test_delete_comments_parallel_all_successful(self, github_integration):
        """Test parallel deletion when all deletions succeed."""
        comment_ids = [1, 2, 3, 4, 5]

        with patch.object(
            github_integration,
            "delete_review_comment",
            new_callable=AsyncMock,
            return_value=True,
        ) as mock_delete:
            successful, failed = await github_integration._delete_comments_parallel(comment_ids)

        assert successful == 5
        assert failed == 0
        assert mock_delete.call_count == 5

    @pytest.mark.asyncio
    async def test_delete_comments_parallel_some_failures(self, github_integration):
        """Test parallel deletion when some deletions fail."""
        comment_ids = [1, 2, 3, 4, 5]

        # Simulate: 1, 3, 5 succeed; 2, 4 fail
        async def mock_delete(comment_id):
            return comment_id % 2 == 1  # Odd IDs succeed

        with patch.object(
            github_integration,
            "delete_review_comment",
            side_effect=mock_delete,
        ):
            successful, failed = await github_integration._delete_comments_parallel(comment_ids)

        assert successful == 3
        assert failed == 2

    @pytest.mark.asyncio
    async def test_delete_comments_parallel_respects_concurrency(self, github_integration):
        """Test that parallel deletion respects max_concurrent limit."""
        import asyncio

        comment_ids = list(range(1, 21))  # 20 comments
        concurrent_count = 0
        max_concurrent_seen = 0

        async def mock_delete(comment_id):
            nonlocal concurrent_count, max_concurrent_seen
            concurrent_count += 1
            max_concurrent_seen = max(max_concurrent_seen, concurrent_count)
            await asyncio.sleep(0.01)  # Small delay to allow overlap
            concurrent_count -= 1
            return True

        with patch.object(
            github_integration,
            "delete_review_comment",
            side_effect=mock_delete,
        ):
            successful, failed = await github_integration._delete_comments_parallel(
                comment_ids, max_concurrent=5
            )

        assert successful == 20
        assert failed == 0
        # Should never exceed the concurrency limit
        assert max_concurrent_seen <= 5

    @pytest.mark.asyncio
    async def test_delete_comments_parallel_handles_exceptions(self, github_integration):
        """Test that parallel deletion handles exceptions gracefully."""
        comment_ids = [1, 2, 3]

        async def mock_delete(comment_id):
            if comment_id == 2:
                raise RuntimeError("API error")
            return True

        with patch.object(
            github_integration,
            "delete_review_comment",
            side_effect=mock_delete,
        ):
            successful, failed = await github_integration._delete_comments_parallel(comment_ids)

        # 1 and 3 succeed, 2 raises exception (counted as failure)
        assert successful == 2
        assert failed == 1

    @pytest.mark.asyncio
    async def test_cleanup_bot_review_comments_uses_parallel(self, github_integration):
        """Test that cleanup_bot_review_comments uses parallel deletion."""
        mock_comments = [
            {"id": 1, "body": "🤖 IAM Policy Validator - finding 1"},
            {"id": 2, "body": "Some other comment"},  # Not a bot comment
            {"id": 3, "body": "🤖 IAM Policy Validator - finding 2"},
            {"id": 4, "body": "🤖 IAM Policy Validator - finding 3"},
        ]

        with patch.object(
            github_integration,
            "get_review_comments",
            new_callable=AsyncMock,
            return_value=mock_comments,
        ):
            with patch.object(
                github_integration,
                "_delete_comments_parallel",
                new_callable=AsyncMock,
                return_value=(3, 0),
            ) as mock_parallel:
                result = await github_integration.cleanup_bot_review_comments()

        # Should only delete bot comments (IDs 1, 3, 4)
        mock_parallel.assert_called_once()
        call_args = mock_parallel.call_args[0][0]
        assert sorted(call_args) == [1, 3, 4]
        assert result == 3

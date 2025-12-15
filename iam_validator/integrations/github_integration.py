"""GitHub Integration Module.

This module provides functionality to interact with GitHub,
including posting PR comments, line comments, labels, and retrieving PR information.
"""

import asyncio
import base64
import logging
import os
import re
import time
from enum import Enum
from typing import TYPE_CHECKING, Any

import httpx

from iam_validator.core import constants

if TYPE_CHECKING:
    from iam_validator.core.codeowners import CodeOwnersParser

logger = logging.getLogger(__name__)


class GitHubRateLimitError(Exception):
    """Raised when GitHub API rate limit is exceeded."""

    def __init__(self, reset_time: int, message: str = "GitHub API rate limit exceeded"):
        self.reset_time = reset_time
        super().__init__(message)


class GitHubRetryableError(Exception):
    """Raised for transient GitHub API errors that should be retried."""

    pass  # pylint: disable=unnecessary-pass


# Retry configuration
MAX_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 30.0
BACKOFF_MULTIPLIER = 2.0

# HTTP status codes that should trigger retry
RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}

# Concurrency limit for parallel API operations (deletions, updates)
# This prevents hitting GitHub's secondary rate limits while still being fast
MAX_CONCURRENT_API_CALLS = 10


class PRState(str, Enum):
    """GitHub PR state."""

    OPEN = "open"
    CLOSED = "closed"
    ALL = "all"


class ReviewEvent(str, Enum):
    """GitHub PR review event types."""

    APPROVE = "APPROVE"
    REQUEST_CHANGES = "REQUEST_CHANGES"
    COMMENT = "COMMENT"


class GitHubIntegration:
    """Handles comprehensive GitHub API interactions for PRs.

    This class provides methods to:
    - Post general PR comments
    - Add line-specific review comments
    - Manage PR labels
    - Submit PR reviews
    - Retrieve PR information and files
    """

    def __init__(
        self,
        token: str | None = None,
        repository: str | None = None,
        pr_number: str | None = None,
    ):
        """Initialize GitHub integration.

        Args:
            token: GitHub API token (defaults to GITHUB_TOKEN env var)
            repository: Repository in format 'owner/repo' (defaults to GITHUB_REPOSITORY env var)
            pr_number: PR number (defaults to GITHUB_PR_NUMBER env var)
        """
        self.token = self._validate_token(token or os.environ.get("GITHUB_TOKEN"))
        self.repository = self._validate_repository(
            repository or os.environ.get("GITHUB_REPOSITORY")
        )
        self.pr_number = self._validate_pr_number(pr_number or os.environ.get("GITHUB_PR_NUMBER"))
        self.api_url = self._validate_api_url(
            os.environ.get("GITHUB_API_URL", "https://api.github.com")
        )
        self._client: httpx.AsyncClient | None = None
        # Cache for team memberships: (org, team_slug) -> list[str]
        # Reduces API calls when checking multiple users against same team
        self._team_cache: dict[tuple[str, str], list[str]] = {}
        # Cache for CODEOWNERS content (fetched once per instance)
        self._codeowners_cache: str | None = None
        self._codeowners_loaded: bool = False

    def _validate_token(self, token: str | None) -> str | None:
        """Validate and sanitize GitHub token.

        Args:
            token: GitHub token to validate

        Returns:
            Validated token or None
        """
        if token is None:
            return None

        # Basic validation - ensure it's a string and not empty
        if not isinstance(token, str) or not token.strip():
            logger.warning("Invalid GitHub token provided (empty or non-string)")
            return None

        # Sanitize - remove any whitespace
        token = token.strip()

        # Basic format check - GitHub tokens have specific patterns
        # Personal access tokens: ghp_*, fine-grained: github_pat_*
        # GitHub App tokens start with different prefixes
        # Just ensure it's reasonable length and ASCII
        if len(token) < 10 or len(token) > 500:
            logger.warning(f"GitHub token has unusual length: {len(token)}")
            return None

        # Ensure only ASCII characters (tokens should be ASCII)
        if not token.isascii():
            logger.warning("GitHub token contains non-ASCII characters")
            return None

        return token

    def _validate_repository(self, repository: str | None) -> str | None:
        """Validate repository format (owner/repo).

        Args:
            repository: Repository string to validate

        Returns:
            Validated repository or None
        """
        if repository is None:
            return None

        if not isinstance(repository, str) or not repository.strip():
            logger.warning("Invalid repository provided (empty or non-string)")
            return None

        repository = repository.strip()

        # Must be in format owner/repo
        if "/" not in repository:
            logger.warning(f"Invalid repository format: {repository} (expected owner/repo)")
            return None

        parts = repository.split("/")
        if len(parts) != 2:
            logger.warning(f"Invalid repository format: {repository} (expected exactly one slash)")
            return None

        owner, repo = parts
        if not owner or not repo:
            logger.warning(f"Invalid repository format: {repository} (empty owner or repo)")
            return None

        # Basic sanitization - alphanumeric, hyphens, underscores, dots
        # GitHub allows these characters in usernames and repo names
        valid_pattern = re.compile(r"^[a-zA-Z0-9._-]+$")
        if not valid_pattern.match(owner) or not valid_pattern.match(repo):
            logger.warning(
                f"Invalid characters in repository: {repository} "
                "(only alphanumeric, ., -, _ allowed)"
            )
            return None

        return repository

    def _validate_pr_number(self, pr_number: str | None) -> str | None:
        """Validate PR number.

        Args:
            pr_number: PR number to validate

        Returns:
            Validated PR number or None
        """
        if pr_number is None:
            return None

        if not isinstance(pr_number, str) or not pr_number.strip():
            logger.warning("Invalid PR number provided (empty or non-string)")
            return None

        pr_number = pr_number.strip()

        # Must be a positive integer
        try:
            pr_int = int(pr_number)
            if pr_int <= 0:
                logger.warning(f"Invalid PR number: {pr_number} (must be positive)")
                return None
        except ValueError:
            logger.warning(f"Invalid PR number: {pr_number} (must be an integer)")
            return None

        return pr_number

    def _validate_api_url(self, api_url: str) -> str:
        """Validate GitHub API URL.

        Args:
            api_url: API URL to validate

        Returns:
            Validated API URL or default
        """
        if not api_url or not isinstance(api_url, str):
            logger.warning("Invalid API URL provided, using default")
            return "https://api.github.com"

        api_url = api_url.strip()

        # Must be HTTPS (security requirement)
        if not api_url.startswith("https://"):
            logger.warning(
                f"API URL must use HTTPS: {api_url}, using default https://api.github.com"
            )
            return "https://api.github.com"

        # Basic URL validation
        # Simple URL pattern check
        url_pattern = re.compile(r"^https://[a-zA-Z0-9.-]+(?:/.*)?$")
        if not url_pattern.match(api_url):
            logger.warning(f"Invalid API URL format: {api_url}, using default")
            return "https://api.github.com"

        return api_url

    async def __aenter__(self) -> "GitHubIntegration":
        """Async context manager entry."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            headers=self._get_headers(),
        )
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        del exc_type, exc_val, exc_tb  # Unused
        if self._client:
            await self._client.aclose()
            self._client = None

    def _get_headers(self) -> dict[str, str]:
        """Get common request headers."""
        return {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        }

    def is_configured(self) -> bool:
        """Check if GitHub integration is properly configured.

        Returns:
            True if all required environment variables are set
        """
        is_valid = all([self.token, self.repository, self.pr_number])

        # Provide helpful debug info when not configured
        if not is_valid:
            missing = []
            if not self.token:
                missing.append("GITHUB_TOKEN")
            if not self.repository:
                missing.append("GITHUB_REPOSITORY")
            if not self.pr_number:
                missing.append("GITHUB_PR_NUMBER")

            logger.debug(f"GitHub integration missing: {', '.join(missing)}")
            if not self.pr_number and self.token and self.repository:
                logger.info(
                    "GitHub PR integration requires GITHUB_PR_NUMBER. "
                    "This is only available when running on pull request events. "
                    "Current event may not have PR context."
                )

        return is_valid

    async def _make_request(
        self, method: str, endpoint: str, **kwargs: Any
    ) -> dict[str, Any] | None:
        """Make an HTTP request to GitHub API with retry and rate limit handling.

        Implements exponential backoff for transient errors (5xx, 429) and
        respects GitHub's rate limit headers.

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE)
            endpoint: API endpoint path
            **kwargs: Additional arguments to pass to httpx

        Returns:
            Response JSON or None on error
        """
        if not self.is_configured():
            logger.error("GitHub integration not configured")
            return None

        url = f"{self.api_url}/repos/{self.repository}/{endpoint}"
        backoff = INITIAL_BACKOFF_SECONDS
        last_error: Exception | None = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                if self._client:
                    response = await self._client.request(method, url, **kwargs)
                else:
                    async with httpx.AsyncClient(headers=self._get_headers()) as client:
                        response = await client.request(method, url, **kwargs)

                # Handle rate limiting (429)
                if response.status_code == 429:
                    # Get reset time from headers
                    reset_time = response.headers.get("X-RateLimit-Reset")
                    retry_after = response.headers.get("Retry-After")

                    if retry_after:
                        wait_time = int(retry_after)
                    elif reset_time:
                        wait_time = max(0, int(reset_time) - int(time.time()))
                    else:
                        wait_time = min(backoff, MAX_BACKOFF_SECONDS)

                    if attempt < MAX_RETRIES:
                        logger.warning(
                            f"Rate limited on {method} {endpoint}, "
                            f"waiting {wait_time}s (attempt {attempt + 1}/{MAX_RETRIES + 1})"
                        )
                        await asyncio.sleep(wait_time)
                        backoff = min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_SECONDS)
                        continue
                    else:
                        raise GitHubRateLimitError(
                            int(reset_time or 0),
                            f"Rate limit exceeded after {MAX_RETRIES + 1} attempts",
                        )

                # Handle retryable server errors (5xx)
                if response.status_code in RETRYABLE_STATUS_CODES and attempt < MAX_RETRIES:
                    logger.warning(
                        f"Retryable error {response.status_code} on {method} {endpoint}, "
                        f"retrying in {backoff:.1f}s (attempt {attempt + 1}/{MAX_RETRIES + 1})"
                    )
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_SECONDS)
                    continue

                response.raise_for_status()
                return response.json() if response.text else {}

            except httpx.HTTPStatusError as e:
                last_error = e
                # Don't retry client errors (4xx) except rate limit
                if 400 <= e.response.status_code < 500 and e.response.status_code != 429:
                    logger.error(f"HTTP error: {e.response.status_code} - {e.response.text}")
                    return None
                # For server errors, continue to retry logic
                if attempt < MAX_RETRIES:
                    logger.warning(
                        f"HTTP error {e.response.status_code}, retrying in {backoff:.1f}s"
                    )
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_SECONDS)
                    continue

            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_error = e
                if attempt < MAX_RETRIES:
                    logger.warning(
                        f"Connection error on {method} {endpoint}: {e}, "
                        f"retrying in {backoff:.1f}s (attempt {attempt + 1}/{MAX_RETRIES + 1})"
                    )
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_SECONDS)
                    continue

            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Unexpected error on {method} {endpoint}: {e}")
                return None

        # All retries exhausted
        if last_error:
            logger.error(f"Request failed after {MAX_RETRIES + 1} attempts: {last_error}")
        return None

    async def _make_request_no_retry(
        self, method: str, endpoint: str, **kwargs: Any
    ) -> dict[str, Any] | None:
        """Make an HTTP request without retry (for non-critical operations).

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE)
            endpoint: API endpoint path
            **kwargs: Additional arguments to pass to httpx

        Returns:
            Response JSON or None on error
        """
        if not self.is_configured():
            logger.error("GitHub integration not configured")
            return None

        url = f"{self.api_url}/repos/{self.repository}/{endpoint}"

        try:
            if self._client:
                response = await self._client.request(method, url, **kwargs)
            else:
                async with httpx.AsyncClient(headers=self._get_headers()) as client:
                    response = await client.request(method, url, **kwargs)

            response.raise_for_status()
            return response.json() if response.text else {}

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"Request failed: {e}")
            return None

    async def _make_paginated_request(
        self, endpoint: str, max_pages: int = 100
    ) -> list[dict[str, Any]]:
        """Make a paginated GET request to GitHub API, fetching all pages.

        GitHub API returns at most 100 items per page for list endpoints.
        This method follows pagination links to fetch ALL items.

        Args:
            endpoint: API endpoint path (e.g., "pulls/123/comments")
            max_pages: Maximum number of pages to fetch (safety limit)

        Returns:
            Combined list of all items across all pages
        """
        if not self.is_configured():
            logger.error("GitHub integration not configured")
            return []

        all_items: list[dict[str, Any]] = []
        url: str | None = f"{self.api_url}/repos/{self.repository}/{endpoint}"
        page_count = 0

        # Add per_page=100 to maximize items per request
        if "?" in endpoint:
            url = f"{url}&per_page=100"
        else:
            url = f"{url}?per_page=100"

        while url and page_count < max_pages:
            page_count += 1
            try:
                if self._client:
                    response = await self._client.request("GET", url)
                else:
                    async with httpx.AsyncClient(
                        timeout=httpx.Timeout(30.0), headers=self._get_headers()
                    ) as client:
                        response = await client.request("GET", url)

                response.raise_for_status()
                items = response.json()

                if isinstance(items, list):
                    all_items.extend(items)
                    logger.debug(
                        f"Fetched page {page_count} with {len(items)} items "
                        f"(total: {len(all_items)})"
                    )
                else:
                    # Not a list response, shouldn't happen for list endpoints
                    logger.warning(f"Unexpected response type on page {page_count}")
                    break

                # Check for next page in Link header
                # Format: <url>; rel="next", <url>; rel="last"
                link_header = response.headers.get("Link", "")
                url = None  # Reset for next iteration

                if link_header:
                    for link in link_header.split(","):
                        if 'rel="next"' in link:
                            # Extract URL from <url>
                            match = re.search(r"<([^>]+)>", link)
                            if match:
                                url = match.group(1)
                                break

            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error during pagination: {e.response.status_code}")
                break
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error during pagination: {e}")
                break

        if page_count >= max_pages:
            logger.warning(f"Reached max pages limit ({max_pages}), results may be incomplete")

        logger.debug(
            f"Paginated request complete: {len(all_items)} total items from {page_count} page(s)"
        )
        return all_items

    # ==================== PR Comments ====================

    async def post_comment(self, comment_body: str) -> bool:
        """Post a general comment to a PR.

        Args:
            comment_body: The markdown content to post

        Returns:
            True if successful, False otherwise
        """
        result = await self._make_request(
            "POST",
            f"issues/{self.pr_number}/comments",
            json={"body": comment_body},
        )

        if result:
            logger.info(f"Successfully posted comment to PR #{self.pr_number}")
            return True
        return False

    async def update_or_create_comment(
        self, comment_body: str, identifier: str = "<!-- iam-policy-validator -->"
    ) -> bool:
        """Update an existing comment or create a new one.

        This method will look for an existing comment with the identifier
        and update it, or create a new comment if none exists.

        Args:
            comment_body: The markdown content to post
            identifier: HTML comment identifier to find existing comments

        Returns:
            True if successful, False otherwise
        """
        # Add identifier to comment body
        full_body = f"{identifier}\n{comment_body}"

        # Try to find and update existing comment
        existing_comment_id = await self._find_existing_comment(identifier)

        if existing_comment_id:
            return await self._update_comment(existing_comment_id, full_body)
        else:
            return await self.post_comment(full_body)

    async def post_multipart_comments(
        self,
        comment_parts: list[str],
        identifier: str = "<!-- iam-policy-validator -->",
    ) -> bool:
        """Post or update multiple related comments (for large reports).

        For single-part comments (most common case), this will UPDATE the
        existing comment in place rather than delete and recreate it.
        This preserves comment history and avoids PR timeline noise.

        For multi-part comments:
        1. Delete all old comments with the identifier
        2. Post new comments in sequence with part indicators
        3. Validate each part stays under GitHub's limit

        Args:
            comment_parts: List of comment bodies to post (split into parts)
            identifier: HTML comment identifier to find/manage existing comments

        Returns:
            True if all parts posted successfully, False otherwise
        """
        # GitHub's actual limit
        github_comment_limit = 65536

        total_parts = len(comment_parts)

        # Optimization: For single-part comments, use update-or-create
        # This preserves the existing comment and avoids PR timeline noise
        if total_parts == 1:
            part_body = comment_parts[0]
            full_body = f"{identifier}\n\n{part_body}"

            # Safety check: ensure we don't exceed GitHub's limit
            if len(full_body) > github_comment_limit:
                logger.error(
                    f"Comment exceeds GitHub's limit ({len(full_body)} > {github_comment_limit} chars). "
                    f"Comment will be truncated."
                )
                available_space = github_comment_limit - 500
                truncated_body = part_body[:available_space]
                truncation_warning = (
                    "\n\n---\n\n"
                    "> ⚠️ **This comment was truncated to fit GitHub's size limit**\n"
                    ">\n"
                    "> Download the full report using `--output report.json` or "
                    "`--format markdown --output report.md`\n"
                )
                full_body = f"{identifier}\n\n{truncated_body}{truncation_warning}"

            success = await self.update_or_create_comment(full_body, identifier)
            if success:
                logger.info("Successfully updated summary comment")
            return success

        # Multi-part: Delete all existing comments with this identifier first
        await self._delete_comments_with_identifier(identifier)

        # Post each part
        success = True

        for part_num, part_body in enumerate(comment_parts, 1):
            # Add identifier and part indicator
            part_indicator = f"**(Part {part_num}/{total_parts})**"
            full_body = f"{identifier}\n{part_indicator}\n\n{part_body}"

            # Safety check: ensure we don't exceed GitHub's limit
            if len(full_body) > github_comment_limit:
                logger.error(
                    f"Part {part_num}/{total_parts} exceeds GitHub's comment limit "
                    f"({len(full_body)} > {github_comment_limit} chars). "
                    f"This part will be truncated."
                )
                # Truncate with warning message
                available_space = github_comment_limit - 500  # Reserve space for truncation message
                truncated_body = part_body[:available_space]
                truncation_warning = (
                    "\n\n---\n\n"
                    "> ⚠️ **This comment was truncated to fit GitHub's size limit**\n"
                    ">\n"
                    "> Download the full report using `--output report.json` or "
                    "`--format markdown --output report.md`\n"
                )
                full_body = (
                    f"{identifier}\n{part_indicator}\n\n{truncated_body}{truncation_warning}"
                )

            if not await self.post_comment(full_body):
                logger.error(f"Failed to post comment part {part_num}/{total_parts}")
                success = False
            else:
                logger.debug(
                    f"Posted part {part_num}/{total_parts} ({len(full_body):,} characters)"
                )

        if success:
            logger.info(f"Successfully posted {total_parts} comment part(s)")

        return success

    async def _delete_comments_with_identifier(self, identifier: str) -> int:
        """Delete all comments with the given identifier.

        Args:
            identifier: HTML comment identifier to find comments

        Returns:
            Number of comments deleted
        """
        result = await self._make_request("GET", f"issues/{self.pr_number}/comments")

        deleted_count = 0
        if result and isinstance(result, list):
            for comment in result:
                if not isinstance(comment, dict):
                    continue

                body = comment.get("body", "")
                comment_id = comment.get("id")

                if identifier in str(body) and isinstance(comment_id, int):
                    delete_result = await self._make_request(
                        "DELETE", f"issues/comments/{comment_id}"
                    )
                    if delete_result is not None:
                        deleted_count += 1

        if deleted_count > 0:
            logger.info(f"Deleted {deleted_count} old comments")

        return deleted_count

    async def _find_existing_comment(self, identifier: str) -> int | None:
        """Find an existing comment with the given identifier."""
        result = await self._make_request("GET", f"issues/{self.pr_number}/comments")

        if result and isinstance(result, list):
            for comment in result:
                if isinstance(comment, dict) and identifier in str(comment.get("body", "")):
                    comment_id = comment.get("id")
                    if isinstance(comment_id, int):
                        return comment_id

        return None

    async def _update_comment(self, comment_id: int, comment_body: str) -> bool:
        """Update an existing GitHub comment."""
        result = await self._make_request(
            "PATCH",
            f"issues/comments/{comment_id}",
            json={"body": comment_body},
        )

        if result:
            logger.info(f"Successfully updated comment {comment_id}")
            return True
        return False

    # ==================== PR Review Comments (Line-specific) ====================

    async def get_review_comments(self) -> list[dict[str, Any]]:
        """Get all review comments on the PR with pagination.

        Fetches ALL review comments across all pages. This is critical for
        proper comment deduplication and cleanup when there are many findings.

        Returns:
            List of all review comment dicts
        """
        return await self._make_paginated_request(f"pulls/{self.pr_number}/comments")

    async def get_bot_review_comments_with_location(
        self, identifier: str = constants.BOT_IDENTIFIER
    ) -> dict[tuple[str, int, str], dict[str, Any]]:
        """Get bot review comments indexed by file path, line number, and issue type.

        This enables efficient lookup to update existing comments.
        Uses (path, line, issue_type) as key to support multiple issues at the same line.

        Args:
            identifier: String to identify bot comments

        Returns:
            Dict mapping (file_path, line_number, issue_type) to comment metadata dict
            Comment dict contains: id, body, path, line, issue_type, commit_id
        """
        comments = await self.get_review_comments()
        bot_comments_map: dict[tuple[str, int, str], dict[str, Any]] = {}

        for comment in comments:
            if not isinstance(comment, dict):
                continue

            body = comment.get("body", "")
            comment_id = comment.get("id")
            path = comment.get("path")
            line = comment.get("line") or comment.get("original_line")

            # Check if this is a bot comment with valid location
            if (
                identifier in str(body)
                and isinstance(comment_id, int)
                and isinstance(path, str)
                and isinstance(line, int)
            ):
                # Extract issue type from HTML comment
                issue_type_match = re.search(r"<!-- issue-type: (\w+) -->", body)
                issue_type = issue_type_match.group(1) if issue_type_match else "unknown"

                key = (path, line, issue_type)
                bot_comments_map[key] = {
                    "id": comment_id,
                    "body": body,
                    "path": path,
                    "line": line,
                    "issue_type": issue_type,
                    "commit_id": comment.get("commit_id"),
                }

        logger.debug(f"Found {len(bot_comments_map)} bot review comments at specific locations")
        return bot_comments_map

    async def delete_review_comment(self, comment_id: int) -> bool:
        """Delete a specific review comment.

        Args:
            comment_id: ID of the comment to delete

        Returns:
            True if successful, False otherwise
        """
        result = await self._make_request(
            "DELETE",
            f"pulls/comments/{comment_id}",
        )

        if result is not None:  # DELETE returns empty dict on success
            logger.debug(f"Successfully deleted review comment {comment_id}")
            return True
        return False

    async def _delete_comments_parallel(
        self, comment_ids: list[int], max_concurrent: int = MAX_CONCURRENT_API_CALLS
    ) -> tuple[int, int]:
        """Delete multiple review comments in parallel with controlled concurrency.

        Uses a semaphore to limit concurrent API calls, preventing rate limit issues
        while still being much faster than sequential deletion.

        Args:
            comment_ids: List of comment IDs to delete
            max_concurrent: Maximum number of concurrent deletions (default: 10)

        Returns:
            Tuple of (successful_count, failed_count)
        """
        if not comment_ids:
            return (0, 0)

        semaphore = asyncio.Semaphore(max_concurrent)

        async def delete_with_limit(comment_id: int) -> bool:
            async with semaphore:
                return await self.delete_review_comment(comment_id)

        # Run all deletions in parallel (semaphore controls actual concurrency)
        results = await asyncio.gather(
            *[delete_with_limit(cid) for cid in comment_ids],
            return_exceptions=True,
        )

        successful = sum(1 for r in results if r is True)
        failed = len(results) - successful

        if successful > 0:
            logger.info(f"Parallel deletion: {successful} deleted, {failed} failed")

        return (successful, failed)

    # NOTE: resolve_review_comment was removed because GitHub REST API doesn't support
    # resolving review comments via {"state": "resolved"}. Resolving review threads
    # requires the GraphQL API with resolveReviewThread mutation.
    # See: https://docs.github.com/en/graphql/reference/mutations#resolvereviewthread

    async def update_review_comment(self, comment_id: int, new_body: str) -> bool:
        """Update the body text of an existing review comment.

        Args:
            comment_id: ID of the comment to update
            new_body: New comment text (markdown supported)

        Returns:
            True if successful, False otherwise
        """
        result = await self._make_request(
            "PATCH",
            f"pulls/comments/{comment_id}",
            json={"body": new_body},
        )

        if result is not None:
            logger.debug(f"Successfully updated review comment {comment_id}")
            return True
        return False

    async def cleanup_bot_review_comments(self, identifier: str = constants.BOT_IDENTIFIER) -> int:
        """Delete all review comments from the bot (from previous runs).

        This ensures old/outdated comments are removed before posting new ones.
        Uses parallel deletion for speed when there are many comments.

        Args:
            identifier: String to identify bot comments

        Returns:
            Number of comments deleted
        """
        comments = await self.get_review_comments()

        # Collect all bot comment IDs to delete
        comment_ids_to_delete: list[int] = []
        for comment in comments:
            if not isinstance(comment, dict):
                continue

            body = comment.get("body", "")
            comment_id = comment.get("id")

            # Check if this is a bot comment
            if identifier in str(body) and isinstance(comment_id, int):
                comment_ids_to_delete.append(comment_id)

        if not comment_ids_to_delete:
            return 0

        # Delete all bot comments in parallel
        successful, _failed = await self._delete_comments_parallel(comment_ids_to_delete)

        if successful > 0:
            logger.info(f"Cleaned up {successful} old review comments")

        return successful

    # NOTE: cleanup_bot_review_comments_by_resolving was removed because it depended on
    # resolve_review_comment which doesn't work with GitHub REST API.
    # Use cleanup_bot_review_comments (deletion) instead, or implement GraphQL-based
    # resolution if audit trail preservation is needed.

    async def create_review_comment(
        self,
        commit_id: str,
        file_path: str,
        line: int,
        body: str,
        side: str = "RIGHT",
    ) -> bool:
        """Create a line-specific review comment on a file in the PR.

        Args:
            commit_id: The SHA of the commit to comment on
            file_path: The relative path to the file in the repo
            line: The line number in the file to comment on
            body: The comment text (markdown supported)
            side: Which side of the diff ("LEFT" for deletion, "RIGHT" for addition)

        Returns:
            True if successful, False otherwise
        """
        result = await self._make_request(
            "POST",
            f"pulls/{self.pr_number}/comments",
            json={
                "commit_id": commit_id,
                "path": file_path,
                "line": line,
                "side": side,
                "body": body,
            },
        )

        if result:
            logger.info(f"Successfully posted review comment on {file_path}:{line}")
            return True
        return False

    async def create_review_with_comments(
        self,
        comments: list[dict[str, Any]],
        body: str = "",
        event: ReviewEvent = ReviewEvent.COMMENT,
    ) -> bool:
        """Create a review with multiple line-specific comments.

        Args:
            comments: List of comment dicts with keys: path, line, body, (optional) side
            body: The overall review body text
            event: The review event type (APPROVE, REQUEST_CHANGES, COMMENT)

        Returns:
            True if successful, False otherwise

        Example:
            comments = [
                {
                    "path": "policies/policy.json",
                    "line": 5,
                    "body": "Invalid action detected here",
                },
                {
                    "path": "policies/policy.json",
                    "line": 12,
                    "body": "Missing condition key",
                },
            ]
        """
        # Get the latest commit SHA
        pr_info = await self.get_pr_info()
        if not pr_info:
            return False

        head_info = pr_info.get("head")
        if not isinstance(head_info, dict):
            logger.error("Invalid PR head information")
            return False

        commit_id = head_info.get("sha")
        if not isinstance(commit_id, str):
            logger.error("Could not get commit SHA from PR")
            return False

        # Format comments for the review API
        formatted_comments: list[dict[str, Any]] = []
        for comment in comments:
            formatted_comments.append(
                {
                    "path": comment["path"],
                    "line": comment["line"],
                    "body": comment["body"],
                    "side": comment.get("side", "RIGHT"),
                }
            )

        result = await self._make_request(
            "POST",
            f"pulls/{self.pr_number}/reviews",
            json={
                "commit_id": commit_id,
                "body": body,
                "event": event.value,
                "comments": formatted_comments,
            },
        )

        if result:
            logger.info(f"Successfully created review with {len(comments)} comments")
            return True
        return False

    async def update_or_create_review_comments(
        self,
        comments: list[dict[str, Any]],
        body: str = "",
        event: ReviewEvent = ReviewEvent.COMMENT,
        identifier: str = constants.REVIEW_IDENTIFIER,
        validated_files: set[str] | None = None,
        skip_cleanup: bool = False,
    ) -> bool:
        """Smart comment management using fingerprint-based matching.

        This method uses finding fingerprints (stable IDs) as the PRIMARY key
        for matching comments, with location as SECONDARY for new comments.

        Strategy:
        1. Index existing comments by finding_id (from HTML comment)
        2. For each new comment:
           - If finding_id exists: UPDATE (even if line changed)
           - If new: CREATE at specified line
        3. Delete comments whose finding_id is not in new set (resolved)
           (unless skip_cleanup=True)

        Note: Comments stay at their original line even if the issue moved,
        because GitHub doesn't support moving review comments. The comment
        body is updated to reflect any changes.

        Args:
            comments: List of comment dicts with keys: path, line, body, (optional) side
            body: The overall review body text
            event: The review event type (APPROVE, REQUEST_CHANGES, COMMENT)
            identifier: String to identify bot comments (for matching existing)
            validated_files: Set of all file paths that were validated in this run.
                           Used to clean up comments for files that no longer have findings.
                           If None, only files with current findings are considered.
            skip_cleanup: If True, skip the cleanup phase (deleting resolved comments).
                         Use this in streaming mode where files are processed one at a time
                         to avoid deleting comments from files processed earlier.

        Returns:
            True if successful, False otherwise

        Example:
            # First run: Creates 3 comments
            comments = [
                {"path": "policy.json", "line": 5, "body": "<!-- finding-id: abc123 -->Issue A"},
                {"path": "policy.json", "line": 10, "body": "<!-- finding-id: def456 -->Issue B"},
            ]

            # Second run: Same findings, even if lines shifted
            comments = [
                {"path": "policy.json", "line": 8, "body": "<!-- finding-id: abc123 -->Issue A (updated)"},
                {"path": "policy.json", "line": 15, "body": "<!-- finding-id: def456 -->Issue B"},
            ]
            # Result: Both comments UPDATED in place (not recreated), preserving conversation history
        """
        # Step 1: Get existing bot comments indexed by fingerprint
        existing_by_fingerprint = await self._get_bot_comments_by_fingerprint(identifier)
        logger.debug(
            f"Found {len(existing_by_fingerprint)} existing bot comments with fingerprints"
        )

        # Also get location-based index for fallback (comments without fingerprints)
        existing_by_location = await self.get_bot_review_comments_with_location(identifier)

        seen_fingerprints: set[str] = set()
        seen_locations: set[tuple[str, int, str]] = set()
        # Track comment IDs that were updated/matched - these should NOT be deleted
        matched_comment_ids: set[int] = set()
        updated_count = 0
        new_comments_for_review: list[dict[str, Any]] = []

        for comment in comments:
            path = comment["path"]
            line = comment["line"]
            new_body = comment["body"]

            # Try fingerprint-based matching first
            finding_id = self._extract_finding_id(new_body)

            if finding_id:
                seen_fingerprints.add(finding_id)

                if finding_id in existing_by_fingerprint:
                    existing = existing_by_fingerprint[finding_id]
                    matched_comment_ids.add(existing["id"])
                    # Check if update needed (body changed)
                    if existing["body"] != new_body:
                        success = await self.update_review_comment(existing["id"], new_body)
                        if success:
                            updated_count += 1
                            logger.debug(
                                f"Updated comment for finding {finding_id[:8]}... "
                                f"(was at {existing['path']}:{existing['line']})"
                            )
                    else:
                        logger.debug(f"Comment for finding {finding_id[:8]}... unchanged")
                    continue

            # Fallback: location-based matching
            # This handles both:
            # 1. Legacy comments without fingerprints
            # 2. Comments with fingerprints that don't match (e.g., path changed)
            issue_type_match = re.search(r"<!-- issue-type: (\w+) -->", new_body)
            issue_type = issue_type_match.group(1) if issue_type_match else "unknown"
            location = (path, line, issue_type)
            seen_locations.add(location)

            existing_loc = existing_by_location.get(location)
            if existing_loc:
                # Found existing comment at same location with same issue type
                # Update it (this handles both legacy comments and fingerprint mismatches)
                matched_comment_ids.add(existing_loc["id"])
                if existing_loc["body"] != new_body:
                    success = await self.update_review_comment(existing_loc["id"], new_body)
                    if success:
                        updated_count += 1
                        if finding_id:
                            logger.debug(
                                f"Updated comment at {path}:{line} (fingerprint mismatch, location match)"
                            )
                        else:
                            logger.debug(f"Updated legacy comment at {path}:{line}")
                continue

            # New comment - collect for batch creation
            new_comments_for_review.append(comment)

        # Step 2: Create new comments via review API (if any)
        created_count = 0
        if new_comments_for_review:
            success = await self.create_review_with_comments(
                new_comments_for_review,
                body=body,
                event=event,
            )
            if success:
                created_count = len(new_comments_for_review)
                logger.info(f"Created {created_count} new review comments")
            else:
                logger.error("Failed to create new review comments")
                return False

        # Step 3: Delete resolved comments (unless skip_cleanup is True)
        # In streaming mode, we skip cleanup because we're processing files one at a time
        # and don't want to delete comments from files processed earlier in the stream
        deleted_count = 0

        if skip_cleanup:
            logger.debug("Skipping cleanup phase (streaming mode)")
        else:
            # Priority: fingerprint-based deletion, then location-based for legacy
            # Also clean up comments for files removed from the PR or files that were
            # validated but no longer have findings
            files_with_findings = {c["path"] for c in comments}

            # Use validated_files if provided, otherwise fall back to files_with_findings
            # This ensures we clean up comments for files that were validated but have no findings
            files_in_scope = validated_files if validated_files is not None else files_with_findings

            # Get current PR files to detect removed files
            # Note: get_pr_files() returns [] on error, so we check for non-empty result
            pr_files = await self.get_pr_files()
            if pr_files:
                current_pr_files: set[str] | None = {f["filename"] for f in pr_files}
            else:
                # Empty result could be an API error - fall back to batch-only cleanup
                # to avoid accidentally deleting valid comments
                logger.debug("Could not fetch PR files for cleanup, using batch-only mode")
                current_pr_files = None

            def should_delete_comment(existing_path: str) -> bool:
                """Check if a comment should be deleted based on file status.

                A comment should be deleted if the file is part of this PR.
                The fingerprint check (done by caller) ensures we only delete
                comments for findings that are no longer present.

                This aggressive cleanup ensures stale comments are removed even if:
                - The file was fixed but not re-validated in this specific run
                - The validation runs on a subset of PR files

                We preserve comments for files NOT in the PR to avoid accidentally
                deleting comments from other branches/PRs.
                """
                # If we successfully fetched PR files, delete comments for any PR file
                # whose finding is no longer present (fingerprint check done by caller)
                if current_pr_files is not None:
                    return existing_path in current_pr_files

                # Fallback: if we couldn't fetch PR files, only clean up validated files
                # to avoid accidentally deleting valid comments
                return existing_path in files_in_scope

            # Collect all comment IDs to delete
            # Delete by fingerprint (primary) - comments that:
            # 1. Were NOT matched (updated) in this run
            # 2. Have a fingerprint not in the new findings
            # 3. Are in files that are part of this PR/validation
            comment_ids_to_delete: list[int] = []

            for fingerprint, existing in existing_by_fingerprint.items():
                comment_id = existing["id"]
                # Skip if this comment was matched/updated via location fallback
                if comment_id in matched_comment_ids:
                    continue
                if fingerprint not in seen_fingerprints and should_delete_comment(existing["path"]):
                    comment_ids_to_delete.append(comment_id)
                    logger.debug(f"Marking for deletion: resolved comment {fingerprint[:8]}...")

            # Delete by location (legacy comments without fingerprints)
            for location, existing in existing_by_location.items():
                comment_id = existing["id"]
                # Skip if already matched/updated
                if comment_id in matched_comment_ids:
                    continue
                # Skip if already marked for deletion by fingerprint above
                existing_fingerprint = self._extract_finding_id(existing.get("body", ""))
                if existing_fingerprint:
                    continue  # Already handled above

                if location not in seen_locations and should_delete_comment(existing["path"]):
                    comment_ids_to_delete.append(comment_id)
                    logger.debug(f"Marking for deletion: resolved legacy comment at {location}")

            # Delete all collected comments in parallel
            if comment_ids_to_delete:
                deleted_count, _failed = await self._delete_comments_parallel(comment_ids_to_delete)

        logger.info(
            f"Review comment management: {updated_count} updated, "
            f"{created_count} created, {deleted_count} deleted (resolved)"
        )

        # Step 4: If no new comments were created but we need to submit APPROVE/REQUEST_CHANGES,
        # submit a review without inline comments to update the PR review state.
        # This is important when all issues are ignored/resolved - we need to dismiss
        # the previous REQUEST_CHANGES review by submitting an APPROVE review.
        if not new_comments_for_review and event in (
            ReviewEvent.APPROVE,
            ReviewEvent.REQUEST_CHANGES,
        ):
            # Only submit if there's a meaningful state change to make
            # (submitting APPROVE when all issues are resolved/ignored)
            logger.info(f"Submitting {event.value} review (no inline comments)")
            success = await self.create_review_with_comments(
                comments=[],
                body=body,
                event=event,
            )
            if not success:
                logger.warning(f"Failed to submit {event.value} review")
                # Don't fail the whole operation - comments were managed successfully

        return True

    def _extract_finding_id(self, body: str) -> str | None:
        """Extract finding ID from comment body HTML comment.

        Args:
            body: Comment body text

        Returns:
            16-character finding ID hash, or None if not found
        """
        match = re.search(r"<!-- finding-id: ([a-f0-9]{16}) -->", body)
        return match.group(1) if match else None

    async def _get_bot_comments_by_fingerprint(self, identifier: str) -> dict[str, dict[str, Any]]:
        """Index existing bot comments by their finding fingerprint.

        Args:
            identifier: String to identify bot comments

        Returns:
            Dict mapping finding_id to comment metadata dict
            Comment dict contains: id, body, path, line
        """
        comments = await self.get_review_comments()
        indexed: dict[str, dict[str, Any]] = {}

        for comment in comments:
            if not isinstance(comment, dict):
                continue

            body = comment.get("body", "")
            if identifier not in str(body):
                continue

            finding_id = self._extract_finding_id(body)
            if finding_id:
                indexed[finding_id] = {
                    "id": comment["id"],
                    "body": body,
                    "path": comment.get("path", ""),
                    "line": comment.get("line") or comment.get("original_line"),
                }

        return indexed

    # ==================== PR Labels ====================

    async def add_labels(self, labels: list[str]) -> bool:
        """Add labels to the PR.

        Args:
            labels: List of label names to add

        Returns:
            True if successful, False otherwise
        """
        result = await self._make_request(
            "POST",
            f"issues/{self.pr_number}/labels",
            json={"labels": labels},
        )

        if result:
            logger.info(f"Successfully added labels: {', '.join(labels)}")
            return True
        return False

    async def remove_label(self, label: str) -> bool:
        """Remove a label from the PR.

        Args:
            label: Label name to remove

        Returns:
            True if successful, False otherwise
        """
        result = await self._make_request(
            "DELETE",
            f"issues/{self.pr_number}/labels/{label}",
        )

        if result is not None:  # DELETE returns empty dict on success
            logger.info(f"Successfully removed label: {label}")
            return True
        return False

    async def get_labels(self) -> list[str]:
        """Get all labels on the PR.

        Returns:
            List of label names
        """
        result = await self._make_request(
            "GET",
            f"issues/{self.pr_number}/labels",
        )

        if result and isinstance(result, list):
            labels: list[str] = []
            for label in result:
                if isinstance(label, dict):
                    name = label.get("name")
                    if isinstance(name, str):
                        labels.append(name)
            return labels
        return []

    async def set_labels(self, labels: list[str]) -> bool:
        """Set labels on the PR, replacing any existing labels.

        Args:
            labels: List of label names to set

        Returns:
            True if successful, False otherwise
        """
        result = await self._make_request(
            "PUT",
            f"issues/{self.pr_number}/labels",
            json={"labels": labels},
        )

        if result:
            logger.info(f"Successfully set labels: {', '.join(labels)}")
            return True
        return False

    # ==================== PR Information ====================

    async def get_pr_info(self) -> dict[str, Any] | None:
        """Get detailed information about the PR.

        Returns:
            PR information dict or None on error
        """
        return await self._make_request("GET", f"pulls/{self.pr_number}")

    async def get_pr_files(self) -> list[dict[str, Any]]:
        """Get list of files changed in the PR.

        Returns:
            List of file information dicts
        """
        result = await self._make_request("GET", f"pulls/{self.pr_number}/files")

        if result and isinstance(result, list):
            return result
        return []

    async def get_pr_commits(self) -> list[dict[str, Any]]:
        """Get list of commits in the PR.

        Returns:
            List of commit information dicts
        """
        result = await self._make_request("GET", f"pulls/{self.pr_number}/commits")

        if result and isinstance(result, list):
            return result
        return []

    # ==================== PR Status ====================

    async def set_commit_status(
        self,
        state: str,
        context: str,
        description: str,
        target_url: str | None = None,
    ) -> bool:
        """Set a commit status on the PR's head commit.

        Args:
            state: Status state ("error", "failure", "pending", "success")
            context: A string label to differentiate this status from others
            description: A short description of the status
            target_url: Optional URL to link to more details

        Returns:
            True if successful, False otherwise
        """
        pr_info = await self.get_pr_info()
        if not pr_info:
            return False

        head_info = pr_info.get("head")
        if not isinstance(head_info, dict):
            return False

        commit_sha = head_info.get("sha")
        if not isinstance(commit_sha, str):
            return False

        payload: dict[str, Any] = {
            "state": state,
            "context": context,
            "description": description,
        }
        if target_url:
            payload["target_url"] = target_url

        result = await self._make_request(
            "POST",
            f"statuses/{commit_sha}",
            json=payload,
        )

        if result:
            logger.info(f"Successfully set commit status: {state}")
            return True
        return False

    # ==================== CODEOWNERS and Ignore Commands ====================

    async def get_codeowners_content(self) -> str | None:
        """Fetch CODEOWNERS file content from repository.

        Results are cached per instance to avoid redundant API calls.

        Searches in standard CODEOWNERS locations:
        - CODEOWNERS
        - .github/CODEOWNERS
        - docs/CODEOWNERS

        Returns:
            CODEOWNERS file content as string, or None if not found
        """
        # Return cached result if already loaded
        if self._codeowners_loaded:
            return self._codeowners_cache

        from iam_validator.core.codeowners import (  # pylint: disable=import-outside-toplevel
            CodeOwnersParser,
        )

        for path in CodeOwnersParser.CODEOWNERS_PATHS:
            result = await self._make_request(
                "GET",
                f"contents/{path}",
            )

            if result and isinstance(result, dict) and "content" in result:
                try:
                    content = base64.b64decode(result["content"]).decode("utf-8")
                    logger.debug(f"Found CODEOWNERS at {path}")
                    # Cache the result
                    self._codeowners_cache = content
                    self._codeowners_loaded = True
                    return content
                except (ValueError, UnicodeDecodeError) as e:
                    logger.warning(f"Failed to decode CODEOWNERS at {path}: {e}")
                    continue

        logger.debug("No CODEOWNERS file found in repository")
        # Cache the negative result too
        self._codeowners_cache = None
        self._codeowners_loaded = True
        return None

    async def get_team_members(self, org: str, team_slug: str) -> list[str]:
        """Get members of a GitHub team.

        Results are cached per instance to avoid redundant API calls
        when checking multiple users against the same team.

        Note: This requires the token to have `read:org` scope for
        organization teams.

        Args:
            org: Organization name
            team_slug: Team slug (URL-friendly name)

        Returns:
            List of team member usernames (lowercase)
        """
        # Check cache first
        cache_key = (org.lower(), team_slug.lower())
        if cache_key in self._team_cache:
            logger.debug(f"Using cached team members for {org}/{team_slug}")
            return self._team_cache[cache_key]

        url = f"{self.api_url}/orgs/{org}/teams/{team_slug}/members"

        try:
            if self._client:
                response = await self._client.request("GET", url)
            else:
                async with httpx.AsyncClient(
                    headers=self._get_headers(), timeout=httpx.Timeout(30.0)
                ) as client:
                    response = await client.request("GET", url)

            response.raise_for_status()
            result = response.json()

            if isinstance(result, list):
                members = [
                    member.get("login", "").lower()
                    for member in result
                    if isinstance(member, dict) and member.get("login")
                ]
                # Cache the result
                self._team_cache[cache_key] = members
                logger.debug(f"Found {len(members)} members in team {org}/{team_slug}")
                return members

        except httpx.HTTPStatusError as e:
            logger.warning(
                f"Failed to get team members for {org}/{team_slug}: HTTP {e.response.status_code}"
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning(f"Failed to get team members for {org}/{team_slug}: {e}")

        # Cache empty result to avoid repeated failed API calls
        self._team_cache[cache_key] = []
        return []

    async def is_user_codeowner(
        self,
        username: str,
        file_path: str,
        codeowners_parser: "CodeOwnersParser | None" = None,
        allowed_users: list[str] | None = None,
    ) -> bool:
        """Check if a user is authorized to ignore findings for a file.

        Authorization is granted if:
        1. User is listed directly in CODEOWNERS for the file
        2. User is a member of a team listed in CODEOWNERS for the file
        3. User is in the allowed_users fallback list (when no CODEOWNERS)

        Performance: Team membership checks are executed in parallel.

        Args:
            username: GitHub username to check
            file_path: Path to the file being checked
            codeowners_parser: Pre-parsed CODEOWNERS (for caching)
            allowed_users: Fallback list of allowed users (when no CODEOWNERS)

        Returns:
            True if user is authorized, False otherwise
        """
        username_lower = username.lower()

        # Check fallback allowed_users first (always applies if configured)
        if allowed_users:
            if username_lower in [u.lower() for u in allowed_users]:
                logger.debug(f"User {username} authorized via allowed_users config")
                return True

        # Get or parse CODEOWNERS
        parser = codeowners_parser
        if parser is None:
            content = await self.get_codeowners_content()
            if content is None:
                # No CODEOWNERS and no allowed_users match = deny
                logger.debug(f"No CODEOWNERS file found, user {username} not in allowed_users")
                return False

            from iam_validator.core.codeowners import (  # pylint: disable=import-outside-toplevel
                CodeOwnersParser,
            )

            parser = CodeOwnersParser(content)

        # Check direct user ownership
        if parser.is_owner(username, file_path):
            logger.debug(f"User {username} is direct owner of {file_path}")
            return True

        # Check team membership - fetch all teams in parallel for speed
        teams = parser.get_teams_for_file(file_path)
        if not teams:
            logger.debug(f"User {username} is not authorized for {file_path}")
            return False

        # Fetch all team memberships concurrently

        async def check_team(org: str, team_slug: str) -> tuple[str, str, bool]:
            members = await self.get_team_members(org, team_slug)
            return (org, team_slug, username_lower in members)

        results = await asyncio.gather(*[check_team(org, team_slug) for org, team_slug in teams])

        for org, team_slug, is_member in results:
            if is_member:
                logger.debug(f"User {username} authorized via team {org}/{team_slug}")
                return True

        logger.debug(f"User {username} is not authorized for {file_path}")
        return False

    async def get_issue_comments(self) -> list[dict[str, Any]]:
        """Get all issue comments (general PR comments, not review comments) with pagination.

        Fetches ALL issue comments across all pages. This ensures proper
        comment management when there are many comments on a PR.

        Returns:
            List of all issue comment dicts
        """
        return await self._make_paginated_request(f"issues/{self.pr_number}/comments")

    async def get_comment_by_id(self, comment_id: int) -> dict[str, Any] | None:
        """Get a specific review comment by ID.

        Used for verifying that ignore command replies still exist
        (tamper-resistant verification).

        Args:
            comment_id: The ID of the review comment to fetch

        Returns:
            Comment dict if found, None if deleted or error
        """
        result = await self._make_request(
            "GET",
            f"pulls/comments/{comment_id}",
        )

        if result and isinstance(result, dict):
            return result
        return None

    async def post_reply_to_review_comment(
        self,
        comment_id: int,
        body: str,
    ) -> bool:
        """Post a reply to a review comment thread.

        Args:
            comment_id: The ID of the review comment to reply to
            body: The reply text (markdown supported)

        Returns:
            True if successful, False otherwise
        """
        result = await self._make_request(
            "POST",
            f"pulls/{self.pr_number}/comments",
            json={
                "body": body,
                "in_reply_to": comment_id,
            },
        )

        if result:
            logger.debug(f"Successfully posted reply to comment {comment_id}")
            return True
        return False

    async def scan_for_ignore_commands(
        self,
        identifier: str = constants.BOT_IDENTIFIER,
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        """Scan for ignore commands in replies to bot review comments.

        Looks for replies to bot comments that contain ignore commands.
        Supports formats: "ignore", "/ignore", "@iam-validator ignore",
        "skip", "suppress", and "ignore: reason here".

        Args:
            identifier: String to identify bot comments

        Returns:
            List of (bot_comment, reply_comment) tuples where reply
            contains an ignore command
        """
        all_comments = await self.get_review_comments()
        ignore_commands: list[tuple[dict[str, Any], dict[str, Any]]] = []

        # Index bot comments by ID for O(1) lookup
        bot_comments_by_id: dict[int, dict[str, Any]] = {}
        for comment in all_comments:
            if not isinstance(comment, dict):
                continue
            body = comment.get("body", "")
            comment_id = comment.get("id")
            if identifier in str(body) and isinstance(comment_id, int):
                bot_comments_by_id[comment_id] = comment

        # Find replies with ignore commands
        for comment in all_comments:
            if not isinstance(comment, dict):
                continue

            reply_to_id = comment.get("in_reply_to_id")
            if reply_to_id and reply_to_id in bot_comments_by_id:
                body = comment.get("body", "")
                if self._is_ignore_command(body):
                    ignore_commands.append((bot_comments_by_id[reply_to_id], comment))

        logger.debug(f"Found {len(ignore_commands)} ignore command(s) in PR comments")
        return ignore_commands

    def _is_ignore_command(self, text: str) -> bool:
        """Check if text is an ignore command.

        Supports:
        - "ignore" (case insensitive)
        - "/ignore"
        - "@iam-validator ignore"
        - "skip", "suppress"
        - "ignore: reason here" (with optional reason)

        Args:
            text: Comment text to check

        Returns:
            True if text is an ignore command
        """
        if not text:
            return False

        text = text.strip().lower()

        ignore_patterns = [
            r"^\s*ignore\s*$",
            r"^\s*/ignore\s*$",
            r"^\s*@?iam-validator\s+ignore\s*$",
            r"^\s*ignore\s*:\s*.+$",  # With reason
            r"^\s*skip\s*$",
            r"^\s*suppress\s*$",
        ]

        return any(re.match(pattern, text, re.IGNORECASE) for pattern in ignore_patterns)

    @staticmethod
    def extract_finding_id(comment_body: str) -> str | None:
        """Extract finding ID from a bot comment.

        Args:
            comment_body: The comment body text

        Returns:
            Finding ID hash, or None if not found
        """
        match = re.search(r"<!-- finding-id: ([a-f0-9]+) -->", comment_body)
        return match.group(1) if match else None

    @staticmethod
    def extract_ignore_reason(text: str) -> str | None:
        """Extract reason from ignore command.

        Args:
            text: The ignore command text

        Returns:
            Reason string, or None if no reason provided
        """
        match = re.search(r"ignore\s*:\s*(.+)$", text.strip(), re.IGNORECASE)
        return match.group(1).strip() if match else None

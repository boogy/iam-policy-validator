"""GitHub Integration Module.

This module provides functionality to interact with GitHub,
including posting PR comments, line comments, labels, and retrieving PR information.
"""

import logging
import os
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


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
        import re

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
        import re

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
        return all([self.token, self.repository, self.pr_number])

    async def _make_request(
        self, method: str, endpoint: str, **kwargs: Any
    ) -> dict[str, Any] | None:
        """Make an HTTP request to GitHub API.

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
        except Exception as e:
            logger.error(f"Request failed: {e}")
            return None

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

        This method will:
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

        # Delete all existing comments with this identifier
        await self._delete_comments_with_identifier(identifier)

        # Post each part
        success = True
        total_parts = len(comment_parts)

        for part_num, part_body in enumerate(comment_parts, 1):
            # Add identifier and part indicator
            part_indicator = f"**(Part {part_num}/{total_parts})**" if total_parts > 1 else ""
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
        """Get all review comments on the PR.

        Returns:
            List of review comment dicts
        """
        result = await self._make_request(
            "GET",
            f"pulls/{self.pr_number}/comments",
        )

        if result and isinstance(result, list):
            return result
        return []

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
            logger.info(f"Successfully deleted review comment {comment_id}")
            return True
        return False

    async def cleanup_bot_review_comments(self, identifier: str = "🤖 IAM Policy Validator") -> int:
        """Delete all review comments from the bot (from previous runs).

        This ensures old/outdated comments are removed before posting new ones.

        Args:
            identifier: String to identify bot comments

        Returns:
            Number of comments deleted
        """
        comments = await self.get_review_comments()
        deleted_count = 0

        for comment in comments:
            if not isinstance(comment, dict):
                continue

            body = comment.get("body", "")
            comment_id = comment.get("id")

            # Check if this is a bot comment
            if identifier in str(body) and isinstance(comment_id, int):
                if await self.delete_review_comment(comment_id):
                    deleted_count += 1

        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old review comments")

        return deleted_count

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

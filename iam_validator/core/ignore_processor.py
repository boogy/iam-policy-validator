"""Ignore command processor for CODEOWNERS-based finding suppression.

This module processes ignore commands from PR comments, validates
authorization via CODEOWNERS, and manages the ignored findings store.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from iam_validator.core.codeowners import CodeOwnersParser
from iam_validator.core.ignored_findings import IgnoredFinding, IgnoredFindingsStore

if TYPE_CHECKING:
    from iam_validator.integrations.github_integration import GitHubIntegration

logger = logging.getLogger(__name__)


class IgnoreCommandProcessor:
    """Processes ignore commands from PR comments.

    This processor:
    1. Scans for replies to bot comments containing "ignore"
    2. Verifies the replier is a CODEOWNER for the affected file
    3. Adds authorized ignores to the ignored findings store
    4. Posts denial replies for unauthorized attempts

    Authorization flow:
    1. Check if user is in allowed_users config (always applies)
    2. Check if user is directly listed in CODEOWNERS for the file
    3. Check if user is a member of a team listed in CODEOWNERS

    If no CODEOWNERS file exists and allowed_users is empty, all
    ignore requests are denied (fail secure).
    """

    def __init__(
        self,
        github: GitHubIntegration,
        allowed_users: list[str] | None = None,
        post_denial_feedback: bool = False,
    ) -> None:
        """Initialize the processor.

        Args:
            github: GitHub integration instance
            allowed_users: Fallback list of users who can ignore findings
                          (used when CODEOWNERS is not available)
            post_denial_feedback: Whether to post visible replies on denied ignores
        """
        self.github = github
        self.allowed_users = allowed_users or []
        self.post_denial_feedback = post_denial_feedback
        self.store = IgnoredFindingsStore(github)
        self._codeowners_parser: CodeOwnersParser | None = None
        self._codeowners_loaded = False
        # Cache for authorization results: (username, file_path) -> bool
        self._auth_cache: dict[tuple[str, str], bool] = {}
        # Cache for team memberships: (org, team) -> list[str]
        self._team_cache: dict[tuple[str, str], list[str]] = {}

    async def process_pending_ignores(self) -> int:
        """Process all pending ignore commands.

        Scans PR comments for ignore commands, validates authorization,
        and adds to the ignored findings store.

        Performance: Uses batch mode to save all findings in a single
        GitHub API call instead of one per finding.

        Returns:
            Number of findings newly ignored
        """
        # Early exit: scan for ignore commands first
        ignore_commands = await self.github.scan_for_ignore_commands()

        if not ignore_commands:
            logger.debug("No ignore commands found")
            return 0

        logger.info(f"Processing {len(ignore_commands)} ignore command(s)")

        # Load CODEOWNERS lazily (only if we have commands to process)
        await self._load_codeowners()

        # Collect all valid findings first, then save in batch
        findings_to_add: list[IgnoredFinding] = []

        for bot_comment, reply in ignore_commands:
            finding = await self._process_single_ignore(bot_comment, reply)
            if finding:
                findings_to_add.append(finding)

        # Batch save all findings in one API call
        if findings_to_add:
            success = await self.store.add_ignored_batch(findings_to_add)
            if success:
                logger.info(f"Successfully ignored {len(findings_to_add)} finding(s)")
            else:
                logger.warning("Failed to save ignored findings")
                return 0

        return len(findings_to_add)

    async def _process_single_ignore(
        self,
        bot_comment: dict[str, Any],
        reply: dict[str, Any],
    ) -> IgnoredFinding | None:
        """Process a single ignore command.

        Args:
            bot_comment: The bot comment being replied to
            reply: The reply comment with ignore command

        Returns:
            IgnoredFinding if valid and authorized, None otherwise
        """
        # Extract required information
        finding_id = self.github.extract_finding_id(bot_comment.get("body", ""))
        file_path = bot_comment.get("path", "")
        replier = reply.get("user", {}).get("login", "")
        reply_body = reply.get("body", "")

        if not finding_id:
            logger.debug("Ignore command reply missing finding ID in bot comment")
            return None

        if not file_path:
            logger.debug("Ignore command reply missing file path")
            return None

        if not replier:
            logger.debug("Ignore command reply missing user")
            return None

        # Check if already ignored
        if await self.store.is_ignored(finding_id):
            logger.debug(f"Finding {finding_id} already ignored")
            return None

        # Check authorization (with caching)
        is_authorized = await self._is_authorized(replier, file_path)

        if not is_authorized:
            logger.info(f"Denied ignore from {replier} for {file_path} - not authorized")
            await self._post_denial(reply, replier, file_path)
            return None

        # Extract metadata from bot comment
        check_id = self._extract_check_id(bot_comment.get("body", ""))
        issue_type = self._extract_issue_type(bot_comment.get("body", ""))
        reason = self.github.extract_ignore_reason(reply_body)

        # Create the ignored finding (will be saved in batch)
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        finding = IgnoredFinding(
            finding_id=finding_id,
            file_path=file_path,
            check_id=check_id,
            issue_type=issue_type,
            ignored_by=replier,
            ignored_at=now,
            reason=reason,
            reply_comment_id=reply.get("id"),  # Store for tamper verification
        )

        logger.debug(f"Prepared ignored finding {finding_id} by {replier}")
        return finding

    async def _load_codeowners(self) -> None:
        """Load and cache CODEOWNERS file."""
        if self._codeowners_loaded:
            return

        content = await self.github.get_codeowners_content()
        if content:
            self._codeowners_parser = CodeOwnersParser(content)
            logger.debug("Loaded CODEOWNERS file")
        else:
            logger.debug("No CODEOWNERS file found")

        self._codeowners_loaded = True

    async def _is_authorized(self, username: str, file_path: str) -> bool:
        """Check if user is authorized to ignore findings for a file.

        Uses caching to avoid repeated API calls.

        Args:
            username: GitHub username
            file_path: Path to the file

        Returns:
            True if authorized
        """
        cache_key = (username.lower(), file_path)
        if cache_key in self._auth_cache:
            return self._auth_cache[cache_key]

        result = await self.github.is_user_codeowner(
            username=username,
            file_path=file_path,
            codeowners_parser=self._codeowners_parser,
            allowed_users=self.allowed_users,
        )

        self._auth_cache[cache_key] = result
        return result

    async def _post_denial(
        self,
        reply: dict[str, Any],
        username: str,
        file_path: str,
    ) -> None:
        """Post a reply explaining why the ignore was denied.

        Posts a visible reply to the user if post_denial_feedback is enabled,
        otherwise only logs the denial.

        Args:
            reply: The reply comment that was denied
            username: User who tried to ignore
            file_path: File path they tried to ignore
        """
        if self.post_denial_feedback:
            message = (
                f"@{username} You are not authorized to ignore findings for `{file_path}`. "
                f"Only CODEOWNERS or users in `allowed_users` can ignore findings."
            )
            try:
                await self.github.post_reply_to_review_comment(reply["id"], message)
            except Exception as e:
                logger.warning(f"Failed to post denial feedback: {e}")

        logger.warning(
            f"Ignore request denied: @{username} is not authorized "
            f"for {file_path} (not in CODEOWNERS or allowed_users)"
        )

    def _extract_check_id(self, body: str) -> str:
        """Extract check ID from bot comment body.

        Args:
            body: Comment body text

        Returns:
            Check ID or empty string
        """
        match = re.search(r"\*Check: `([^`]+)`\*", body)
        return match.group(1) if match else ""

    def _extract_issue_type(self, body: str) -> str:
        """Extract issue type from bot comment body.

        Args:
            body: Comment body text

        Returns:
            Issue type or empty string
        """
        match = re.search(r"<!-- issue-type: (\w+) -->", body)
        return match.group(1) if match else ""


async def filter_ignored_findings(
    github: GitHubIntegration,
    findings: list[tuple[str, Any]],  # List of (file_path, ValidationIssue)
) -> tuple[list[tuple[str, Any]], frozenset[str]]:
    """Filter out ignored findings from a list.

    This is a convenience function for filtering findings before
    determining exit code or posting comments.

    Args:
        github: GitHub integration instance
        findings: List of (file_path, issue) tuples

    Returns:
        Tuple of (filtered_findings, ignored_ids)
    """
    from iam_validator.core.finding_fingerprint import FindingFingerprint

    store = IgnoredFindingsStore(github)
    ignored_ids = await store.get_ignored_ids()

    if not ignored_ids:
        return findings, frozenset()

    filtered: list[tuple[str, Any]] = []
    for file_path, issue in findings:
        fingerprint = FindingFingerprint.from_issue(issue, file_path)
        finding_id = fingerprint.to_hash()

        if finding_id not in ignored_ids:
            filtered.append((file_path, issue))
        else:
            logger.debug(f"Filtered out ignored finding {finding_id}")

    filtered_count = len(findings) - len(filtered)
    if filtered_count > 0:
        logger.info(f"Filtered out {filtered_count} ignored finding(s)")

    return filtered, ignored_ids

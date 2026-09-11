"""Ignored findings storage for PR-scoped ignores.

This module manages persistent storage of ignored findings via a hidden
PR comment. Ignored findings are stored as JSON in a comment that
persists with the PR lifecycle.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from iam_validator.core import constants

if TYPE_CHECKING:
    from iam_validator.integrations.github_integration import GitHubIntegration

logger = logging.getLogger(__name__)

# Storage format version for future compatibility
STORAGE_VERSION = 1


@dataclass(slots=True)
class IgnoredFinding:
    """Record of an ignored finding.

    Attributes:
        finding_id: Unique hash identifying the finding
        file_path: Path to the policy file
        check_id: Check that generated the finding
        issue_type: Type of issue
        ignored_by: Username who ignored the finding
        ignored_at: ISO timestamp when ignored
        reason: Optional reason provided by the user
        reply_comment_id: ID of the reply comment for tamper verification
    """

    finding_id: str
    file_path: str
    check_id: str
    issue_type: str
    ignored_by: str
    ignored_at: str
    reason: str | None = None
    reply_comment_id: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IgnoredFinding:
        """Create IgnoredFinding from dictionary.

        Args:
            data: Dictionary with finding data

        Returns:
            IgnoredFinding instance
        """
        return cls(
            finding_id=data.get("finding_id", ""),
            file_path=data.get("file_path", ""),
            check_id=data.get("check_id", ""),
            issue_type=data.get("issue_type", ""),
            ignored_by=data.get("ignored_by", ""),
            ignored_at=data.get("ignored_at", ""),
            reason=data.get("reason"),
            reply_comment_id=data.get("reply_comment_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation
        """
        return asdict(self)


class IgnoredFindingsStore:
    """Manages persistent storage of ignored findings via PR comment.

    Storage is implemented as a hidden PR comment with JSON payload.
    The comment is automatically created, updated, and managed.

    Example storage format:
        <!-- iam-policy-validator-ignored-findings -->
        <!-- DO NOT EDIT: This comment tracks ignored validation findings -->

        ```json
        {
          "version": 1,
          "ignored_findings": [
            {
              "finding_id": "abc123...",
              "file_path": "policies/admin.json",
              "check_id": "sensitive_action",
              "ignored_by": "username",
              "ignored_at": "2024-01-15T10:30:00Z",
              "reason": "Approved by security team"
            }
          ]
        }
        ```
    """

    def __init__(self, github: GitHubIntegration, comment_tag: str | None = None) -> None:
        """Initialize the store.

        Args:
            github: GitHub integration instance
            comment_tag: Optional run scope. When set, the storage marker is
                scoped via :func:`iam_validator.core.constants.scoped_marker`
                so concurrent runs (e.g. one per policy type) maintain
                independent ignore stores instead of overwriting each other.
        """
        self.github = github
        self._cache: dict[str, IgnoredFinding] | None = None
        self._comment_id: int | None = None
        self._marker = constants.scoped_marker(constants.IGNORED_FINDINGS_IDENTIFIER, comment_tag)

    async def load(self) -> dict[str, IgnoredFinding]:
        """Load ignored findings from PR comment.

        Returns cached data if available, otherwise fetches from GitHub.

        Returns:
            Dictionary mapping finding_id to IgnoredFinding
        """
        if self._cache is not None:
            return self._cache

        comment = await self._find_storage_comment()
        if not comment:
            self._cache = {}
            return self._cache

        self._comment_id = comment.get("id")
        body = comment.get("body", "")
        data = self._parse_comment(body)

        self._cache = {}
        for finding_data in data.get("ignored_findings", []):
            try:
                finding = IgnoredFinding.from_dict(finding_data)
                self._cache[finding.finding_id] = finding
            except (KeyError, TypeError) as e:
                logger.warning(f"Failed to parse ignored finding: {e}")

        logger.debug(f"Loaded {len(self._cache)} ignored finding(s) from storage")
        return self._cache

    async def save(self) -> bool:
        """Save current ignored findings to PR comment.

        Creates a new comment if none exists, or updates the existing one.

        Returns:
            True if save was successful
        """
        if self._cache is None:
            self._cache = {}

        body = self._format_comment(self._cache)

        if self._comment_id:
            # Update existing comment
            # TODO: Replace with public method once GitHubIntegration exposes
            # a public update_comment(comment_id, body) method.
            result = await self.github._update_comment(self._comment_id, body)  # noqa: SLF001
            if result:
                logger.debug("Updated ignored findings storage comment")
                return True
            logger.warning("Failed to update ignored findings storage comment")
            return False
        else:
            # Create new comment
            result = await self.github.post_comment(body)
            if result:
                # Find the comment ID for future updates
                comment = await self._find_storage_comment()
                if comment:
                    self._comment_id = comment.get("id")
                logger.debug("Created ignored findings storage comment")
                return True
            logger.warning("Failed to create ignored findings storage comment")
            return False

    async def add_ignored(self, finding: IgnoredFinding) -> bool:
        """Add a finding to the ignored list.

        Args:
            finding: The finding to ignore

        Returns:
            True if successfully added and saved
        """
        findings = await self.load()
        findings[finding.finding_id] = finding
        self._cache = findings
        return await self.save()

    async def add_ignored_batch(self, new_findings: list[IgnoredFinding]) -> bool:
        """Add multiple findings to the ignored list in a single save.

        More efficient than calling add_ignored() multiple times as it
        only makes one GitHub API call to update the storage comment.

        Args:
            new_findings: List of findings to ignore

        Returns:
            True if successfully added and saved
        """
        if not new_findings:
            return True

        findings = await self.load()
        for finding in new_findings:
            findings[finding.finding_id] = finding
        self._cache = findings
        return await self.save()

    async def is_ignored(self, finding_id: str) -> bool:
        """Check if a finding is ignored.

        Args:
            finding_id: The finding ID hash to check

        Returns:
            True if the finding is in the ignored list
        """
        findings = await self.load()
        return finding_id in findings

    async def get_ignored_ids(self) -> frozenset[str]:
        """Get all ignored finding IDs as a frozenset.

        Returns a frozenset for O(1) membership checking and immutability.

        Returns:
            Frozenset of ignored finding IDs
        """
        findings = await self.load()
        return frozenset(findings.keys())

    async def remove_ignored(self, finding_id: str) -> bool:
        """Remove a finding from the ignored list.

        Args:
            finding_id: The finding ID hash to remove

        Returns:
            True if successfully removed and saved
        """
        findings = await self.load()
        if finding_id in findings:
            del findings[finding_id]
            self._cache = findings
            return await self.save()
        return False

    async def prune_resolved(
        self,
        live_finding_ids: frozenset[str] | set[str],
        validated_files: set[str],
    ) -> int:
        """Drop ignore records whose finding no longer exists.

        An ignore record is only meaningful while the finding it silences is
        still being reported. Once the policy is fixed the record is dead
        weight: it keeps inflating the "Ignored Findings" count and table in
        the PR summary long after the underlying issue is gone.

        Pruning is scoped to ``validated_files``. A run that covers a subset
        of the repository's policies (streaming per-file passes, or a workflow
        driven by a changed-files list) has no evidence about findings in
        files it never looked at, so records for those files are kept.

        Args:
            live_finding_ids: Finding IDs reported by the current run, for
                every issue in the validated files regardless of whether the
                issue is itself ignored.
            validated_files: Relative paths of the policy files this run
                actually validated.

        Returns:
            Number of records removed (0 means nothing was saved).
        """
        if not validated_files:
            return 0

        findings = await self.load()
        stale_ids = [
            finding_id
            for finding_id, finding in findings.items()
            if finding.file_path in validated_files and finding_id not in live_finding_ids
        ]
        if not stale_ids:
            return 0

        # Keep the pre-prune snapshot so a failed save leaves the in-memory
        # store agreeing with what GitHub still holds; the next run retries.
        original = dict(findings)
        for finding_id in stale_ids:
            logger.info(
                f"Pruning ignore record for resolved finding {finding_id[:8]}... "
                f"({findings[finding_id].file_path}: {findings[finding_id].issue_type})"
            )
            del findings[finding_id]

        self._cache = findings
        if not await self.save():
            logger.warning("Failed to save pruned ignored findings storage")
            self._cache = original
            return 0
        return len(stale_ids)

    async def _find_storage_comment(self) -> dict[str, Any] | None:
        """Find the storage comment on the PR.

        Returns:
            Comment dict if found, None otherwise
        """
        comments = await self.github.get_issue_comments()

        for comment in comments:
            if not isinstance(comment, dict):
                continue
            body = comment.get("body", "")
            # Anchored match: the store always writes its marker on the
            # first line, so a comment merely containing (or forging) the
            # marker deeper in its body cannot hijack the ignore store.
            if constants.body_has_anchored_marker(str(body), self._marker):
                return comment

        return None

    def _parse_comment(self, body: str) -> dict[str, Any]:
        """Extract JSON data from comment body.

        Args:
            body: Comment body text

        Returns:
            Parsed JSON data or empty default structure
        """
        # Look for JSON code block
        match = re.search(r"```json\n(.*?)\n```", body, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
                # Validate version
                if data.get("version", 0) > STORAGE_VERSION:
                    logger.warning(
                        f"Storage version {data.get('version')} is newer than supported version {STORAGE_VERSION}"
                    )
                return data
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse ignored findings JSON: {e}")

        return {"version": STORAGE_VERSION, "ignored_findings": []}

    def _format_comment(self, findings: dict[str, IgnoredFinding]) -> str:
        """Format findings as a storage comment.

        Args:
            findings: Dictionary of ignored findings

        Returns:
            Formatted comment body
        """
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        data = {
            "version": STORAGE_VERSION,
            "ignored_findings": [f.to_dict() for f in findings.values()],
        }

        json_str = json.dumps(data, indent=2, sort_keys=True)

        return f"""{self._marker}
<!-- DO NOT EDIT: This comment tracks ignored validation findings -->
<!-- Last updated: {now} -->
<!-- Findings can be ignored by CODEOWNERS replying "ignore" to validation comments -->

<details>
<summary>📋 Ignored Findings ({len(findings)})</summary>

```json
{json_str}
```

</details>
"""

    def invalidate_cache(self) -> None:
        """Invalidate the cache to force reload on next access."""
        self._cache = None
        self._comment_id = None

    def verify_ignored_findings(self, comment_authors: Mapping[int, str]) -> list[str]:
        """Find ignore records whose reply comment no longer backs them.

        An ignore is only as good as the reply that requested it: the record
        is trusted because an authorized user wrote "ignore" in a specific
        comment. If that comment is gone the ignore was revoked, and if it is
        now authored by someone else the stored ``ignored_by`` is a forgery —
        which is what stops a hand-edited storage comment from silencing
        findings on someone else's authority.

        Pure and synchronous: the caller supplies the full comment→author map
        so this costs no API calls, however many records are stored.

        Args:
            comment_authors: Login by review comment id for the whole PR, as
                returned by ``get_review_comment_authors()``. Must be complete
                — a partial map would read missing entries as deletions.

        Returns:
            Finding IDs that no longer verify and should be removed.
        """
        invalid_ids: list[str] = []
        # Reads the loaded cache; call load() (or remove_invalid_findings,
        # which does) before this, or there is nothing to verify.
        findings = self._cache or {}

        for finding_id, finding in findings.items():
            if not finding.reply_comment_id:
                # Legacy record predating reply tracking - nothing to verify
                continue

            author = comment_authors.get(finding.reply_comment_id)
            if author is None:
                logger.warning(
                    f"Reply comment {finding.reply_comment_id} for finding {finding_id} is gone - ignore revoked"
                )
                invalid_ids.append(finding_id)
                continue

            if author.lower() != finding.ignored_by.lower():
                logger.warning(
                    f"Author mismatch for finding {finding_id}: stored={finding.ignored_by}, actual={author}"
                )
                invalid_ids.append(finding_id)

        if invalid_ids:
            logger.info(f"Found {len(invalid_ids)} ignore record(s) that no longer verify")

        return invalid_ids

    async def remove_invalid_findings(self, comment_authors: Mapping[int, str] | None) -> int:
        """Drop ignore records that no longer verify against their reply.

        Args:
            comment_authors: Login by review comment id for the whole PR, or
                ``None`` when that listing could not be fetched. ``None`` is a
                no-op: without a complete map every record would look deleted,
                so a transient API failure must never revoke a valid ignore.

        Returns:
            Number of records removed (0 means nothing was saved).
        """
        if comment_authors is None:
            logger.debug("Skipping ignore verification - review comment listing unavailable")
            return 0

        findings = await self.load()
        if not findings:
            return 0

        invalid_ids = self.verify_ignored_findings(comment_authors)
        if not invalid_ids:
            return 0

        # Keep the pre-removal snapshot so a failed save leaves the in-memory
        # store agreeing with what GitHub still holds; the next run retries.
        original = dict(findings)
        for finding_id in invalid_ids:
            del findings[finding_id]

        self._cache = findings
        if not await self.save():
            logger.warning("Failed to save verified ignored findings storage")
            self._cache = original
            return 0

        logger.info(f"Removed {len(invalid_ids)} ignore record(s) that no longer verify")
        return len(invalid_ids)

"""PR Comment Module.

This module handles posting validation findings as PR comments.
It reads a JSON report and posts line-specific comments to GitHub PRs.
"""

import json
import logging
from typing import Any

from iam_validator.core.constants import (
    BOT_IDENTIFIER,
    REVIEW_IDENTIFIER,
    SUMMARY_IDENTIFIER,
)
from iam_validator.core.diff_parser import DiffParser
from iam_validator.core.label_manager import LabelManager
from iam_validator.core.models import ValidationIssue, ValidationReport
from iam_validator.core.policy_loader import PolicyLineMap, PolicyLoader
from iam_validator.core.report import IgnoredFindingInfo, ReportGenerator
from iam_validator.integrations.github_integration import GitHubIntegration, ReviewEvent

logger = logging.getLogger(__name__)


class ContextIssue:
    """Represents an issue in a modified statement but on an unchanged line.

    These issues are shown in the summary comment rather than as inline comments,
    since GitHub only allows comments on lines that appear in the PR diff.
    """

    def __init__(
        self,
        file_path: str,
        statement_index: int,
        line_number: int,
        issue: ValidationIssue,
    ):
        """Initialize context issue.

        Args:
            file_path: Relative path to the file
            statement_index: Zero-based statement index
            line_number: Line number where the issue exists
            issue: The validation issue
        """
        self.file_path = file_path
        self.statement_index = statement_index
        self.line_number = line_number
        self.issue = issue


class PRCommenter:
    """Posts validation findings as PR comments."""

    # Load identifiers from constants module for consistency
    BOT_IDENTIFIER = BOT_IDENTIFIER
    SUMMARY_IDENTIFIER = SUMMARY_IDENTIFIER
    REVIEW_IDENTIFIER = REVIEW_IDENTIFIER

    def __init__(
        self,
        github: GitHubIntegration | None = None,
        cleanup_old_comments: bool = True,
        fail_on_severities: list[str] | None = None,
        severity_labels: dict[str, str | list[str]] | None = None,
        enable_codeowners_ignore: bool = True,
        allowed_ignore_users: list[str] | None = None,
    ):
        """Initialize PR commenter.

        Args:
            github: GitHubIntegration instance (will create one if None)
            cleanup_old_comments: Whether to clean up old bot comments after posting new ones.
                                 Set to False in streaming mode where files are processed one at a time
                                 to avoid deleting comments from files processed earlier.
            fail_on_severities: List of severity levels that should trigger REQUEST_CHANGES
                               (e.g., ["error", "critical", "high"])
            severity_labels: Mapping of severity levels to label name(s) for automatic label management
                           Supports both single labels and lists of labels per severity.
                           Examples:
                             - Single: {"error": "iam-validity-error", "critical": "security-critical"}
                             - Multiple: {"error": ["iam-error", "needs-fix"], "critical": ["security-critical", "needs-review"]}
                             - Mixed: {"error": "iam-validity-error", "critical": ["security-critical", "needs-review"]}
            enable_codeowners_ignore: Whether to enable CODEOWNERS-based ignore feature
            allowed_ignore_users: Fallback users who can ignore findings when no CODEOWNERS
        """
        self.github = github
        self.cleanup_old_comments = cleanup_old_comments
        self.fail_on_severities = fail_on_severities or ["error", "critical"]
        self.severity_labels = severity_labels or {}
        self.enable_codeowners_ignore = enable_codeowners_ignore
        self.allowed_ignore_users = allowed_ignore_users or []
        # Track issues in modified statements that are on unchanged lines
        self._context_issues: list[ContextIssue] = []
        # Track ignored finding IDs for the current run
        self._ignored_finding_ids: frozenset[str] = frozenset()
        # Store full ignored findings for display in summary
        self._ignored_findings: dict[str, Any] = {}
        # Cache for PolicyLineMap per file (for field-level line detection)
        self._policy_line_maps: dict[str, PolicyLineMap] = {}

    async def post_findings_to_pr(
        self,
        report: ValidationReport,
        create_review: bool = True,
        add_summary_comment: bool = True,
        manage_labels: bool = True,
        process_ignores: bool = True,
    ) -> bool:
        """Post validation findings to a PR.

        Args:
            report: Validation report with findings
            create_review: Whether to create a PR review with line comments
            add_summary_comment: Whether to add a summary comment
            manage_labels: Whether to manage PR labels based on severity findings
            process_ignores: Whether to process pending ignore commands

        Returns:
            True if successful, False otherwise
        """
        if self.github is None:
            self.github = GitHubIntegration()

        if not self.github.is_configured():
            logger.error(
                "GitHub integration not configured. "
                "Required: GITHUB_TOKEN, GITHUB_REPOSITORY, and GITHUB_PR_NUMBER environment variables. "
                "Ensure your workflow is triggered by a pull_request event."
            )
            return False

        success = True

        # Process pending ignore commands first (if enabled)
        if process_ignores and self.enable_codeowners_ignore:
            await self._process_ignore_commands()

        # Load ignored findings for filtering
        if self.enable_codeowners_ignore:
            await self._load_ignored_findings()

        # Note: Cleanup is now handled smartly by update_or_create_review_comments()
        # It will update existing comments, create new ones, and delete resolved ones

        # Post line-specific review comments FIRST
        # (This populates self._context_issues)
        if create_review:
            if not await self._post_review_comments(report):
                logger.error("Failed to post review comments")
                success = False

        # Post summary comment (potentially as multiple parts)
        if add_summary_comment:
            generator = ReportGenerator()
            # Pass ignored count to show in summary
            ignored_count = len(self._ignored_finding_ids) if self._ignored_finding_ids else 0

            # Convert ignored findings to IgnoredFindingInfo for display
            ignored_findings_info: list[IgnoredFindingInfo] = []
            if self._ignored_findings:
                for finding in self._ignored_findings.values():
                    ignored_findings_info.append(
                        IgnoredFindingInfo(
                            file_path=finding.file_path,
                            issue_type=finding.issue_type,
                            ignored_by=finding.ignored_by,
                            reason=finding.reason,
                        )
                    )

            # Determine if all blocking issues are ignored
            all_blocking_ignored = self._are_all_blocking_issues_ignored(report)

            comment_parts = generator.generate_github_comment_parts(
                report,
                ignored_count=ignored_count,
                ignored_findings=ignored_findings_info if ignored_findings_info else None,
                all_blocking_ignored=all_blocking_ignored,
            )

            # Post all parts using the multipart method
            if not await self.github.post_multipart_comments(
                comment_parts, self.SUMMARY_IDENTIFIER
            ):
                logger.error("Failed to post summary comment(s)")
                success = False
            else:
                if len(comment_parts) > 1:
                    logger.info(f"Posted summary in {len(comment_parts)} parts")
                else:
                    logger.info("Posted summary comment")

        # Manage PR labels based on severity findings
        if manage_labels and self.severity_labels:
            label_manager = LabelManager(self.github, self.severity_labels)

            # Create a filter function that uses relative paths for ignored finding lookup
            def is_issue_ignored_for_labels(issue: ValidationIssue, file_path: str) -> bool:
                relative_path = self._make_relative_path(file_path)
                if not relative_path:
                    return False
                return self._is_issue_ignored(issue, relative_path)

            label_success, added, removed = await label_manager.manage_labels_from_report(
                report, is_issue_ignored=is_issue_ignored_for_labels
            )

            if not label_success:
                logger.error("Failed to manage PR labels")
                success = False
            else:
                if added > 0 or removed > 0:
                    logger.info(f"Label management: added {added}, removed {removed}")

        return success

    async def _post_review_comments(self, report: ValidationReport) -> bool:
        """Post line-specific review comments with strict diff filtering.

        Only posts comments on lines that were actually changed in the PR.
        Issues in modified statements but on unchanged lines are tracked in
        self._context_issues for inclusion in the summary comment.

        Args:
            report: Validation report

        Returns:
            True if successful, False otherwise
        """
        if not self.github:
            return False

        # Clear context issues from previous runs
        self._context_issues = []

        # Fetch PR diff information
        logger.info("Fetching PR diff information for strict filtering...")
        pr_files = await self.github.get_pr_files()
        if not pr_files:
            logger.warning(
                "Could not fetch PR diff information. "
                "Falling back to unfiltered commenting (may fail if lines not in diff)."
            )
            parsed_diffs = {}
        else:
            parsed_diffs = DiffParser.parse_pr_files(pr_files)
            # Use warning level for diagnostics to ensure visibility
            logger.warning(
                f"[DIFF] Parsed diffs for {len(parsed_diffs)} file(s): {list(parsed_diffs.keys())}"
            )

        # Collect ALL validated files (for cleanup of resolved findings)
        # This includes files with no issues - we need to track them so stale comments get deleted
        validated_files: set[str] = set()
        for result in report.results:
            relative_path = self._make_relative_path(result.policy_file)
            if relative_path:
                validated_files.add(relative_path)

        logger.debug(f"Tracking {len(validated_files)} validated files for comment cleanup")

        # Group issues by file
        inline_comments: list[dict[str, Any]] = []
        context_issue_count = 0

        for result in report.results:
            if not result.issues:
                continue

            # Convert absolute path to relative path for GitHub
            relative_path = self._make_relative_path(result.policy_file)
            if not relative_path:
                logger.warning(
                    f"Could not determine relative path for {result.policy_file}, skipping review comments"
                )
                continue

            # Use warning level for path diagnostics to ensure visibility
            logger.warning(f"[PATH] Processing: {result.policy_file} -> '{relative_path}'")

            # Get diff info for this file
            diff_info = parsed_diffs.get(relative_path)
            if not diff_info:
                # Log ALL available paths to help diagnose path mismatches
                all_paths = list(parsed_diffs.keys())
                logger.warning(
                    f"'{relative_path}' not found in PR diff. "
                    f"Available paths ({len(all_paths)}): {all_paths}"
                )
                # Check for partial matches to help diagnose
                for avail_path in all_paths:
                    if relative_path.endswith(avail_path.split("/")[-1]):
                        logger.warning(
                            f"  Possible match by filename: '{avail_path}' "
                            f"(basename matches '{relative_path.split('/')[-1]}')"
                        )
                # Still process issues for summary (excluding ignored)
                for issue in result.issues:
                    # Skip ignored issues
                    if self._is_issue_ignored(issue, relative_path):
                        continue
                    if issue.statement_index is not None:
                        line_num = self._find_issue_line(
                            issue, result.policy_file, self._get_line_mapping(result.policy_file)
                        )
                        if line_num:
                            self._context_issues.append(
                                ContextIssue(relative_path, issue.statement_index, line_num, issue)
                            )
                            context_issue_count += 1
                continue

            # Get line mapping and modified statements for this file
            line_mapping = self._get_line_mapping(result.policy_file)
            modified_statements = DiffParser.get_modified_statements(
                line_mapping, diff_info.changed_lines, result.policy_file
            )

            # Check if this file has no patch (large file or GitHub truncated the diff)
            # In this case, we allow inline comments on any line since the file is in the PR
            allow_all_lines = diff_info.status.endswith("_no_patch")
            if allow_all_lines:
                logger.warning(
                    f"[MATCH] {relative_path}: No patch available (status={diff_info.status}), "
                    "allowing inline comments on any line"
                )
            else:
                logger.warning(
                    f"[MATCH] {relative_path}: FOUND in diff with {len(diff_info.changed_lines)} changed lines, "
                    f"{len(modified_statements)} modified statements, status={diff_info.status}"
                )

            # Process each issue with filtering (relaxed for no_patch files)
            for issue in result.issues:
                # Skip ignored issues
                if self._is_issue_ignored(issue, relative_path):
                    logger.debug(f"Skipped ignored issue in {relative_path}: {issue.issue_type}")
                    continue

                line_number = self._find_issue_line(issue, result.policy_file, line_mapping)

                if not line_number:
                    logger.debug(
                        f"Could not determine line number for issue in {relative_path}: {issue.issue_type}"
                    )
                    continue

                # SPECIAL CASE: Policy-level issues (privilege escalation, etc.)
                # Post to first available line in diff, preferring line 1 if available
                if issue.statement_index == -1:
                    # Try to find the best line to post the comment
                    comment_line = None

                    if allow_all_lines:
                        # No patch - post at the actual line
                        comment_line = line_number
                    elif line_number in diff_info.changed_lines:
                        # Best case: line 1 is in the diff
                        comment_line = line_number
                    elif diff_info.changed_lines:
                        # Fallback: use the first changed line in the file
                        # This ensures policy-level issues always appear as inline comments
                        comment_line = min(diff_info.changed_lines)
                        logger.debug(
                            f"Policy-level issue at line {line_number}, posting to first changed line {comment_line}"
                        )

                    if comment_line:
                        # Post as inline comment at the determined line
                        inline_comments.append(
                            {
                                "path": relative_path,
                                "line": comment_line,
                                "body": issue.to_pr_comment(file_path=relative_path),
                            }
                        )
                        logger.debug(
                            f"Policy-level inline comment: {relative_path}:{comment_line} - {issue.issue_type}"
                        )
                    else:
                        # No changed lines in file - add to summary comment
                        self._context_issues.append(
                            ContextIssue(relative_path, issue.statement_index, line_number, issue)
                        )
                        context_issue_count += 1
                        logger.debug(
                            f"Policy-level issue (no diff lines): {relative_path} - {issue.issue_type}"
                        )
                # RELAXED FILTERING for no_patch files, STRICT for others
                elif allow_all_lines or line_number in diff_info.changed_lines:
                    # No patch: allow all lines, or exact match with changed lines
                    inline_comments.append(
                        {
                            "path": relative_path,
                            "line": line_number,
                            "body": issue.to_pr_comment(file_path=relative_path),
                        }
                    )
                    logger.debug(
                        f"Inline comment: {relative_path}:{line_number} - {issue.issue_type}"
                        f"{' (no_patch)' if allow_all_lines else ''}"
                    )
                elif issue.statement_index in modified_statements:
                    # Issue in modified statement but on unchanged line - save for summary
                    self._context_issues.append(
                        ContextIssue(relative_path, issue.statement_index, line_number, issue)
                    )
                    context_issue_count += 1
                    logger.debug(
                        f"Context issue: {relative_path}:{line_number} (statement {issue.statement_index} modified) - {issue.issue_type}"
                    )
                else:
                    # Issue in completely unchanged statement - ignore for inline and summary
                    logger.debug(
                        f"Skipped issue in unchanged statement: {relative_path}:{line_number} - {issue.issue_type}"
                    )

        # Log filtering results
        logger.info(
            f"Diff filtering results: {len(inline_comments)} inline comments, "
            f"{context_issue_count} context issues for summary"
        )

        # Even if no inline comments, we still need to run cleanup to delete stale comments
        # from previous runs where findings have been resolved (unless cleanup is disabled)
        if not inline_comments:
            logger.info("No inline comments to post (after diff filtering)")
            # Still run cleanup to delete any stale comments from resolved findings
            # (unless skip_cleanup is set for streaming mode)
            # Use APPROVE event to dismiss any previous REQUEST_CHANGES review
            if validated_files and self.cleanup_old_comments:
                logger.debug(
                    "Running cleanup for stale comments and approving PR (no blocking issues)..."
                )
                await self.github.update_or_create_review_comments(
                    comments=[],
                    body="",
                    event=ReviewEvent.APPROVE,
                    identifier=self.REVIEW_IDENTIFIER,
                    validated_files=validated_files,
                    skip_cleanup=False,  # Explicitly run cleanup
                )
            return True

        # Determine review event based on fail_on_severities config
        # Exclude ignored findings from blocking issues
        has_blocking_issues = any(
            issue.severity in self.fail_on_severities
            and not self._is_issue_ignored(
                issue, self._make_relative_path(result.policy_file) or ""
            )
            for result in report.results
            for issue in result.issues
        )

        event = ReviewEvent.REQUEST_CHANGES if has_blocking_issues else ReviewEvent.APPROVE
        logger.info(
            f"Creating PR review with {len(inline_comments)} comments, event: {event.value}"
        )

        # Post review with smart update-or-create logic
        # Pass validated_files to ensure stale comments are deleted even for files
        # that no longer have any findings (issues were resolved)
        # Use skip_cleanup based on cleanup_old_comments flag (False in streaming mode)
        review_body = f"{self.REVIEW_IDENTIFIER}"

        success = await self.github.update_or_create_review_comments(
            comments=inline_comments,
            body=review_body,
            event=event,
            identifier=self.REVIEW_IDENTIFIER,
            validated_files=validated_files,
            skip_cleanup=not self.cleanup_old_comments,  # Skip cleanup in streaming mode
        )

        if success:
            logger.info("Successfully managed PR review comments (update/create/delete)")
        else:
            logger.error("Failed to manage PR review comments")

        return success

    def _make_relative_path(self, policy_file: str) -> str | None:
        """Convert absolute path to relative path for GitHub.

        GitHub PR review comments require paths relative to the repository root.

        Args:
            policy_file: Absolute or relative path to policy file

        Returns:
            Relative path from repository root, or None if cannot be determined
        """
        import os  # pylint: disable=import-outside-toplevel
        from pathlib import Path  # pylint: disable=import-outside-toplevel

        # If already relative, use as-is
        if not os.path.isabs(policy_file):
            logger.debug(f"Path already relative: {policy_file}")
            return policy_file

        # Try to get workspace path from environment
        workspace = os.getenv("GITHUB_WORKSPACE")
        # Log first call only to avoid spam
        if not hasattr(self, "_logged_workspace"):
            self._logged_workspace = True
            logger.warning(f"[ENV] GITHUB_WORKSPACE={workspace}")
        if workspace:
            try:
                # Convert to Path objects for proper path handling
                abs_file_path = Path(policy_file).resolve()
                workspace_path = Path(workspace).resolve()

                # Check if file is within workspace
                if abs_file_path.is_relative_to(workspace_path):
                    relative = abs_file_path.relative_to(workspace_path)
                    # Use forward slashes for GitHub (works on all platforms)
                    result = str(relative).replace("\\", "/")
                    return result
                else:
                    logger.warning(
                        f"[PATH] File not within workspace: {abs_file_path} not in {workspace_path}"
                    )
            except (ValueError, OSError) as e:
                logger.debug(f"Could not compute relative path for {policy_file}: {e}")

        # Fallback: try current working directory
        try:
            cwd = Path.cwd()
            abs_file_path = Path(policy_file).resolve()
            if abs_file_path.is_relative_to(cwd):
                relative = abs_file_path.relative_to(cwd)
                return str(relative).replace("\\", "/")
        except (ValueError, OSError) as e:
            logger.debug(f"Could not compute relative path from CWD for {policy_file}: {e}")

        # If all else fails, return None
        logger.warning(
            f"Could not determine relative path for {policy_file}. "
            "Ensure GITHUB_WORKSPACE is set or file is in current directory."
        )
        return None

    def _get_line_mapping(self, policy_file: str) -> dict[int, int]:
        """Get mapping of statement indices to line numbers.

        Args:
            policy_file: Path to policy file

        Returns:
            Dict mapping statement index to line number
        """
        try:
            with open(policy_file, encoding="utf-8") as f:
                lines = f.readlines()

            mapping: dict[int, int] = {}
            statement_count = 0
            in_statement_array = False

            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()

                # Detect "Statement": [ or "Statement" : [
                if '"Statement"' in stripped or "'Statement'" in stripped:
                    in_statement_array = True
                    continue

                # Detect statement object start
                if in_statement_array and stripped.startswith("{"):
                    mapping[statement_count] = line_num
                    statement_count += 1

            return mapping

        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning(f"Could not parse {policy_file} for line mapping: {e}")
            return {}

    def _find_issue_line(
        self,
        issue: ValidationIssue,
        policy_file: str,
        line_mapping: dict[int, int],
    ) -> int | None:
        """Find the line number for an issue.

        Uses field-level line detection when available for precise comment placement.
        For example, an issue about an invalid Action will point to the exact
        Action line, not just the statement start.

        Args:
            issue: Validation issue
            policy_file: Path to policy file
            line_mapping: Statement index to line number mapping

        Returns:
            Line number or None
        """
        # If issue has explicit line number, use it
        if issue.line_number:
            return issue.line_number

        # Try field-level line detection first (most precise)
        if issue.field_name and issue.statement_index >= 0:
            policy_line_map = self._get_policy_line_map(policy_file)
            if policy_line_map:
                field_line = policy_line_map.get_line_for_field(
                    issue.statement_index, issue.field_name
                )
                if field_line:
                    return field_line

        # Fallback: use statement mapping
        if issue.statement_index in line_mapping:
            return line_mapping[issue.statement_index]

        # Fallback: try to find specific field in file by searching
        search_term = issue.action or issue.resource or issue.condition_key
        if search_term:
            return self._search_for_field_line(policy_file, issue.statement_index, search_term)

        return None

    def _get_policy_line_map(self, policy_file: str) -> PolicyLineMap | None:
        """Get cached PolicyLineMap for field-level line detection.

        Args:
            policy_file: Path to policy file

        Returns:
            PolicyLineMap or None if parsing failed
        """
        if policy_file in self._policy_line_maps:
            return self._policy_line_maps[policy_file]

        try:
            with open(policy_file, encoding="utf-8") as f:
                content = f.read()

            policy_map = PolicyLoader.parse_statement_field_lines(content)
            self._policy_line_maps[policy_file] = policy_map
            return policy_map

        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.debug(f"Could not parse field lines for {policy_file}: {e}")
            return None

    def _search_for_field_line(
        self, policy_file: str, statement_idx: int, search_term: str
    ) -> int | None:
        """Search for a specific field within a statement.

        Args:
            policy_file: Path to policy file
            statement_idx: Statement index
            search_term: Term to search for

        Returns:
            Line number or None
        """
        try:
            with open(policy_file, encoding="utf-8") as f:
                lines = f.readlines()

            # Find the statement block
            statement_count = 0
            in_statement = False
            brace_depth = 0

            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()

                # Track braces
                brace_depth += stripped.count("{") - stripped.count("}")

                # Detect statement start
                if not in_statement and stripped.startswith("{") and brace_depth > 0:
                    if statement_count == statement_idx:
                        in_statement = True
                        continue
                    statement_count += 1

                # Search within the statement
                if in_statement:
                    if search_term in line:
                        return line_num

                    # Exit statement when braces balance
                    if brace_depth == 0:
                        in_statement = False

            return None

        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.debug(f"Could not search {policy_file}: {e}")
            return None

    async def _process_ignore_commands(self) -> None:
        """Process pending ignore commands from PR comments."""
        if not self.github:
            return

        from iam_validator.core.ignore_processor import (  # pylint: disable=import-outside-toplevel
            IgnoreCommandProcessor,
        )

        processor = IgnoreCommandProcessor(
            github=self.github,
            allowed_users=self.allowed_ignore_users,
        )
        ignored_count = await processor.process_pending_ignores()
        if ignored_count > 0:
            logger.info(f"Processed {ignored_count} ignore command(s)")

    async def _load_ignored_findings(self) -> None:
        """Load ignored findings for the current PR."""
        if not self.github:
            return

        from iam_validator.core.ignored_findings import (  # pylint: disable=import-outside-toplevel
            IgnoredFindingsStore,
        )

        store = IgnoredFindingsStore(self.github)
        # Load full ignored findings for display in summary
        self._ignored_findings = await store.load()
        # Also get just the IDs for fast lookup
        self._ignored_finding_ids = frozenset(self._ignored_findings.keys())
        if self._ignored_finding_ids:
            logger.debug(f"Loaded {len(self._ignored_finding_ids)} ignored finding(s)")

    def _is_issue_ignored(self, issue: ValidationIssue, file_path: str) -> bool:
        """Check if an issue should be ignored.

        Args:
            issue: The validation issue
            file_path: Relative path to the policy file

        Returns:
            True if the issue is ignored
        """
        if not self._ignored_finding_ids:
            return False

        from iam_validator.core.finding_fingerprint import (  # pylint: disable=import-outside-toplevel
            FindingFingerprint,
        )

        fingerprint = FindingFingerprint.from_issue(issue, file_path)
        return fingerprint.to_hash() in self._ignored_finding_ids

    def _are_all_blocking_issues_ignored(self, report: ValidationReport) -> bool:
        """Check if all blocking issues (based on fail_on_severities) are ignored.

        Args:
            report: The validation report

        Returns:
            True if there are no unignored blocking issues (i.e., all blocking
            issues have been ignored, or there were no blocking issues to begin with)
        """
        if not self._ignored_finding_ids:
            # No ignored findings - check if there are any blocking issues at all
            for result in report.results:
                for issue in result.issues:
                    if issue.severity in self.fail_on_severities:
                        return False
            return True

        # Check each blocking issue to see if it's ignored
        for result in report.results:
            relative_path = self._make_relative_path(result.policy_file)
            if not relative_path:
                continue
            for issue in result.issues:
                if issue.severity in self.fail_on_severities:
                    if not self._is_issue_ignored(issue, relative_path):
                        return False

        return True


async def post_report_to_pr(
    report_file: str,
    create_review: bool = True,
    add_summary: bool = True,
    config_path: str | None = None,
) -> bool:
    """Post a JSON report to a PR.

    Args:
        report_file: Path to JSON report file
        create_review: Whether to create line-specific review
        add_summary: Whether to add summary comment
        config_path: Optional path to config file (to get fail_on_severity)

    Returns:
        True if successful, False otherwise
    """
    try:
        # Load report from JSON
        with open(report_file, encoding="utf-8") as f:
            report_data = json.load(f)

        report = ValidationReport.model_validate(report_data)

        # Load config to get fail_on_severity and severity_labels settings
        from iam_validator.core.config.config_loader import (  # pylint: disable=import-outside-toplevel
            ConfigLoader,
        )

        config = ConfigLoader.load_config(config_path)
        fail_on_severities = config.get_setting("fail_on_severity", ["error", "critical"])
        severity_labels = config.get_setting("severity_labels", {})

        # Get ignore settings
        ignore_settings = config.get_setting("ignore_settings", {})
        enable_codeowners_ignore = ignore_settings.get("enabled", True)
        allowed_ignore_users = ignore_settings.get("allowed_users", [])

        # Post to PR
        async with GitHubIntegration() as github:
            commenter = PRCommenter(
                github,
                fail_on_severities=fail_on_severities,
                severity_labels=severity_labels,
                enable_codeowners_ignore=enable_codeowners_ignore,
                allowed_ignore_users=allowed_ignore_users,
            )
            return await commenter.post_findings_to_pr(
                report,
                create_review=create_review,
                add_summary_comment=add_summary,
            )

    except FileNotFoundError:
        logger.error(f"Report file not found: {report_file}")
        return False
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in report file: {e}")
        return False
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error(f"Failed to post report to PR: {e}")
        return False

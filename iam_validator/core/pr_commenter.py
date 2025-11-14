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
from iam_validator.core.label_manager import LabelManager
from iam_validator.core.models import ValidationIssue, ValidationReport
from iam_validator.core.report import ReportGenerator
from iam_validator.integrations.github_integration import GitHubIntegration, ReviewEvent

logger = logging.getLogger(__name__)


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
    ):
        """Initialize PR commenter.

        Args:
            github: GitHubIntegration instance (will create one if None)
            cleanup_old_comments: Whether to clean up old bot comments before posting new ones
            fail_on_severities: List of severity levels that should trigger REQUEST_CHANGES
                               (e.g., ["error", "critical", "high"])
            severity_labels: Mapping of severity levels to label name(s) for automatic label management
                           Supports both single labels and lists of labels per severity.
                           Examples:
                             - Single: {"error": "iam-validity-error", "critical": "security-critical"}
                             - Multiple: {"error": ["iam-error", "needs-fix"], "critical": ["security-critical", "needs-review"]}
                             - Mixed: {"error": "iam-validity-error", "critical": ["security-critical", "needs-review"]}
        """
        self.github = github
        self.cleanup_old_comments = cleanup_old_comments
        self.fail_on_severities = fail_on_severities or ["error", "critical"]
        self.severity_labels = severity_labels or {}

    async def post_findings_to_pr(
        self,
        report: ValidationReport,
        create_review: bool = True,
        add_summary_comment: bool = True,
        manage_labels: bool = True,
    ) -> bool:
        """Post validation findings to a PR.

        Args:
            report: Validation report with findings
            create_review: Whether to create a PR review with line comments
            add_summary_comment: Whether to add a summary comment
            manage_labels: Whether to manage PR labels based on severity findings

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

        # Clean up old bot comments if enabled
        if self.cleanup_old_comments and create_review:
            logger.info("Cleaning up old review comments from previous runs...")
            await self.github.cleanup_bot_review_comments(self.REVIEW_IDENTIFIER)

        # Post summary comment (potentially as multiple parts)
        if add_summary_comment:
            generator = ReportGenerator()
            comment_parts = generator.generate_github_comment_parts(report)

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

        # Post line-specific review comments
        if create_review:
            if not await self._post_review_comments(report):
                logger.error("Failed to post review comments")
                success = False

        # Manage PR labels based on severity findings
        if manage_labels and self.severity_labels:
            label_manager = LabelManager(self.github, self.severity_labels)
            label_success, added, removed = await label_manager.manage_labels_from_report(report)

            if not label_success:
                logger.error("Failed to manage PR labels")
                success = False
            else:
                if added > 0 or removed > 0:
                    logger.info(f"Label management: added {added}, removed {removed}")

        return success

    async def _post_review_comments(self, report: ValidationReport) -> bool:
        """Post line-specific review comments.

        Args:
            report: Validation report

        Returns:
            True if successful, False otherwise
        """
        if not self.github:
            return False

        # Group issues by file
        comments_by_file: dict[str, list[dict[str, Any]]] = {}

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

            # Try to determine line numbers from the policy file
            line_mapping = self._get_line_mapping(result.policy_file)

            for issue in result.issues:
                # Determine the line number for this issue
                line_number = self._find_issue_line(issue, result.policy_file, line_mapping)

                if line_number:
                    comment = {
                        "path": relative_path,  # Use relative path for GitHub
                        "line": line_number,
                        "body": issue.to_pr_comment(),
                    }

                    if relative_path not in comments_by_file:
                        comments_by_file[relative_path] = []
                    comments_by_file[relative_path].append(comment)
                    logger.debug(
                        f"Prepared review comment for {relative_path}:{line_number} - {issue.issue_type}"
                    )
                else:
                    logger.debug(
                        f"Could not determine line number for issue in {relative_path}: {issue.issue_type}"
                    )

        # If no line-specific comments, skip
        if not comments_by_file:
            logger.info("No line-specific comments to post")
            return True

        # Flatten comments list
        all_comments = []
        for file_comments in comments_by_file.values():
            all_comments.extend(file_comments)

        logger.info(
            f"Posting {len(all_comments)} review comments across {len(comments_by_file)} file(s)"
        )

        # Log files that will receive comments (for debugging)
        for file_path, file_comments in comments_by_file.items():
            logger.debug(f"  {file_path}: {len(file_comments)} comment(s)")

        # Determine review event based on fail_on_severities config
        # Check if any issue has a severity that should trigger REQUEST_CHANGES
        has_blocking_issues = any(
            issue.severity in self.fail_on_severities
            for result in report.results
            for issue in result.issues
        )

        # Set review event: request changes if any blocking issues, else comment
        event = ReviewEvent.REQUEST_CHANGES if has_blocking_issues else ReviewEvent.COMMENT
        logger.info(f"Creating PR review with event: {event.value}")

        # Post review with comments (use minimal body since summary comment has the details)
        # Only include the identifier for cleanup purposes
        review_body = f"{self.REVIEW_IDENTIFIER}"

        success = await self.github.create_review_with_comments(
            comments=all_comments,
            body=review_body,
            event=event,
        )

        if success:
            logger.info(f"Successfully created PR review with {len(all_comments)} comments")
        else:
            logger.error("Failed to create PR review")

        return success

    def _make_relative_path(self, policy_file: str) -> str | None:
        """Convert absolute path to relative path for GitHub.

        GitHub PR review comments require paths relative to the repository root.

        Args:
            policy_file: Absolute or relative path to policy file

        Returns:
            Relative path from repository root, or None if cannot be determined
        """
        import os
        from pathlib import Path

        # If already relative, use as-is
        if not os.path.isabs(policy_file):
            return policy_file

        # Try to get workspace path from environment
        workspace = os.getenv("GITHUB_WORKSPACE")
        if workspace:
            try:
                # Convert to Path objects for proper path handling
                abs_file_path = Path(policy_file).resolve()
                workspace_path = Path(workspace).resolve()

                # Check if file is within workspace
                if abs_file_path.is_relative_to(workspace_path):
                    relative = abs_file_path.relative_to(workspace_path)
                    # Use forward slashes for GitHub (works on all platforms)
                    return str(relative).replace("\\", "/")
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

        # Otherwise, use statement mapping
        if issue.statement_index in line_mapping:
            return line_mapping[issue.statement_index]

        # Fallback: try to find specific field in file
        search_term = issue.action or issue.resource or issue.condition_key
        if search_term:
            return self._search_for_field_line(policy_file, issue.statement_index, search_term)

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
        from iam_validator.core.config.config_loader import ConfigLoader

        config = ConfigLoader.load_config(config_path)
        fail_on_severities = config.get_setting("fail_on_severity", ["error", "critical"])
        severity_labels = config.get_setting("severity_labels", {})

        # Post to PR
        async with GitHubIntegration() as github:
            commenter = PRCommenter(
                github,
                fail_on_severities=fail_on_severities,
                severity_labels=severity_labels,
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

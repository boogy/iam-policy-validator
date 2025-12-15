"""Label Manager for GitHub PR Labels based on Severity Findings.

This module manages GitHub PR labels based on IAM policy validation severity findings.
When validation finds issues with specific severities, it applies corresponding labels.
When those severities are not found, it removes the labels if present.
"""

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from iam_validator.core.models import PolicyValidationResult, ValidationIssue, ValidationReport
    from iam_validator.integrations.github_integration import GitHubIntegration

logger = logging.getLogger(__name__)


class LabelManager:
    """Manages GitHub PR labels based on severity findings."""

    def __init__(
        self,
        github: "GitHubIntegration",
        severity_labels: dict[str, str | list[str]] | None = None,
    ):
        """Initialize label manager.

        Args:
            github: GitHubIntegration instance for API calls
            severity_labels: Mapping of severity levels to label name(s)
                           Supports both single labels and lists of labels per severity.
                           Examples:
                             - Single label per severity:
                               {"error": "iam-validity-error", "critical": "security-critical"}
                             - Multiple labels per severity:
                               {"error": ["iam-error", "needs-fix"], "critical": ["security-critical", "needs-security-review"]}
                             - Mixed:
                               {"error": "iam-validity-error", "critical": ["security-critical", "needs-review"]}
        """
        self.github = github
        self.severity_labels = severity_labels or {}

    def is_enabled(self) -> bool:
        """Check if label management is enabled.

        Returns:
            True if severity_labels is configured and GitHub is configured
        """
        return bool(self.severity_labels) and self.github.is_configured()

    def _get_severities_in_results(
        self,
        results: list["PolicyValidationResult"],
        is_issue_ignored: Callable[["ValidationIssue", str], bool] | None = None,
    ) -> set[str]:
        """Extract all severity levels found in validation results.

        Args:
            results: List of PolicyValidationResult objects
            is_issue_ignored: Optional callback to check if an issue is ignored.
                            Takes (issue, file_path) and returns True if ignored.

        Returns:
            Set of severity levels found (e.g., {"error", "critical", "high"})
        """
        severities = set()
        for result in results:
            for issue in result.issues:
                # Skip ignored issues if a filter is provided
                if is_issue_ignored and is_issue_ignored(issue, result.policy_file):
                    continue
                severities.add(issue.severity)
        return severities

    def _get_severities_in_report(self, report: "ValidationReport") -> set[str]:
        """Extract all severity levels found in validation report.

        Args:
            report: ValidationReport object

        Returns:
            Set of severity levels found (e.g., {"error", "critical", "high"})
        """
        return self._get_severities_in_results(report.results)

    def _determine_labels_to_apply(self, found_severities: set[str]) -> set[str]:
        """Determine which labels should be applied based on found severities.

        Args:
            found_severities: Set of severity levels found in validation

        Returns:
            Set of label names to apply
        """
        labels_to_apply = set()
        for severity, labels in self.severity_labels.items():
            if severity in found_severities:
                # Support both single labels and lists of labels
                if isinstance(labels, list):
                    labels_to_apply.update(labels)
                else:
                    labels_to_apply.add(labels)
        return labels_to_apply

    def _determine_labels_to_remove(self, found_severities: set[str]) -> set[str]:
        """Determine which labels should be removed based on missing severities.

        Args:
            found_severities: Set of severity levels found in validation

        Returns:
            Set of label names to remove
        """
        labels_to_remove = set()
        for severity, labels in self.severity_labels.items():
            if severity not in found_severities:
                # Support both single labels and lists of labels
                if isinstance(labels, list):
                    labels_to_remove.update(labels)
                else:
                    labels_to_remove.add(labels)
        return labels_to_remove

    async def manage_labels_from_results(
        self,
        results: list["PolicyValidationResult"],
        is_issue_ignored: Callable[["ValidationIssue", str], bool] | None = None,
    ) -> tuple[bool, int, int]:
        """Manage PR labels based on validation results.

        This method will:
        1. Determine which severity levels are present in the results (excluding ignored issues)
        2. Add labels for severities that are found
        3. Remove labels for severities that are not found

        Args:
            results: List of PolicyValidationResult objects
            is_issue_ignored: Optional callback to check if an issue is ignored.
                            Takes (issue, file_path) and returns True if ignored.
                            Ignored issues are excluded from label determination.

        Returns:
            Tuple of (success, labels_added, labels_removed)
        """
        if not self.is_enabled():
            logger.debug("Label management not enabled (no severity_labels configured)")
            return (True, 0, 0)

        # Get all severities found in results (excluding ignored issues)
        found_severities = self._get_severities_in_results(results, is_issue_ignored)
        logger.debug(f"Found severities in results: {found_severities}")

        # Determine which labels to apply/remove
        labels_to_apply = self._determine_labels_to_apply(found_severities)
        labels_to_remove = self._determine_labels_to_remove(found_severities)

        logger.debug(f"Labels to apply: {labels_to_apply}")
        logger.debug(f"Labels to remove: {labels_to_remove}")

        # Get current labels on PR
        current_labels = set(await self.github.get_labels())
        logger.debug(f"Current PR labels: {current_labels}")

        # Filter: only add labels that aren't already present
        labels_to_add = labels_to_apply - current_labels

        # Filter: only remove labels that are currently present
        labels_to_actually_remove = labels_to_remove & current_labels

        success = True
        added_count = 0
        removed_count = 0

        # Add new labels
        if labels_to_add:
            logger.info(f"Adding labels to PR: {labels_to_add}")
            if await self.github.add_labels(list(labels_to_add)):
                added_count = len(labels_to_add)
            else:
                logger.error("Failed to add labels to PR")
                success = False

        # Remove old labels
        for label in labels_to_actually_remove:
            logger.info(f"Removing label from PR: {label}")
            if await self.github.remove_label(label):
                removed_count += 1
            else:
                logger.error(f"Failed to remove label: {label}")
                success = False

        if added_count > 0 or removed_count > 0:
            logger.info(f"Label management complete: added {added_count}, removed {removed_count}")
        else:
            logger.debug("No label changes needed")

        return (success, added_count, removed_count)

    async def manage_labels_from_report(
        self,
        report: "ValidationReport",
        is_issue_ignored: Callable[["ValidationIssue", str], bool] | None = None,
    ) -> tuple[bool, int, int]:
        """Manage PR labels based on validation report.

        This is a convenience method that extracts results from the report
        and calls manage_labels_from_results().

        Args:
            report: ValidationReport object
            is_issue_ignored: Optional callback to check if an issue is ignored.
                            Takes (issue, file_path) and returns True if ignored.
                            Ignored issues are excluded from label determination.

        Returns:
            Tuple of (success, labels_added, labels_removed)
        """
        return await self.manage_labels_from_results(report.results, is_issue_ignored)

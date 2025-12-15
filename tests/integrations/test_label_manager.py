"""Unit tests for Label Manager."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from iam_validator.core.label_manager import LabelManager
from iam_validator.core.models import (
    PolicyValidationResult,
    ValidationIssue,
    ValidationReport,
)


class TestLabelManager:
    """Test the LabelManager class."""

    @pytest.fixture
    def mock_github(self):
        """Create a mock GitHubIntegration."""
        mock = MagicMock()
        mock.is_configured = MagicMock(return_value=True)
        mock.get_labels = AsyncMock(return_value=[])
        mock.add_labels = AsyncMock(return_value=True)
        mock.remove_label = AsyncMock(return_value=True)
        return mock

    @pytest.fixture
    def severity_labels(self):
        """Create a sample severity_labels configuration."""
        return {
            "error": "iam-validity-error",
            "critical": "security-critical",
            "high": "security-high",
            "medium": "security-medium",
        }

    @pytest.fixture
    def sample_results(self):
        """Create sample validation results with various severities."""
        return [
            PolicyValidationResult(
                policy_file="policy1.json",
                policy_name="TestPolicy1",
                is_valid=False,
                issues=[
                    ValidationIssue(
                        severity="error",
                        statement_index=0,
                        issue_type="invalid_action",
                        message="Invalid action",
                    ),
                    ValidationIssue(
                        severity="critical",
                        statement_index=0,
                        issue_type="full_wildcard",
                        message="Full wildcard detected",
                    ),
                ],
            ),
            PolicyValidationResult(
                policy_file="policy2.json",
                policy_name="TestPolicy2",
                is_valid=False,
                issues=[
                    ValidationIssue(
                        severity="high",
                        statement_index=0,
                        issue_type="service_wildcard",
                        message="Service wildcard detected",
                    ),
                ],
            ),
        ]

    def test_is_enabled_with_config(self, mock_github, severity_labels):
        """Test is_enabled returns True when configured."""
        manager = LabelManager(mock_github, severity_labels)
        assert manager.is_enabled() is True

    def test_is_enabled_without_config(self, mock_github):
        """Test is_enabled returns False when not configured."""
        manager = LabelManager(mock_github, {})
        assert manager.is_enabled() is False

    def test_is_enabled_github_not_configured(self, severity_labels):
        """Test is_enabled returns False when GitHub is not configured."""
        mock_github = MagicMock()
        mock_github.is_configured = MagicMock(return_value=False)
        manager = LabelManager(mock_github, severity_labels)
        assert manager.is_enabled() is False

    def test_get_severities_in_results(self, mock_github, severity_labels, sample_results):
        """Test extracting severities from results."""
        manager = LabelManager(mock_github, severity_labels)
        severities = manager._get_severities_in_results(sample_results)
        assert severities == {"error", "critical", "high"}

    def test_get_severities_empty_results(self, mock_github, severity_labels):
        """Test extracting severities from empty results."""
        manager = LabelManager(mock_github, severity_labels)
        severities = manager._get_severities_in_results([])
        assert severities == set()

    def test_determine_labels_to_apply(self, mock_github, severity_labels):
        """Test determining which labels to apply."""
        manager = LabelManager(mock_github, severity_labels)
        found_severities = {"error", "critical"}
        labels = manager._determine_labels_to_apply(found_severities)
        assert labels == {"iam-validity-error", "security-critical"}

    def test_determine_labels_to_remove(self, mock_github, severity_labels):
        """Test determining which labels to remove."""
        manager = LabelManager(mock_github, severity_labels)
        found_severities = {"error", "critical"}
        labels = manager._determine_labels_to_remove(found_severities)
        assert labels == {"security-high", "security-medium"}

    @pytest.mark.asyncio
    async def test_manage_labels_add_only(self, mock_github, severity_labels, sample_results):
        """Test adding labels when none are present."""
        manager = LabelManager(mock_github, severity_labels)
        mock_github.get_labels = AsyncMock(return_value=[])

        success, added, removed = await manager.manage_labels_from_results(sample_results)

        assert success is True
        assert added == 3  # error, critical, high
        assert removed == 0
        mock_github.add_labels.assert_called_once()
        # Check that the correct labels were added
        added_labels = mock_github.add_labels.call_args[0][0]
        assert set(added_labels) == {"iam-validity-error", "security-critical", "security-high"}

    @pytest.mark.asyncio
    async def test_manage_labels_remove_only(self, mock_github, severity_labels):
        """Test removing labels when severities are not found."""
        manager = LabelManager(mock_github, severity_labels)
        # Current labels on PR
        mock_github.get_labels = AsyncMock(
            return_value=["security-critical", "security-high", "security-medium"]
        )

        # No issues in results
        empty_results = [
            PolicyValidationResult(
                policy_file="policy.json",
                policy_name="TestPolicy",
                is_valid=True,
                issues=[],
            )
        ]

        success, added, removed = await manager.manage_labels_from_results(empty_results)

        assert success is True
        assert added == 0
        assert removed == 3
        assert mock_github.remove_label.call_count == 3

    @pytest.mark.asyncio
    async def test_manage_labels_add_and_remove(self, mock_github, severity_labels, sample_results):
        """Test adding and removing labels simultaneously."""
        manager = LabelManager(mock_github, severity_labels)
        # Current labels include medium (should be removed) but not error, critical, high
        mock_github.get_labels = AsyncMock(return_value=["security-medium"])

        success, added, removed = await manager.manage_labels_from_results(sample_results)

        assert success is True
        assert added == 3  # error, critical, high
        assert removed == 1  # medium
        mock_github.add_labels.assert_called_once()
        mock_github.remove_label.assert_called_once_with("security-medium")

    @pytest.mark.asyncio
    async def test_manage_labels_no_changes_needed(self, mock_github, severity_labels, sample_results):
        """Test when labels are already correct."""
        manager = LabelManager(mock_github, severity_labels)
        # Current labels match exactly what should be there
        mock_github.get_labels = AsyncMock(
            return_value=["iam-validity-error", "security-critical", "security-high"]
        )

        success, added, removed = await manager.manage_labels_from_results(sample_results)

        assert success is True
        assert added == 0
        assert removed == 0
        # Should not call add or remove
        mock_github.add_labels.assert_not_called()
        mock_github.remove_label.assert_not_called()

    @pytest.mark.asyncio
    async def test_manage_labels_disabled(self, mock_github):
        """Test that label management is skipped when disabled."""
        manager = LabelManager(mock_github, {})  # Empty severity_labels

        results = [
            PolicyValidationResult(
                policy_file="policy.json",
                policy_name="TestPolicy",
                is_valid=False,
                issues=[
                    ValidationIssue(
                        severity="error",
                        statement_index=0,
                        issue_type="invalid_action",
                        message="Invalid action",
                    ),
                ],
            )
        ]

        success, added, removed = await manager.manage_labels_from_results(results)

        assert success is True
        assert added == 0
        assert removed == 0
        # Should not call any GitHub methods
        mock_github.get_labels.assert_not_called()
        mock_github.add_labels.assert_not_called()
        mock_github.remove_label.assert_not_called()

    @pytest.mark.asyncio
    async def test_manage_labels_api_failure_add(self, mock_github, severity_labels, sample_results):
        """Test handling API failure when adding labels."""
        manager = LabelManager(mock_github, severity_labels)
        mock_github.get_labels = AsyncMock(return_value=[])
        mock_github.add_labels = AsyncMock(return_value=False)  # Simulate failure

        success, added, removed = await manager.manage_labels_from_results(sample_results)

        assert success is False
        assert added == 0
        assert removed == 0

    @pytest.mark.asyncio
    async def test_manage_labels_api_failure_remove(self, mock_github, severity_labels):
        """Test handling API failure when removing labels."""
        manager = LabelManager(mock_github, severity_labels)
        mock_github.get_labels = AsyncMock(return_value=["security-medium"])
        mock_github.remove_label = AsyncMock(return_value=False)  # Simulate failure

        empty_results = [
            PolicyValidationResult(
                policy_file="policy.json",
                policy_name="TestPolicy",
                is_valid=True,
                issues=[],
            )
        ]

        success, added, removed = await manager.manage_labels_from_results(empty_results)

        assert success is False
        assert added == 0
        assert removed == 0

    @pytest.mark.asyncio
    async def test_manage_labels_from_report(self, mock_github, severity_labels, sample_results):
        """Test the convenience method that works with ValidationReport."""
        manager = LabelManager(mock_github, severity_labels)
        mock_github.get_labels = AsyncMock(return_value=[])

        report = ValidationReport(
            results=sample_results,
            total_policies=2,
            valid_policies=0,
            invalid_policies=2,
            total_issues=3,
        )

        success, added, removed = await manager.manage_labels_from_report(report)

        assert success is True
        assert added == 3  # error, critical, high
        assert removed == 0

    def test_severity_not_in_config(self, mock_github, severity_labels, sample_results):
        """Test that severities not in config are ignored."""
        # Add a result with a severity not in the config
        sample_results.append(
            PolicyValidationResult(
                policy_file="policy3.json",
                policy_name="TestPolicy3",
                is_valid=True,
                issues=[
                    ValidationIssue(
                        severity="info",  # Not in severity_labels config
                        statement_index=0,
                        issue_type="informational",
                        message="Informational message",
                    ),
                ],
            )
        )

        manager = LabelManager(mock_github, severity_labels)
        labels = manager._determine_labels_to_apply({"error", "critical", "info"})
        # "info" should not create a label since it's not in the config
        assert labels == {"iam-validity-error", "security-critical"}

    # ========== Tests for list support ==========

    @pytest.fixture
    def severity_labels_with_lists(self):
        """Create a severity_labels configuration with lists."""
        return {
            "error": ["iam-validity-error", "needs-fix"],
            "critical": ["security-critical", "needs-security-review"],
            "high": "security-high",  # Mixed: single label
        }

    def test_determine_labels_to_apply_with_lists(
        self, mock_github, severity_labels_with_lists
    ):
        """Test determining labels when config uses lists."""
        manager = LabelManager(mock_github, severity_labels_with_lists)
        found_severities = {"error", "critical"}
        labels = manager._determine_labels_to_apply(found_severities)
        assert labels == {
            "iam-validity-error",
            "needs-fix",
            "security-critical",
            "needs-security-review",
        }

    def test_determine_labels_to_remove_with_lists(
        self, mock_github, severity_labels_with_lists
    ):
        """Test determining labels to remove when config uses lists."""
        manager = LabelManager(mock_github, severity_labels_with_lists)
        found_severities = {"error"}  # critical and high not found
        labels = manager._determine_labels_to_remove(found_severities)
        assert labels == {
            "security-critical",
            "needs-security-review",
            "security-high",
        }

    @pytest.mark.asyncio
    async def test_manage_labels_with_lists(
        self, mock_github, severity_labels_with_lists, sample_results
    ):
        """Test managing labels when config uses lists."""
        manager = LabelManager(mock_github, severity_labels_with_lists)
        mock_github.get_labels = AsyncMock(return_value=[])

        success, added, removed = await manager.manage_labels_from_results(sample_results)

        assert success is True
        # error (2 labels) + critical (2 labels) + high (1 label) = 5 labels
        assert added == 5
        assert removed == 0
        mock_github.add_labels.assert_called_once()
        added_labels = set(mock_github.add_labels.call_args[0][0])
        assert added_labels == {
            "iam-validity-error",
            "needs-fix",
            "security-critical",
            "needs-security-review",
            "security-high",
        }

    @pytest.mark.asyncio
    async def test_manage_labels_mixed_lists_and_strings(self, mock_github):
        """Test managing labels with mixed list and string configuration."""
        mixed_config = {
            "error": ["iam-error", "needs-fix"],  # List
            "critical": "security-critical",  # String
        }
        manager = LabelManager(mock_github, mixed_config)
        # Current PR has the critical label which should be removed
        mock_github.get_labels = AsyncMock(return_value=["security-critical"])

        results = [
            PolicyValidationResult(
                policy_file="policy.json",
                policy_name="TestPolicy",
                is_valid=False,
                issues=[
                    ValidationIssue(
                        severity="error",
                        statement_index=0,
                        issue_type="invalid_action",
                        message="Invalid action",
                    ),
                ],
            )
        ]

        success, added, removed = await manager.manage_labels_from_results(results)

        assert success is True
        assert added == 2  # Two labels for error
        assert removed == 1  # One label for critical (not found)
        # Check added labels
        added_labels = set(mock_github.add_labels.call_args[0][0])
        assert added_labels == {"iam-error", "needs-fix"}
        # Check removed label
        mock_github.remove_label.assert_called_once_with("security-critical")

    # ========== Tests for ignored findings filter ==========

    @pytest.mark.asyncio
    async def test_manage_labels_with_ignored_filter_excludes_issues(
        self, mock_github, severity_labels
    ):
        """Test that ignored issues are excluded from label determination."""
        manager = LabelManager(mock_github, severity_labels)
        mock_github.get_labels = AsyncMock(return_value=[])

        results = [
            PolicyValidationResult(
                policy_file="policy1.json",
                policy_name="TestPolicy1",
                is_valid=False,
                issues=[
                    ValidationIssue(
                        severity="critical",
                        statement_index=0,
                        issue_type="full_wildcard",
                        message="Full wildcard detected",
                    ),
                    ValidationIssue(
                        severity="error",
                        statement_index=0,
                        issue_type="invalid_action",
                        message="Invalid action",
                    ),
                ],
            ),
        ]

        # Filter that ignores the critical issue
        def is_ignored(issue, file_path):
            return issue.issue_type == "full_wildcard"

        success, added, removed = await manager.manage_labels_from_results(
            results, is_issue_ignored=is_ignored
        )

        assert success is True
        # Only error label should be added (critical is ignored)
        assert added == 1
        mock_github.add_labels.assert_called_once()
        added_labels = mock_github.add_labels.call_args[0][0]
        assert set(added_labels) == {"iam-validity-error"}

    @pytest.mark.asyncio
    async def test_manage_labels_all_issues_ignored_removes_labels(
        self, mock_github, severity_labels
    ):
        """Test that when all issues are ignored, corresponding labels are removed."""
        manager = LabelManager(mock_github, severity_labels)
        # Current PR has labels from previous run
        mock_github.get_labels = AsyncMock(
            return_value=["iam-validity-error", "security-critical"]
        )

        results = [
            PolicyValidationResult(
                policy_file="policy1.json",
                policy_name="TestPolicy1",
                is_valid=False,
                issues=[
                    ValidationIssue(
                        severity="critical",
                        statement_index=0,
                        issue_type="full_wildcard",
                        message="Full wildcard detected",
                    ),
                    ValidationIssue(
                        severity="error",
                        statement_index=0,
                        issue_type="invalid_action",
                        message="Invalid action",
                    ),
                ],
            ),
        ]

        # Filter that ignores ALL issues
        def is_ignored(issue, file_path):
            return True

        success, added, removed = await manager.manage_labels_from_results(
            results, is_issue_ignored=is_ignored
        )

        assert success is True
        assert added == 0
        # Both labels should be removed since all issues are ignored
        assert removed == 2
        mock_github.add_labels.assert_not_called()
        assert mock_github.remove_label.call_count == 2

    @pytest.mark.asyncio
    async def test_manage_labels_from_report_with_ignored_filter(
        self, mock_github, severity_labels, sample_results
    ):
        """Test manage_labels_from_report passes the filter to manage_labels_from_results."""
        manager = LabelManager(mock_github, severity_labels)
        mock_github.get_labels = AsyncMock(return_value=[])

        report = ValidationReport(
            results=sample_results,
            total_policies=2,
            valid_policies=0,
            invalid_policies=2,
            total_issues=3,
        )

        # Filter that ignores critical and high issues
        def is_ignored(issue, file_path):
            return issue.severity in ["critical", "high"]

        success, added, removed = await manager.manage_labels_from_report(
            report, is_issue_ignored=is_ignored
        )

        assert success is True
        # Only error label should be added (critical and high are ignored)
        assert added == 1
        mock_github.add_labels.assert_called_once()
        added_labels = mock_github.add_labels.call_args[0][0]
        assert set(added_labels) == {"iam-validity-error"}

    def test_get_severities_with_filter_excludes_ignored(
        self, mock_github, severity_labels, sample_results
    ):
        """Test _get_severities_in_results respects the filter."""
        manager = LabelManager(mock_github, severity_labels)

        # Filter that ignores critical issues
        def is_ignored(issue, file_path):
            return issue.severity == "critical"

        severities = manager._get_severities_in_results(
            sample_results, is_issue_ignored=is_ignored
        )
        # critical should be excluded
        assert severities == {"error", "high"}

    def test_get_severities_with_file_path_filter(self, mock_github, severity_labels):
        """Test that the filter receives the correct file path."""
        manager = LabelManager(mock_github, severity_labels)

        results = [
            PolicyValidationResult(
                policy_file="policies/admin.json",
                policy_name="AdminPolicy",
                is_valid=False,
                issues=[
                    ValidationIssue(
                        severity="critical",
                        statement_index=0,
                        issue_type="full_wildcard",
                        message="Full wildcard",
                    ),
                ],
            ),
            PolicyValidationResult(
                policy_file="policies/readonly.json",
                policy_name="ReadOnlyPolicy",
                is_valid=False,
                issues=[
                    ValidationIssue(
                        severity="error",
                        statement_index=0,
                        issue_type="invalid_action",
                        message="Invalid action",
                    ),
                ],
            ),
        ]

        # Filter that ignores issues in admin.json
        def is_ignored(issue, file_path):
            return "admin.json" in file_path

        severities = manager._get_severities_in_results(
            results, is_issue_ignored=is_ignored
        )
        # critical from admin.json should be excluded
        assert severities == {"error"}

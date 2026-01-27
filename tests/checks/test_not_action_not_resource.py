"""Tests for NotAction/NotResource security check."""

from unittest.mock import MagicMock

import pytest

from iam_validator.checks.not_action_not_resource import NotActionNotResourceCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
def check() -> NotActionNotResourceCheck:
    return NotActionNotResourceCheck()


@pytest.fixture
def config() -> CheckConfig:
    return CheckConfig(check_id="not_action_not_resource", enabled=True, severity="high")


@pytest.fixture
def mock_fetcher() -> MagicMock:
    return MagicMock()


class TestNotActionNotResourceCheck:
    """Tests for NotActionNotResourceCheck."""

    @pytest.mark.asyncio
    async def test_normal_allow_no_issue(self, check, config, mock_fetcher) -> None:
        """Test that normal Allow statements don't trigger issues."""
        statement = Statement(
            effect="Allow",
            action=["s3:GetObject", "s3:ListBucket"],
            resource="arn:aws:s3:::my-bucket/*",
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_not_action_allow_no_condition(self, check, config, mock_fetcher) -> None:
        """Test that NotAction with Allow and no conditions is flagged as high severity."""
        statement = Statement(
            effect="Allow",
            not_action=["iam:*", "organizations:*"],
            resource="*",
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "high"
        assert issues[0].issue_type == "not_action_allow_no_condition"

    @pytest.mark.asyncio
    async def test_not_action_allow_with_condition(self, check, config, mock_fetcher) -> None:
        """Test that NotAction with Allow and conditions is flagged as medium severity."""
        statement = Statement(
            effect="Allow",
            not_action=["iam:*"],
            resource="*",
            condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "medium"
        assert issues[0].issue_type == "not_action_allow"

    @pytest.mark.asyncio
    async def test_not_resource_broad_detected(self, check, config, mock_fetcher) -> None:
        """Test that NotResource with broad Resource is flagged."""
        statement = Statement(
            effect="Allow",
            action=["s3:*"],
            resource="*",
            not_resource=["arn:aws:s3:::protected-bucket/*"],
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "high"
        assert issues[0].issue_type == "not_resource_broad"

    @pytest.mark.asyncio
    async def test_not_action_deny_low_severity(self, check, config, mock_fetcher) -> None:
        """Test that NotAction with Deny and wildcard Resource is informational."""
        statement = Statement(
            effect="Deny",
            not_action=["s3:GetObject", "s3:ListBucket"],
            resource="*",
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        assert issues[0].issue_type == "not_action_deny_review"

    @pytest.mark.asyncio
    async def test_both_not_action_and_not_resource(self, check, config, mock_fetcher) -> None:
        """Test statement with both NotAction and NotResource."""
        statement = Statement(
            effect="Allow",
            not_action=["iam:*"],
            not_resource=["arn:aws:s3:::protected/*"],
            resource="*",
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        # Expect 3 issues: NotAction alone, NotResource alone, AND combined critical
        assert len(issues) == 3
        issue_types = {i.issue_type for i in issues}
        assert "not_action_allow_no_condition" in issue_types
        assert "not_resource_broad" in issue_types
        assert "combined_not_action_not_resource" in issue_types

        # The combined check should be critical severity
        combined_issue = next(i for i in issues if i.issue_type == "combined_not_action_not_resource")
        assert combined_issue.severity == "critical"

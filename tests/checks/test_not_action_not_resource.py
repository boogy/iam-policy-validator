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
        """Test that NotAction with Allow and no conditions is flagged with implicit grant info."""
        statement = Statement(
            effect="Allow",
            not_action=["iam:*", "s3:*"],
            resource="*",
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "high"
        assert issues[0].issue_type == "not_action_allow_no_condition"
        # Message should describe what's implicitly granted
        msg = issues[0].message.lower()
        assert "except" in msg
        assert "`iam`" in issues[0].message or "`s3`" in issues[0].message

    @pytest.mark.asyncio
    async def test_not_action_allow_with_condition(self, check, config, mock_fetcher) -> None:
        """Test that NotAction with Allow and conditions is flagged as medium with grant info."""
        statement = Statement(
            effect="Allow",
            not_action=["organizations:*"],
            resource="*",
            condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "medium"
        assert issues[0].issue_type == "not_action_allow"
        assert "organizations" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_not_action_with_specific_actions(self, check, config, mock_fetcher) -> None:
        """Test NotAction with specific (non-wildcard) actions."""
        statement = Statement(
            effect="Allow",
            not_action=["iam:CreateUser", "iam:DeleteUser"],
            resource="*",
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        not_action_issues = [i for i in issues if i.issue_type == "not_action_allow_no_condition"]
        assert len(not_action_issues) == 1
        assert "iam" in not_action_issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_not_resource_broad_detected(self, check, config, mock_fetcher) -> None:
        """Test that NotResource with broad Resource is flagged with future resource warning."""
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
        assert "future resources" in issues[0].suggestion.lower() or "new resources" in issues[0].suggestion.lower()

    @pytest.mark.asyncio
    async def test_not_action_deny(self, check, config, mock_fetcher) -> None:
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
        assert "denies everything except" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_both_not_action_and_not_resource(self, check, config, mock_fetcher) -> None:
        """Test statement with both NotAction and NotResource.

        When both are present, only the combined critical finding is emitted
        to avoid redundant noise from the individual checks.
        """
        statement = Statement(
            effect="Allow",
            not_action=["iam:*"],
            not_resource=["arn:aws:s3:::protected/*"],
            resource="*",
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        # Only the combined critical finding, individual checks are suppressed
        assert len(issues) == 1
        assert issues[0].issue_type == "combined_not_action_not_resource"
        assert issues[0].severity == "critical"

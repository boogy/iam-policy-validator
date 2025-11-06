"""Tests for FullWildcardCheck."""

import pytest

from iam_validator.checks.full_wildcard import FullWildcardCheck
from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
async def fetcher():
    """Create AWS service fetcher for tests."""
    async with AWSServiceFetcher(prefetch_common=False) as f:
        yield f


@pytest.fixture
def check():
    """Create FullWildcardCheck instance."""
    return FullWildcardCheck()


@pytest.fixture
def config():
    """Create default check config."""
    return CheckConfig(check_id="full_wildcard", enabled=True, config={})


class TestFullWildcardCheck:
    """Tests for FullWildcardCheck."""

    def test_check_id(self, check):
        """Test check ID."""
        assert check.check_id == "full_wildcard"

    def test_description(self, check):
        """Test check description."""
        assert "action and resource wildcards together" in check.description.lower()

    def test_default_severity(self, check):
        """Test default severity is critical."""
        assert check.default_severity == "critical"

    @pytest.mark.asyncio
    async def test_full_wildcard_detected(self, check, fetcher, config):
        """Test that both Action:* and Resource:* together is detected."""
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "critical"
        assert issues[0].issue_type == "security_risk"
        assert "all actions on all resources" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_only_action_wildcard_no_issue(self, check, fetcher, config):
        """Test that only Action:* without Resource:* is not flagged."""
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_only_resource_wildcard_no_issue(self, check, fetcher, config):
        """Test that only Resource:* without Action:* is not flagged."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_deny_statement_ignored(self, check, fetcher, config):
        """Test that Deny statements are ignored."""
        statement = Statement(
            Effect="Deny",
            Action=["*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_specific_actions_and_resources_no_issue(self, check, fetcher, config):
        """Test that specific actions and resources don't trigger the check."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "s3:PutObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_in_list(self, check, fetcher, config):
        """Test that wildcard is detected even when in a list with other actions."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "*"],
            Resource=["arn:aws:s3:::my-bucket/*", "*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_statement_with_sid(self, check, fetcher, config):
        """Test that statement SID is captured in issue."""
        statement = Statement(
            Sid="AllowEverything",
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_sid == "AllowEverything"

    @pytest.mark.asyncio
    async def test_statement_index(self, check, fetcher, config):
        """Test that statement index is captured."""
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 5, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_index == 5

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, fetcher, config):
        """Test that line number is captured when available."""
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
            line_number=42,
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].line_number == 42

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity override."""
        config = CheckConfig(
            check_id="full_wildcard",
            enabled=True,
            severity="high",
        )

        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "high"

    @pytest.mark.asyncio
    async def test_custom_message(self, check, fetcher):
        """Test custom message configuration."""
        config = CheckConfig(
            check_id="full_wildcard",
            enabled=True,
            config={"message": "Custom warning message"},
        )

        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].message == "Custom warning message"

    @pytest.mark.asyncio
    async def test_custom_suggestion(self, check, fetcher):
        """Test custom suggestion configuration."""
        config = CheckConfig(
            check_id="full_wildcard",
            enabled=True,
            config={"suggestion": "Custom suggestion text"},
        )

        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Custom suggestion text" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_suggestion_with_example(self, check, fetcher):
        """Test suggestion includes example when configured."""
        config = CheckConfig(
            check_id="full_wildcard",
            enabled=True,
            config={
                "suggestion": "Fix this issue",
                "example": "Use specific actions like s3:GetObject",
            },
        )

        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Fix this issue" in issues[0].suggestion
        assert "Example:" in issues[0].suggestion
        assert "Use specific actions like s3:GetObject" in issues[0].suggestion

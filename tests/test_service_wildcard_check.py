"""Tests for ServiceWildcardCheck."""

import pytest

from iam_validator.checks.service_wildcard import ServiceWildcardCheck
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
    """Create ServiceWildcardCheck instance."""
    return ServiceWildcardCheck()


@pytest.fixture
def config():
    """Create default check config."""
    return CheckConfig(check_id="service_wildcard", enabled=True, config={})


class TestServiceWildcardCheck:
    """Tests for ServiceWildcardCheck."""

    def test_check_id(self, check):
        """Test check ID."""
        assert check.check_id == "service_wildcard"

    def test_description(self, check):
        """Test check description."""
        assert "service-level wildcards" in check.description.lower()

    def test_default_severity(self, check):
        """Test default severity is high."""
        assert check.default_severity == "high"

    @pytest.mark.asyncio
    async def test_service_wildcard_detected(self, check, fetcher, config):
        """Test that service-level wildcards are detected."""
        statement = Statement(
            Effect="Allow",
            Action=["iam:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "high"
        assert issues[0].issue_type == "overly_permissive"
        assert "iam:*" in issues[0].message
        assert issues[0].action == "iam:*"

    @pytest.mark.asyncio
    async def test_multiple_service_wildcards(self, check, fetcher, config):
        """Test that multiple service wildcards are all detected."""
        statement = Statement(
            Effect="Allow",
            Action=["iam:*", "s3:*", "ec2:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 3
        actions = {issue.action for issue in issues}
        assert actions == {"iam:*", "s3:*", "ec2:*"}

    @pytest.mark.asyncio
    async def test_full_wildcard_skipped(self, check, fetcher, config):
        """Test that full wildcard Action:* is skipped (handled by wildcard_action check)."""
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_prefix_wildcard_not_flagged(self, check, fetcher, config):
        """Test that prefix wildcards like iam:Get* are not flagged by this check."""
        statement = Statement(
            Effect="Allow",
            Action=["iam:Get*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_specific_actions_not_flagged(self, check, fetcher, config):
        """Test that specific actions are not flagged."""
        statement = Statement(
            Effect="Allow",
            Action=["iam:GetUser", "s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_deny_statement_ignored(self, check, fetcher, config):
        """Test that Deny statements are ignored."""
        statement = Statement(
            Effect="Deny",
            Action=["iam:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_allowed_services_configuration(self, check, fetcher):
        """Test that configured allowed services are not flagged."""
        config = CheckConfig(
            check_id="service_wildcard",
            enabled=True,
            config={"allowed_services": ["logs", "cloudwatch"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["logs:*", "cloudwatch:*", "iam:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Only iam:* should be flagged, logs:* and cloudwatch:* are allowed
        assert len(issues) == 1
        assert issues[0].action == "iam:*"

    @pytest.mark.asyncio
    async def test_allowed_services_all_pass(self, check, fetcher):
        """Test that all actions pass when in allowed list."""
        config = CheckConfig(
            check_id="service_wildcard",
            enabled=True,
            config={"allowed_services": ["logs", "cloudwatch"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["logs:*", "cloudwatch:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_statement_with_sid(self, check, fetcher, config):
        """Test that statement SID is captured in issue."""
        statement = Statement(
            Sid="AllowIAMAll",
            Effect="Allow",
            Action=["iam:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_sid == "AllowIAMAll"

    @pytest.mark.asyncio
    async def test_statement_index(self, check, fetcher, config):
        """Test that statement index is captured."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 7, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_index == 7

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, fetcher, config):
        """Test that line number is captured when available."""
        statement = Statement(
            Effect="Allow",
            Action=["ec2:*"],
            Resource=["*"],
            line_number=100,
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].line_number == 100

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity override."""
        config = CheckConfig(
            check_id="service_wildcard",
            enabled=True,
            severity="critical",
        )

        statement = Statement(
            Effect="Allow",
            Action=["iam:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_custom_message_template(self, check, fetcher):
        """Test custom message template with placeholders."""
        config = CheckConfig(
            check_id="service_wildcard",
            enabled=True,
            config={"message": "Wildcard detected: {action} for {service}"},
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].message == "Wildcard detected: s3:* for s3"

    @pytest.mark.asyncio
    async def test_custom_suggestion_template(self, check, fetcher):
        """Test custom suggestion template with placeholders."""
        config = CheckConfig(
            check_id="service_wildcard",
            enabled=True,
            config={
                "suggestion": "Replace {action} with specific actions for {service}",
            },
        )

        statement = Statement(
            Effect="Allow",
            Action=["ec2:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Replace ec2:* with specific actions for ec2" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_suggestion_with_example(self, check, fetcher):
        """Test suggestion includes example when configured."""
        config = CheckConfig(
            check_id="service_wildcard",
            enabled=True,
            config={
                "suggestion": "Use specific actions instead of {action}",
                "example": "Try {service}:Get* or {service}:List*",
            },
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Use specific actions instead of s3:*" in issues[0].suggestion
        assert "Example:" in issues[0].suggestion
        assert "Try s3:Get* or s3:List*" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_action_without_service_prefix_ignored(self, check, fetcher, config):
        """Test that actions without service prefix are ignored."""
        statement = Statement(
            Effect="Allow",
            Action=["GetUser"],  # Invalid format, missing service prefix
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_empty_allowed_services_config(self, check, fetcher):
        """Test that empty allowed_services config is handled correctly."""
        config = CheckConfig(
            check_id="service_wildcard",
            enabled=True,
            config={"allowed_services": []},
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should still flag s3:* since allowed_services is empty
        assert len(issues) == 1
        assert issues[0].action == "s3:*"

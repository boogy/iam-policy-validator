"""Tests for WildcardResourceCheck."""

import pytest

from iam_validator.checks.wildcard_resource import WildcardResourceCheck
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
    """Create WildcardResourceCheck instance."""
    return WildcardResourceCheck()


@pytest.fixture
def config():
    """Create default check config."""
    return CheckConfig(check_id="wildcard_resource", enabled=True, config={})


class TestWildcardResourceCheck:
    """Tests for WildcardResourceCheck."""

    def test_check_id(self, check):
        """Test check ID."""
        assert check.check_id == "wildcard_resource"

    def test_description(self, check):
        """Test check description."""
        assert "wildcard resources" in check.description.lower()

    def test_default_severity(self, check):
        """Test default severity is medium."""
        assert check.default_severity == "medium"

    @pytest.mark.asyncio
    async def test_wildcard_resource_detected(self, check, fetcher, config):
        """Test that Resource:* is detected."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "medium"
        assert issues[0].issue_type == "overly_permissive"
        assert "all resources" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_specific_resources_not_flagged(self, check, fetcher, config):
        """Test that specific resources are not flagged."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_deny_statement_ignored(self, check, fetcher, config):
        """Test that Deny statements are ignored."""
        statement = Statement(
            Effect="Deny",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_in_list_with_other_resources(self, check, fetcher, config):
        """Test that wildcard is detected even when mixed with other resources."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*", "*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "all resources" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_allowed_wildcards_pass(self, check, fetcher):
        """Test that actions in allowed_wildcards configuration are not flagged."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["ec2:Describe*", "s3:List*"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["ec2:DescribeInstances", "s3:ListBucket"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # These actions should be allowed with Resource:* because they match allowed patterns
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_allowed_wildcards_partial_match_fails(self, check, fetcher):
        """Test that only matching actions pass with allowed_wildcards."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["ec2:Describe*"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["ec2:DescribeInstances", "ec2:TerminateInstances"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # ec2:TerminateInstances doesn't match ec2:Describe*, so should be flagged
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_full_wildcard_action_with_allowed_config_fails(self, check, fetcher):
        """Test that Action:* is still flagged even with allowed_wildcards config."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["ec2:Describe*"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["*"],  # Full wildcard is filtered out
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Full wildcard "*" should still be flagged
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_statement_with_sid(self, check, fetcher, config):
        """Test that statement SID is captured in issue."""
        statement = Statement(
            Sid="AllowAllResources",
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_sid == "AllowAllResources"

    @pytest.mark.asyncio
    async def test_statement_index(self, check, fetcher, config):
        """Test that statement index is captured."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 9, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_index == 9

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, fetcher, config):
        """Test that line number is captured when available."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            line_number=55,
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].line_number == 55

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity override."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            severity="high",
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "high"

    @pytest.mark.asyncio
    async def test_custom_message(self, check, fetcher):
        """Test custom message configuration."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"message": "Custom wildcard resource warning"},
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].message == "Custom wildcard resource warning"

    @pytest.mark.asyncio
    async def test_custom_suggestion(self, check, fetcher):
        """Test custom suggestion configuration."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"suggestion": "Please use specific resource ARNs"},
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Please use specific resource ARNs" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_suggestion_with_example(self, check, fetcher):
        """Test suggestion includes example when configured."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={
                "suggestion": "Use specific resource ARNs",
                "example": "Resource: 'arn:aws:s3:::my-bucket/*'",
            },
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Use specific resource ARNs" in issues[0].suggestion
        assert "Example:" in issues[0].suggestion
        assert "Resource: 'arn:aws:s3:::my-bucket/*'" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_wildcard_action_with_allowed_config(self, check, fetcher):
        """Test that wildcard action without allowed_wildcards is flagged."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": []},
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should be flagged because allowed_wildcards is empty
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_empty_resources_not_flagged(self, check, fetcher, config):
        """Test that empty resources list doesn't cause issues."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=[],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_none_resources_not_flagged(self, check, fetcher, config):
        """Test that None resources doesn't cause issues."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
        )
        # Manually set Resource to None to test edge case
        statement.resource = None

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_resource_with_arn_patterns(self, check, fetcher, config):
        """Test that ARN patterns with wildcards are not flagged."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket-*/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # ARN with wildcard pattern is not the same as Resource: "*"
        assert len(issues) == 0

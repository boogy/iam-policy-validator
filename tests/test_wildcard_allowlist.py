"""Tests for wildcard action allowlist functionality."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.checks.action_validation import ActionValidationCheck
from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestWildcardAllowlist:
    """Test suite for wildcard action allowlist."""

    @pytest.fixture
    def check(self):
        """Create an ActionValidationCheck instance."""
        return ActionValidationCheck()

    @pytest.fixture
    def fetcher(self):
        """Create a mock AWSServiceFetcher instance."""
        mock = MagicMock(spec=AWSServiceFetcher)
        mock.validate_action = AsyncMock()
        return mock

    def test_default_allowlist_exists(self, check):
        """Test that default allowlist is defined."""
        assert len(check.DEFAULT_ALLOWED_WILDCARDS) > 0
        assert "s3:List*" in check.DEFAULT_ALLOWED_WILDCARDS
        assert "iam:List*" in check.DEFAULT_ALLOWED_WILDCARDS
        assert "ec2:Describe*" in check.DEFAULT_ALLOWED_WILDCARDS
        # s3:Get* intentionally excluded (can access sensitive data)
        assert "s3:Get*" not in check.DEFAULT_ALLOWED_WILDCARDS

    def test_is_allowed_wildcard_exact_match(self, check):
        """Test exact match in allowlist."""
        allowed = ["s3:Get*", "iam:List*"]

        assert check._is_allowed_wildcard("s3:Get*", allowed) is True
        assert check._is_allowed_wildcard("iam:List*", allowed) is True
        assert check._is_allowed_wildcard("s3:Put*", allowed) is False

    def test_is_allowed_wildcard_case_insensitive(self, check):
        """Test case-insensitive matching."""
        allowed = ["s3:Get*", "IAM:List*"]

        assert check._is_allowed_wildcard("s3:get*", allowed) is True
        assert check._is_allowed_wildcard("S3:GET*", allowed) is True
        assert check._is_allowed_wildcard("iam:list*", allowed) is True
        assert check._is_allowed_wildcard("IAM:LIST*", allowed) is True

    def test_is_allowed_wildcard_pattern_match(self, check):
        """Test pattern matching in allowlist."""
        # Allowlist has patterns with wildcards
        allowed = ["s3:*", "ec2:Describe*"]

        # s3:* should match any s3 action
        assert check._is_allowed_wildcard("s3:GetObject", allowed) is True
        assert check._is_allowed_wildcard("s3:PutObject", allowed) is True
        assert check._is_allowed_wildcard("s3:DeleteBucket", allowed) is True

        # ec2:Describe* should match describe actions
        assert check._is_allowed_wildcard("ec2:DescribeInstances", allowed) is True
        assert check._is_allowed_wildcard("ec2:DescribeImages", allowed) is True

        # Should not match non-describe actions
        assert check._is_allowed_wildcard("ec2:RunInstances", allowed) is False

    @pytest.mark.asyncio
    async def test_allowed_wildcard_no_warning(self, check, fetcher):
        """Test that allowed wildcards don't generate warnings."""
        fetcher.validate_action.return_value = (True, None, True)

        config = CheckConfig(
            check_id="action_validation",
            config={"allowed_wildcards": ["s3:List*"]}
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:List*"],
            Resource=["arn:aws:s3:::bucket/*"]
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not generate any issues
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_disallowed_wildcard_warning(self, check, fetcher):
        """Test that disallowed wildcards generate warnings."""
        fetcher.validate_action.return_value = (True, None, True)

        config = CheckConfig(
            check_id="action_validation",
            config={"allowed_wildcards": ["s3:List*"]}  # Only List* is allowed
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:Put*"],  # Put* is not allowed
            Resource=["arn:aws:s3:::bucket/*"]
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should generate a wildcard warning
        assert len(issues) == 1
        assert issues[0].issue_type == "wildcard_action"
        assert issues[0].severity == "info"
        assert "s3:Put*" in issues[0].message

    @pytest.mark.asyncio
    async def test_default_allowlist_used_when_no_config(self, check, fetcher):
        """Test that default allowlist is used when no config provided."""
        fetcher.validate_action.return_value = (True, None, True)

        config = CheckConfig(check_id="action_validation")  # No custom config

        statement = Statement(
            Effect="Allow",
            Action=["s3:List*"],  # In default allowlist
            Resource=["arn:aws:s3:::bucket/*"]
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not generate warning (default allowlist includes s3:List*)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_multiple_wildcards_mixed(self, check, fetcher):
        """Test mix of allowed and disallowed wildcards."""
        async def validate_side_effect(action):
            # All are valid wildcards
            return (True, None, True)

        fetcher.validate_action.side_effect = validate_side_effect

        config = CheckConfig(
            check_id="action_validation",
            config={"allowed_wildcards": ["s3:List*", "iam:List*"]}
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:List*", "s3:Put*", "iam:List*"],
            Resource=["*"]
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should only warn about s3:Put* (not in allowlist)
        assert len(issues) == 1
        assert issues[0].action == "s3:Put*"
        assert issues[0].issue_type == "wildcard_action"

    @pytest.mark.asyncio
    async def test_disable_wildcard_warnings(self, check, fetcher):
        """Test disabling wildcard warnings entirely."""
        fetcher.validate_action.return_value = (True, None, True)

        config = CheckConfig(
            check_id="action_validation",
            config={"disable_wildcard_warnings": True}
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:Delete*"],  # Not in default allowlist
            Resource=["arn:aws:s3:::bucket/*"]
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not generate any warnings
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_custom_allowlist_overrides_default(self, check, fetcher):
        """Test that custom allowlist completely overrides default."""
        fetcher.validate_action.return_value = (True, None, True)

        # Custom allowlist with only lambda actions
        config = CheckConfig(
            check_id="action_validation",
            config={"allowed_wildcards": ["lambda:Invoke*"]}
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:List*"],  # In DEFAULT allowlist but not custom
            Resource=["arn:aws:s3:::bucket/*"]
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should generate warning (custom allowlist doesn't include s3:List*)
        assert len(issues) == 1
        assert issues[0].action == "s3:List*"

    @pytest.mark.asyncio
    async def test_allowlist_with_broad_patterns(self, check, fetcher):
        """Test allowlist with broad wildcard patterns."""
        fetcher.validate_action.return_value = (True, None, True)

        config = CheckConfig(
            check_id="action_validation",
            config={"allowed_wildcards": ["s3:*", "cloudwatch:*"]}  # Allow all for these services
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:DeleteBucket", "cloudwatch:PutMetricData"],
            Resource=["*"]
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not generate warnings (both covered by s3:* and cloudwatch:*)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_invalid_action_with_wildcard_not_in_allowlist(self, check, fetcher):
        """Test invalid wildcard action still generates error."""
        fetcher.validate_action.return_value = (False, "Action pattern does not match", True)

        config = CheckConfig(
            check_id="action_validation",
            config={"allowed_wildcards": ["s3:Get*"]}
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:InvalidPrefix*"],
            Resource=["arn:aws:s3:::bucket/*"]
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should generate an error (not just a warning)
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_action"
        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_read_only_wildcards_in_default_allowlist(self, check, fetcher):
        """Test that common read-only patterns are in default allowlist."""
        fetcher.validate_action.return_value = (True, None, True)

        config = CheckConfig(check_id="action_validation")

        # Note: s3:Get* is intentionally excluded from defaults (can access sensitive data)
        read_only_actions = [
            "s3:List*",
            "s3:Describe*",
            "ec2:Describe*",
            "iam:Get*",
            "iam:List*",
            "rds:Describe*",
            "lambda:Get*",
            "lambda:List*",
        ]

        statement = Statement(
            Effect="Allow",
            Action=read_only_actions,
            Resource=["*"]
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not generate any warnings (all are in default allowlist)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_write_wildcards_not_in_default_allowlist(self, check, fetcher):
        """Test that write/sensitive operations are not in default allowlist."""
        fetcher.validate_action.return_value = (True, None, True)

        config = CheckConfig(check_id="action_validation")

        # Write and sensitive read operations
        sensitive_actions = [
            "s3:Get*",      # Can read sensitive data
            "s3:Put*",      # Write operation
            "s3:Delete*",   # Destructive operation
            "ec2:Terminate*",  # Destructive operation
            "iam:Delete*",  # Destructive operation
            "lambda:Delete*",  # Destructive operation
        ]

        statement = Statement(
            Effect="Allow",
            Action=sensitive_actions,
            Resource=["*"]
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should generate warnings for all sensitive operations
        assert len(issues) == len(sensitive_actions)
        for issue in issues:
            assert issue.issue_type == "wildcard_action"
            assert issue.severity == "info"

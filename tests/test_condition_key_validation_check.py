"""Tests for condition key validation check."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.checks.condition_key_validation import ConditionKeyValidationCheck
from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestConditionKeyValidationCheck:
    """Test suite for ConditionKeyValidationCheck."""

    @pytest.fixture
    def check(self):
        """Create a ConditionKeyValidationCheck instance."""
        return ConditionKeyValidationCheck()

    @pytest.fixture
    def fetcher(self):
        """Create a mock AWSServiceFetcher instance."""
        mock = MagicMock(spec=AWSServiceFetcher)
        mock.validate_condition_key = AsyncMock()
        return mock

    @pytest.fixture
    def config(self):
        """Create a default CheckConfig."""
        return CheckConfig(check_id="condition_key_validation")

    def test_check_id(self, check):
        """Test check_id property."""
        assert check.check_id == "condition_key_validation"

    def test_description(self, check):
        """Test description property."""
        assert check.description == "Validates condition keys against AWS service definitions"

    def test_default_severity(self, check):
        """Test default_severity property."""
        assert check.default_severity == "error"

    @pytest.mark.asyncio
    async def test_no_conditions(self, check, fetcher, config):
        """Test statement with no conditions."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        fetcher.validate_condition_key.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_condition_key(self, check, fetcher, config):
        """Test valid condition key passes."""
        fetcher.validate_condition_key.return_value = (True, None)

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:prefix": "documents/"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        fetcher.validate_condition_key.assert_called_once_with("s3:GetObject", "s3:prefix")

    @pytest.mark.asyncio
    async def test_invalid_condition_key(self, check, fetcher, config):
        """Test invalid condition key is flagged."""
        fetcher.validate_condition_key.return_value = (
            False,
            "Condition key 's3:invalidKey' is not valid for action 's3:GetObject'",
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].issue_type == "invalid_condition_key"
        assert issues[0].condition_key == "s3:invalidKey"
        assert issues[0].action == "s3:GetObject"

    @pytest.mark.asyncio
    async def test_multiple_condition_keys(self, check, fetcher, config):
        """Test multiple condition keys are validated."""

        async def validate_side_effect(action, key):
            if key == "s3:prefix":
                return (True, None)
            else:
                return (False, f"Condition key '{key}' is not valid")

        fetcher.validate_condition_key.side_effect = validate_side_effect

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:prefix": "documents/", "s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].condition_key == "s3:invalidKey"
        assert fetcher.validate_condition_key.call_count == 2

    @pytest.mark.asyncio
    async def test_multiple_operators(self, check, fetcher, config):
        """Test condition keys in multiple operators."""
        fetcher.validate_condition_key.return_value = (True, None)

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={
                "StringEquals": {"s3:prefix": "documents/"},
                "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        assert fetcher.validate_condition_key.call_count == 2

    @pytest.mark.asyncio
    async def test_multiple_actions(self, check, fetcher, config):
        """Test condition key is validated against multiple actions."""
        fetcher.validate_condition_key.return_value = (True, None)

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "s3:PutObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:prefix": "documents/"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        # Should validate against both actions
        assert fetcher.validate_condition_key.call_count == 2

    @pytest.mark.asyncio
    async def test_wildcard_action_skipped(self, check, fetcher, config):
        """Test wildcard action is skipped in validation."""
        fetcher.validate_condition_key.return_value = (True, None)

        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:prefix": "documents/"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        fetcher.validate_condition_key.assert_not_called()

    @pytest.mark.asyncio
    async def test_only_reports_once_per_condition_key(self, check, fetcher, config):
        """Test that invalid condition key is only reported once even with multiple actions."""
        fetcher.validate_condition_key.return_value = (False, "Invalid condition key")

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should only report once, not three times
        assert len(issues) == 1
        assert issues[0].condition_key == "s3:invalidKey"

    @pytest.mark.asyncio
    async def test_statement_with_sid(self, check, fetcher, config):
        """Test that statement SID is captured."""
        fetcher.validate_condition_key.return_value = (False, "Invalid condition key")

        statement = Statement(
            Sid="TestStatement",
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].statement_sid == "TestStatement"

    @pytest.mark.asyncio
    async def test_statement_index(self, check, fetcher, config):
        """Test that statement index is captured."""
        fetcher.validate_condition_key.return_value = (False, "Invalid condition key")

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 7, fetcher, config)

        assert issues[0].statement_index == 7

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, fetcher, config):
        """Test that line number is captured when available."""
        fetcher.validate_condition_key.return_value = (False, "Invalid condition key")

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        statement.line_number = 55

        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].line_number == 55

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity from config."""
        fetcher.validate_condition_key.return_value = (False, "Invalid condition key")

        config = CheckConfig(check_id="condition_key_validation", severity="error")
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_error_message_fallback(self, check, fetcher, config):
        """Test fallback error message when none provided."""
        fetcher.validate_condition_key.return_value = (False, None)

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Invalid condition key: s3:invalidKey" in issues[0].message

    @pytest.mark.asyncio
    async def test_string_action(self, check, fetcher, config):
        """Test action as string instead of list."""
        fetcher.validate_condition_key.return_value = (True, None)

        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:prefix": "documents/"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        fetcher.validate_condition_key.assert_called_once_with("s3:GetObject", "s3:prefix")

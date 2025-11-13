"""Tests for condition type mismatch check."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.checks.condition_type_mismatch import ConditionTypeMismatchCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestConditionTypeMismatchCheck:
    """Test suite for ConditionTypeMismatchCheck."""

    @pytest.fixture
    def check(self):
        """Create a ConditionTypeMismatchCheck instance."""
        return ConditionTypeMismatchCheck()

    @pytest.fixture
    def fetcher(self):
        """Create a mock AWSServiceFetcher instance."""
        return MagicMock(spec=AWSServiceFetcher)

    @pytest.fixture
    def config(self):
        """Create a default CheckConfig."""
        return CheckConfig(check_id="condition_type_mismatch")

    def test_check_id(self, check):
        """Test check_id property."""
        assert check.check_id == "condition_type_mismatch"

    def test_description(self, check):
        """Test description property."""
        assert (
            check.description
            == "Validates condition operator types match key types and value formats"
        )

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

    @pytest.mark.asyncio
    async def test_valid_string_operator_with_string_key(self, check, fetcher, config):
        """Test StringEquals with a String type global key."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"aws:username": "admin"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_bool_operator_with_bool_key(self, check, fetcher, config):
        """Test Bool with a Bool type global key."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"Bool": {"aws:SecureTransport": "true"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_date_operator_with_date_key(self, check, fetcher, config):
        """Test DateGreaterThan with a Date type global key."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateGreaterThan": {"aws:CurrentTime": "2019-07-16T12:00:00Z"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_numeric_operator_with_numeric_key(self, check, fetcher, config):
        """Test NumericLessThan with a Numeric type global key."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_ipaddress_operator_with_ip_key(self, check, fetcher, config):
        """Test IpAddress with an IPAddress type global key."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_operator_with_arn_key(self, check, fetcher, config):
        """Test ArnEquals with an ARN type global key."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={
                "ArnEquals": {
                    "aws:SourceArn": "arn:aws:iam::123456789012:user/test"
                }
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_operator_ifexists_suffix(self, check, fetcher, config):
        """Test operator with IfExists suffix is normalized correctly."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEqualsIfExists": {"aws:username": "admin"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_operator_forallvalues_prefix(self, check, fetcher, config):
        """Test operator with ForAllValues prefix is normalized correctly."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"ForAllValues:StringLike": {"aws:username": "admin*"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_type_mismatch_numeric_with_string(self, check, fetcher, config):
        """Test type mismatch: NumericEquals with String key."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"NumericEquals": {"aws:username": "123"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) >= 1
        # Should have a type mismatch issue
        type_mismatch_issues = [i for i in issues if i.issue_type == "type_mismatch"]
        assert len(type_mismatch_issues) >= 1
        assert "Type mismatch" in type_mismatch_issues[0].message

    @pytest.mark.asyncio
    async def test_type_mismatch_string_with_arn_generates_warning(
        self, check, fetcher, config
    ):
        """Test String operator with ARN key generates warning (usable but not recommended)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={
                "StringEquals": {
                    "aws:SourceArn": "arn:aws:iam::123456789012:user/test"
                }
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "warning"
        assert issues[0].issue_type == "type_mismatch_usable"
        assert "ArnEquals" in issues[0].message and "ArnLike" in issues[0].message

    @pytest.mark.asyncio
    async def test_invalid_date_format(self, check, fetcher, config):
        """Test invalid date format for Date type key."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateGreaterThan": {"aws:CurrentTime": "2019-07-16"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) >= 1
        format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(format_issues) >= 1
        assert "Invalid value format" in format_issues[0].message

    @pytest.mark.asyncio
    async def test_invalid_bool_format(self, check, fetcher, config):
        """Test invalid boolean format for Bool type key."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"Bool": {"aws:SecureTransport": "yes"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) >= 1
        format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(format_issues) >= 1
        assert "Invalid value format" in format_issues[0].message

    @pytest.mark.asyncio
    async def test_invalid_ipaddress_format(self, check, fetcher, config):
        """Test invalid IP address format."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"IpAddress": {"aws:SourceIp": "invalid-ip"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) >= 1
        format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(format_issues) >= 1

    @pytest.mark.asyncio
    async def test_invalid_arn_format(self, check, fetcher, config):
        """Test invalid ARN format."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"ArnEquals": {"aws:SourceArn": "not-an-arn"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) >= 1
        format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(format_issues) >= 1

    @pytest.mark.asyncio
    async def test_null_operator_skipped(self, check, fetcher, config):
        """Test that Null operator is skipped (it doesn't need type validation)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"Null": {"aws:username": "true"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Null operator should be skipped
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_action_skipped(self, check, fetcher, config):
        """Test that wildcard actions are skipped."""
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:username": "admin"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should still validate the global condition key
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_multiple_condition_keys(self, check, fetcher, config):
        """Test multiple condition keys in one operator."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={
                "StringEquals": {
                    "aws:username": "admin",
                    "aws:PrincipalAccount": "123456789012",
                }
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_multiple_operators(self, check, fetcher, config):
        """Test multiple operators in condition."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={
                "StringEquals": {"aws:username": "admin"},
                "IpAddress": {"aws:SourceIp": "203.0.113.0/24"},
                "Bool": {"aws:SecureTransport": "true"},
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_array_of_values(self, check, fetcher, config):
        """Test condition with array of values."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"aws:username": ["admin", "user1", "user2"]}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_ipv6_address(self, check, fetcher, config):
        """Test valid IPv6 address format."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"IpAddress": {"aws:SourceIp": "2001:DB8::/32"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity from config."""
        config = CheckConfig(check_id="condition_type_mismatch", severity="warning")

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"NumericEquals": {"aws:username": "123"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Type mismatch should respect custom severity
        type_mismatch_issues = [i for i in issues if i.issue_type == "type_mismatch"]
        if type_mismatch_issues:
            assert type_mismatch_issues[0].severity == "warning"

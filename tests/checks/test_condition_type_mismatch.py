"""Tests for condition type mismatch check."""

from unittest.mock import MagicMock

import pytest

from iam_validator.checks.condition_type_mismatch import ConditionTypeMismatchCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
def check():
    return ConditionTypeMismatchCheck()


@pytest.fixture
def fetcher():
    return MagicMock(spec=AWSServiceFetcher)


@pytest.fixture
def config():
    return CheckConfig(check_id="condition_type_mismatch")


def _make_statement(condition):
    """Helper to create a statement with a given condition."""
    return Statement(
        Effect="Allow",
        Action=["s3:GetObject"],
        Resource=["arn:aws:s3:::bucket/*"],
        Condition=condition,
    )


class TestConditionTypeMismatchCheck:
    """Core condition type mismatch tests."""

    @pytest.mark.asyncio
    async def test_no_conditions(self, check, fetcher, config):
        """Test statement with no conditions."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::bucket/*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_operator_types(self, check, fetcher, config):
        """Test various valid operator-type combinations."""
        statement = _make_statement(
            {
                "StringEquals": {"aws:username": "admin"},
                "Bool": {"aws:SecureTransport": "true"},
                "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"},
                "IpAddress": {"aws:SourceIp": "203.0.113.0/24"},
            }
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_type_mismatch_numeric_with_string(self, check, fetcher, config):
        """Test type mismatch: NumericEquals with String key."""
        statement = _make_statement({"NumericEquals": {"aws:username": "123"}})
        issues = await check.execute(statement, 0, fetcher, config)
        type_mismatch = [i for i in issues if i.issue_type == "type_mismatch"]
        assert len(type_mismatch) >= 1

    @pytest.mark.asyncio
    async def test_type_mismatch_string_with_arn_warning(self, check, fetcher, config):
        """Test String operator with ARN key generates warning."""
        statement = _make_statement({"StringEquals": {"aws:SourceArn": "arn:aws:iam::123456789012:user/test"}})
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "warning"
        assert issues[0].issue_type == "type_mismatch_usable"

    @pytest.mark.asyncio
    async def test_invalid_value_formats(self, check, fetcher, config):
        """Test invalid value formats are detected."""
        # Invalid date format
        stmt1 = _make_statement({"DateGreaterThan": {"aws:CurrentTime": "2019-13-45T12:00:00Z"}})
        issues1 = await check.execute(stmt1, 0, fetcher, config)
        assert any(i.issue_type == "invalid_value_format" for i in issues1)

        # Invalid bool format
        stmt2 = _make_statement({"Bool": {"aws:SecureTransport": "yes"}})
        issues2 = await check.execute(stmt2, 0, fetcher, config)
        assert any(i.issue_type == "invalid_value_format" for i in issues2)

    @pytest.mark.asyncio
    async def test_null_operator_skipped(self, check, fetcher, config):
        """Test that Null operator is skipped."""
        statement = _make_statement({"Null": {"aws:username": "true"}})
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0


class TestEnhancedDateValidation:
    """Test suite for enhanced ISO 8601 date validation."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "date_value",
        [
            "2025-12-31T23:59:59Z",
            "2025-12-31T23:59:59+00:00",
            "2025-12-31T23:59:59.999Z",
            "2025-01-01T12:00:00-05:00",
            "2024-02-29T12:00:00Z",  # Leap year
            "2019-07-16",  # Date-only format
        ],
    )
    async def test_valid_date_formats(self, date_value, check, fetcher, config):
        """Valid date formats should not produce format errors."""
        statement = _make_statement({"DateLessThan": {"aws:CurrentTime": date_value}})
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "invalid_value_format" for i in issues)

    @pytest.mark.asyncio
    async def test_valid_unix_epoch_timestamp(self, check, fetcher, config):
        """Valid UNIX epoch timestamp."""
        statement = _make_statement({"DateGreaterThan": {"aws:CurrentTime": "1735689600"}})
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "invalid_value_format" for i in issues)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "date_value",
        [
            "2025-13-01T12:00:00Z",  # Month 13
            "2025-01-32T12:00:00Z",  # Day 32
            "2025-02-30T12:00:00Z",  # Feb 30
            "2025-02-29T12:00:00Z",  # Feb 29 non-leap
            "2025-01-01T25:00:00Z",  # Hour 25
            "2025-01-01T12:60:00Z",  # Minute 60
            "2025-01-01T12:00:00+15:00",  # TZ offset > 14h
        ],
    )
    async def test_invalid_date_formats(self, date_value, check, fetcher, config):
        """Invalid date formats should be detected."""
        statement = _make_statement({"DateLessThan": {"aws:CurrentTime": date_value}})
        issues = await check.execute(statement, 0, fetcher, config)
        date_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_issues) == 1


class TestOperatorValueFormatValidation:
    """Tests for operator-specific value format validation (CIDR, ARN, Bool)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "ip_value",
        [
            "203.0.113.0/24",  # IPv4 CIDR
            "2001:db8::/32",  # IPv6 CIDR
            "203.0.113.1",  # Single IP
        ],
    )
    async def test_valid_ip_formats(self, ip_value, check, fetcher, config):
        """Valid IP/CIDR formats should not be flagged."""
        statement = _make_statement({"IpAddress": {"aws:SourceIp": ip_value}})
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "invalid_ip_cidr_format" for i in issues)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operator", ["IpAddress", "NotIpAddress", "IpAddressIfExists"])
    async def test_invalid_cidr_formats(self, operator, check, fetcher, config):
        """Invalid CIDR formats should be flagged across all IP operators."""
        statement = _make_statement({operator: {"custom:SourceIp": "not-a-cidr"}})
        issues = await check.execute(statement, 0, fetcher, config)
        cidr_issues = [i for i in issues if i.issue_type == "invalid_ip_cidr_format"]
        assert len(cidr_issues) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "arn_value",
        [
            "arn:aws:s3:::my-bucket",
            "*",
            "${aws:SourceArn}",
        ],
    )
    async def test_valid_arn_values(self, arn_value, check, fetcher, config):
        """Valid ARN values should not be flagged."""
        statement = _make_statement({"ArnEquals": {"aws:SourceArn": arn_value}})
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "invalid_arn_format_for_operator" for i in issues)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operator", ["ArnEquals", "ArnNotLike"])
    async def test_invalid_arn_values(self, operator, check, fetcher, config):
        """Non-ARN values should be flagged for ARN operators."""
        statement = _make_statement({operator: {"custom:ResourceArn": "not-an-arn"}})
        issues = await check.execute(statement, 0, fetcher, config)
        arn_issues = [i for i in issues if i.issue_type == "invalid_arn_format_for_operator"]
        assert len(arn_issues) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", ["true", "false"])
    async def test_valid_bool_values(self, value, check, fetcher, config):
        """Bool operator with 'true'/'false' should be valid."""
        statement = _make_statement({"Bool": {"aws:SecureTransport": value}})
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "invalid_bool_value_for_operator" for i in issues)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", ["yes", "1", ""])
    async def test_invalid_bool_values(self, value, check, fetcher, config):
        """Bool operator with non-bool strings should be flagged."""
        statement = _make_statement({"Bool": {"custom:IsEnabled": value}})
        issues = await check.execute(statement, 0, fetcher, config)
        bool_issues = [i for i in issues if i.issue_type == "invalid_bool_value_for_operator"]
        assert len(bool_issues) == 1


class TestNullIfExistsDetection:
    """Test NullIfExists is detected as invalid syntax."""

    @pytest.mark.asyncio
    async def test_null_ifexists_is_error(self, check, fetcher, config):
        """NullIfExists should be flagged as invalid operator."""
        statement = _make_statement({"NullIfExists": {"aws:MultiFactorAuthPresent": "true"}})
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_operator"
        assert "NullIfExists" in issues[0].message
        assert "does not support" in issues[0].message

    @pytest.mark.asyncio
    async def test_null_without_ifexists_still_skipped(self, check, fetcher, config):
        """Regular Null operator should still be skipped."""
        statement = _make_statement({"Null": {"aws:MultiFactorAuthPresent": "true"}})
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_other_ifexists_operators_not_flagged(self, check, fetcher, config):
        """StringEqualsIfExists should NOT trigger NullIfExists error."""
        statement = _make_statement({"StringEqualsIfExists": {"aws:SourceIp": "1.2.3.4"}})
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "invalid_operator" for i in issues)

    @pytest.mark.asyncio
    async def test_foranyvalue_null_ifexists_is_error(self, check, fetcher, config):
        """ForAnyValue:NullIfExists should also be flagged."""
        statement = _make_statement({"ForAnyValue:NullIfExists": {"aws:TagKeys": "true"}})
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_operator"

"""Tests for condition type mismatch check."""

from unittest.mock import MagicMock

import pytest

from iam_validator.checks.condition_type_mismatch import ConditionTypeMismatchCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestConditionTypeMismatchCheck:
    """Test suite for ConditionTypeMismatchCheck."""

    @pytest.fixture
    def check(self):
        return ConditionTypeMismatchCheck()

    @pytest.fixture
    def fetcher(self):
        return MagicMock(spec=AWSServiceFetcher)

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="condition_type_mismatch")

    @pytest.mark.asyncio
    async def test_no_conditions(self, check, fetcher, config):
        """Test statement with no conditions."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_string_operator(self, check, fetcher, config):
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
    async def test_valid_operator_types(self, check, fetcher, config):
        """Test various valid operator-type combinations."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={
                "Bool": {"aws:SecureTransport": "true"},
                "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"},
                "IpAddress": {"aws:SourceIp": "203.0.113.0/24"},
            },
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
        type_mismatch = [i for i in issues if i.issue_type == "type_mismatch"]
        assert len(type_mismatch) >= 1

    @pytest.mark.asyncio
    async def test_type_mismatch_string_with_arn_warning(self, check, fetcher, config):
        """Test String operator with ARN key generates warning."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"aws:SourceArn": "arn:aws:iam::123456789012:user/test"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "warning"
        assert issues[0].issue_type == "type_mismatch_usable"

    @pytest.mark.asyncio
    async def test_invalid_value_formats(self, check, fetcher, config):
        """Test invalid value formats are detected."""
        # Invalid date format - semantically invalid (month 13 doesn't exist)
        # Note: "2019-07-16" (date-only) is now correctly accepted as valid
        statement1 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateGreaterThan": {"aws:CurrentTime": "2019-13-45T12:00:00Z"}},
        )
        issues1 = await check.execute(statement1, 0, fetcher, config)
        assert any(i.issue_type == "invalid_value_format" for i in issues1)

        # Invalid bool format
        statement2 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"Bool": {"aws:SecureTransport": "yes"}},
        )
        issues2 = await check.execute(statement2, 0, fetcher, config)
        assert any(i.issue_type == "invalid_value_format" for i in issues2)

    @pytest.mark.asyncio
    async def test_null_operator_skipped(self, check, fetcher, config):
        """Test that Null operator is skipped."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"Null": {"aws:username": "true"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0


class TestEnhancedDateValidation:
    """Test suite for enhanced ISO 8601 date validation."""

    @pytest.fixture
    def check(self):
        return ConditionTypeMismatchCheck()

    @pytest.fixture
    def fetcher(self):
        return MagicMock(spec=AWSServiceFetcher)

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="condition_type_mismatch")

    @pytest.mark.asyncio
    async def test_valid_iso8601_utc_date(self, check, fetcher, config):
        """Test valid ISO 8601 date with Z suffix."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2025-12-31T23:59:59Z"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 0

    @pytest.mark.asyncio
    async def test_valid_iso8601_with_timezone_offset(self, check, fetcher, config):
        """Test valid ISO 8601 date with timezone offset."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2025-12-31T23:59:59+00:00"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 0

    @pytest.mark.asyncio
    async def test_valid_iso8601_with_milliseconds(self, check, fetcher, config):
        """Test valid ISO 8601 date with milliseconds."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2025-12-31T23:59:59.999Z"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 0

    @pytest.mark.asyncio
    async def test_valid_unix_epoch_timestamp(self, check, fetcher, config):
        """Test valid UNIX epoch timestamp."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateGreaterThan": {"aws:CurrentTime": "1735689600"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 0

    @pytest.mark.asyncio
    async def test_invalid_month_13(self, check, fetcher, config):
        """Test that month 13 is detected as invalid."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2025-13-01T12:00:00Z"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 1

    @pytest.mark.asyncio
    async def test_invalid_day_32(self, check, fetcher, config):
        """Test that day 32 is detected as invalid."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2025-01-32T12:00:00Z"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 1

    @pytest.mark.asyncio
    async def test_invalid_february_30(self, check, fetcher, config):
        """Test that February 30 is detected as invalid."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2025-02-30T12:00:00Z"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 1

    @pytest.mark.asyncio
    async def test_valid_february_29_leap_year(self, check, fetcher, config):
        """Test that February 29 in a leap year is valid."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2024-02-29T12:00:00Z"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 0

    @pytest.mark.asyncio
    async def test_invalid_february_29_non_leap_year(self, check, fetcher, config):
        """Test that February 29 in a non-leap year is invalid."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2025-02-29T12:00:00Z"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 1

    @pytest.mark.asyncio
    async def test_invalid_hour_25(self, check, fetcher, config):
        """Test that hour 25 is detected as invalid."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2025-01-01T25:00:00Z"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 1

    @pytest.mark.asyncio
    async def test_invalid_minute_60(self, check, fetcher, config):
        """Test that minute 60 is detected as invalid."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2025-01-01T12:60:00Z"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 1

    @pytest.mark.asyncio
    async def test_invalid_date_format_no_time(self, check, fetcher, config):
        """Test that incomplete date format without time is detected."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateGreaterThan": {"aws:CurrentTime": "2019-07-16"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        # Note: Date-only format is actually valid in some contexts
        # The new validator accepts "YYYY-MM-DD" format
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 0

    @pytest.mark.asyncio
    async def test_invalid_timezone_offset_15_hours(self, check, fetcher, config):
        """Test that timezone offset > 14 hours is detected as invalid."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2025-01-01T12:00:00+15:00"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 1

    @pytest.mark.asyncio
    async def test_valid_negative_timezone_offset(self, check, fetcher, config):
        """Test valid negative timezone offset."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateLessThan": {"aws:CurrentTime": "2025-01-01T12:00:00-05:00"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        date_format_issues = [i for i in issues if i.issue_type == "invalid_value_format"]
        assert len(date_format_issues) == 0

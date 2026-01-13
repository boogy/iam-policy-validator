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
        # Invalid date format
        statement1 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"DateGreaterThan": {"aws:CurrentTime": "2019-07-16"}},
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

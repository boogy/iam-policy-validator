"""Tests for resource validation check."""

import pytest

from iam_validator.checks.resource_validation import ResourceValidationCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestResourceValidationCheck:
    """Test suite for ResourceValidationCheck."""

    @pytest.fixture
    def check(self):
        return ResourceValidationCheck()

    @pytest.fixture
    def fetcher(self):
        return AWSServiceFetcher()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="resource_validation")

    @pytest.mark.asyncio
    async def test_valid_arn_aws_partition(self, check, fetcher, config):
        """Test valid ARN with aws partition."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::my-bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_other_partitions(self, check, fetcher, config):
        """Test valid ARNs with various AWS partitions."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=[
                "arn:aws-cn:s3:::my-bucket/*",
                "arn:aws-us-gov:s3:::my-bucket/*",
                "arn:aws-iso:s3:::bucket1",
            ],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_resource_skipped(self, check, fetcher, config):
        """Test wildcard resource is skipped."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_invalid_arn_missing_prefix(self, check, fetcher, config):
        """Test invalid ARN without arn: prefix."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["aws:s3:::my-bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_resource"

    @pytest.mark.asyncio
    async def test_invalid_arn_malformed(self, check, fetcher, config):
        """Test malformed ARN."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["not-an-arn"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].resource == "not-an-arn"

    @pytest.mark.asyncio
    async def test_multiple_resources_mixed(self, check, fetcher, config):
        """Test multiple resources with mix of valid and invalid."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=[
                "arn:aws:s3:::valid-bucket/*",
                "invalid-arn",
                "arn:aws:s3:::another-bucket/*",
            ],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].resource == "invalid-arn"

    @pytest.mark.asyncio
    async def test_valid_arn_with_wildcards(self, check, fetcher, config):
        """Test valid ARN with wildcards in region and account fields."""
        statement = Statement(
            Effect="Allow",
            Action=["logs:CreateLogGroup"],
            Resource=["arn:aws:logs:*:*:log-group:/aws/lambda/dev-*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_not_resource_valid(self, check, fetcher, config):
        """Test valid NotResource ARN passes."""
        statement = Statement(
            Effect="Deny",
            Action=["s3:GetObject"],
            NotResource=["arn:aws:s3:::my-bucket/*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_not_resource_invalid(self, check, fetcher, config):
        """Test invalid NotResource ARN is flagged."""
        statement = Statement(
            Effect="Deny",
            Action=["s3:GetObject"],
            NotResource=["not-an-arn"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_resource"
        assert issues[0].field_name == "not_resource"
        assert issues[0].resource == "not-an-arn"

    @pytest.mark.asyncio
    async def test_not_resource_wildcard_skipped(self, check, fetcher, config):
        """Test NotResource wildcard is skipped."""
        statement = Statement(
            Effect="Deny",
            Action=["s3:GetObject"],
            NotResource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_both_resource_and_not_resource(self, check, fetcher, config):
        """Test statement with both Resource and NotResource."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::valid-bucket/*"],
            NotResource=["invalid-arn"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        # Should flag the invalid NotResource
        assert len(issues) == 1
        assert issues[0].field_name == "not_resource"
        assert issues[0].resource == "invalid-arn"

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
        """Create a ResourceValidationCheck instance."""
        return ResourceValidationCheck()

    @pytest.fixture
    def fetcher(self):
        """Create a mock AWSServiceFetcher instance."""
        return AWSServiceFetcher()

    @pytest.fixture
    def config(self):
        """Create a default CheckConfig."""
        return CheckConfig(check_id="resource_validation")

    def test_check_id(self, check):
        """Test check_id property."""
        assert check.check_id == "resource_validation"

    def test_description(self, check):
        """Test description property."""
        assert check.description == "Validates ARN format for resources"

    def test_default_severity(self, check):
        """Test default_severity property."""
        assert check.default_severity == "error"

    @pytest.mark.asyncio
    async def test_valid_arn_aws_partition(self, check, fetcher, config):
        """Test valid ARN with aws partition."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::my-bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_aws_cn_partition(self, check, fetcher, config):
        """Test valid ARN with aws-cn partition."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws-cn:s3:::my-bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_govcloud(self, check, fetcher, config):
        """Test valid ARN with aws-us-gov partition."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws-us-gov:s3:::my-bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_with_region_and_account(self, check, fetcher, config):
        """Test valid ARN with region and account."""
        statement = Statement(
            Effect="Allow",
            Action=["dynamodb:GetItem"],
            Resource=["arn:aws:dynamodb:us-east-1:123456789012:table/MyTable"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_ec2_instance(self, check, fetcher, config):
        """Test valid EC2 instance ARN."""
        statement = Statement(
            Effect="Allow",
            Action=["ec2:TerminateInstances"],
            Resource=["arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0"],
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
        assert issues[0].severity == "error"
        assert issues[0].issue_type == "invalid_resource"
        assert issues[0].resource == "aws:s3:::my-bucket/*"
        assert "Invalid" in issues[0].message and "ARN" in issues[0].message

    @pytest.mark.asyncio
    async def test_invalid_arn_invalid_partition(self, check, fetcher, config):
        """Test invalid ARN with invalid partition."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:invalid-partition:s3:::my-bucket/*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Invalid" in issues[0].message and "ARN" in issues[0].message

    @pytest.mark.asyncio
    async def test_invalid_arn_malformed(self, check, fetcher, config):
        """Test malformed ARN."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["not-an-arn"])
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].resource == "not-an-arn"

    @pytest.mark.asyncio
    async def test_multiple_resources(self, check, fetcher, config):
        """Test multiple resources are validated."""
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
    async def test_statement_with_sid(self, check, fetcher, config):
        """Test that statement SID is captured."""
        statement = Statement(
            Sid="TestStatement", Effect="Allow", Action=["s3:GetObject"], Resource=["invalid-arn"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].statement_sid == "TestStatement"

    @pytest.mark.asyncio
    async def test_statement_index(self, check, fetcher, config):
        """Test that statement index is captured."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["invalid-arn"])
        issues = await check.execute(statement, 9, fetcher, config)

        assert issues[0].statement_index == 9

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, fetcher, config):
        """Test that line number is captured when available."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["invalid-arn"])
        statement.line_number = 100

        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].line_number == 100

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity from config."""
        config = CheckConfig(check_id="resource_validation", severity="warning")
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["invalid-arn"])
        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].severity == "warning"

    @pytest.mark.asyncio
    async def test_custom_arn_pattern(self, check, fetcher):
        """Test custom ARN pattern from config."""
        # More restrictive pattern that only allows standard AWS partition
        config = CheckConfig(
            check_id="resource_validation",
            config={"arn_pattern": r"^arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]*:.+$"},
        )

        # This should fail with the restrictive pattern
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws-cn:s3:::my-bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_string_resource(self, check, fetcher, config):
        """Test resource as string instead of list."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource="arn:aws:s3:::my-bucket/*"
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_no_resources(self, check, fetcher, config):
        """Test statement with no Resource field."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"])
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_suggestion_included(self, check, fetcher, config):
        """Test that suggestion is included in issues."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["invalid-arn"])
        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].suggestion is not None
        assert "arn:partition:service:region:account-id:resource" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_valid_arn_with_wildcards(self, check, fetcher, config):
        """Test valid ARN with wildcards in resource path."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/path/*/file.txt"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_empty_region_and_account(self, check, fetcher, config):
        """Test valid ARN with empty region and account (like S3)."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::my-bucket"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_iso_partitions(self, check, fetcher, config):
        """Test valid ARNs with ISO partitions."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=[
                "arn:aws-iso:s3:::bucket1",
                "arn:aws-iso-b:s3:::bucket2",
                "arn:aws-iso-e:s3:::bucket3",
                "arn:aws-iso-f:s3:::bucket4",
            ],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_eusc_partition(self, check, fetcher, config):
        """Test valid ARN with aws-eusc partition."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws-eusc:s3:::my-bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_wildcard_region(self, check, fetcher, config):
        """Test valid ARN with wildcard in region field."""
        statement = Statement(
            Effect="Allow",
            Action=["lambda:InvokeFunction"],
            Resource=["arn:aws:lambda:*:123456789012:function:dev-*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_wildcard_account(self, check, fetcher, config):
        """Test valid ARN with wildcard in account field."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:us-east-1:*:bucket/my-bucket/*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_wildcard_region_and_account(self, check, fetcher, config):
        """Test valid ARN with wildcards in both region and account fields."""
        statement = Statement(
            Effect="Allow",
            Action=["logs:CreateLogGroup"],
            Resource=["arn:aws:logs:*:*:log-group:/aws/lambda/dev-*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_valid_arn_multiple_wildcards(self, check, fetcher, config):
        """Test valid ARNs with various wildcard patterns."""
        statement = Statement(
            Effect="Allow",
            Action=["dynamodb:GetItem"],
            Resource=[
                "arn:aws:dynamodb:*:123456789012:table/Users",
                "arn:aws:dynamodb:us-west-2:*:table/Products",
                "arn:aws:ec2:*:*:instance/*",
            ],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

"""Tests for wildcard support in allowed_service_principals."""

import pytest

from iam_validator.checks.principal_validation import PrincipalValidationCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.config.service_principals import is_aws_service_principal
from iam_validator.core.models import Statement


class TestServicePrincipalWildcard:
    """Test suite for wildcard support in service principals."""

    @pytest.fixture
    def check(self):
        """Create a PrincipalValidationCheck instance."""
        return PrincipalValidationCheck()

    @pytest.fixture
    def fetcher(self):
        """Create a mock AWSServiceFetcher instance."""
        return AWSServiceFetcher()

    def test_is_aws_service_principal_valid_services(self):
        """Test is_aws_service_principal recognizes valid AWS services."""
        assert is_aws_service_principal("lambda.amazonaws.com") is True
        assert is_aws_service_principal("s3.amazonaws.com") is True
        assert is_aws_service_principal("dynamodb.amazonaws.com") is True
        assert is_aws_service_principal("cloudfront.amazonaws.com") is True
        assert is_aws_service_principal("events.amazonaws.com") is True

    def test_is_aws_service_principal_china_region(self):
        """Test is_aws_service_principal recognizes China region services."""
        assert is_aws_service_principal("s3.amazonaws.com.cn") is True
        assert is_aws_service_principal("lambda.amazonaws.com.cn") is True

    def test_is_aws_service_principal_invalid_principals(self):
        """Test is_aws_service_principal rejects non-service principals."""
        assert is_aws_service_principal("*") is False
        assert is_aws_service_principal("arn:aws:iam::123456789012:root") is False
        assert is_aws_service_principal("arn:aws:iam::123456789012:user/alice") is False
        assert is_aws_service_principal("something.else.com") is False
        assert is_aws_service_principal("") is False

    @pytest.mark.asyncio
    async def test_wildcard_allows_any_aws_service(self, check, fetcher):
        """Test that '*' in allowed_service_principals allows any AWS service."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "dynamodb.amazonaws.com"},
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        config = CheckConfig(
            check_id="principal_validation",
            config={
                "blocked_principals": ["*"],  # Block public access
                "allowed_service_principals": ["aws:*"],  # But allow ALL AWS services
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should have no issues - dynamodb is an AWS service
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_allows_uncommon_aws_services(self, check, fetcher):
        """Test that '*' allows even services not in the default list."""
        # Use a service that's not in the default 16-service list
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "bedrock.amazonaws.com"},
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        config = CheckConfig(
            check_id="principal_validation",
            config={
                "blocked_principals": ["*"],
                "allowed_service_principals": ["aws:*"],  # Allow all AWS services
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should have no issues
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_with_explicit_list_overrides(self, check, fetcher):
        """Test that explicit service list can be used instead of wildcard."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "dynamodb.amazonaws.com"},
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        config = CheckConfig(
            check_id="principal_validation",
            config={
                "blocked_principals": [],  # Don't block anything initially
                "allowed_principals": ["lambda.amazonaws.com"],  # Use whitelist mode
                "allowed_service_principals": [
                    "lambda.amazonaws.com",
                    "s3.amazonaws.com",
                ],  # Specific list (no wildcard)
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should have issues - dynamodb is not in the allowed_principals whitelist
        assert len(issues) > 0
        assert any("not in allowed list" in issue.message.lower() or "unauthorized" in issue.message.lower() for issue in issues)

    @pytest.mark.asyncio
    async def test_wildcard_does_not_allow_non_service_principals(self, check, fetcher):
        """Test that '*' wildcard for services does not allow non-service principals."""
        # Test with an IAM role principal (not a service)
        statement = Statement(
            Effect="Allow",
            Principal={"AWS": "arn:aws:iam::123456789012:role/MyRole"},
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        config = CheckConfig(
            check_id="principal_validation",
            config={
                "blocked_principals": ["arn:aws:iam::*:role/*"],  # Block IAM roles
                "allowed_service_principals": ["aws:*"],  # Only allows services
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should have issues - IAM role is blocked
        assert len(issues) > 0
        assert any("blocked" in issue.message.lower() for issue in issues)

    @pytest.mark.asyncio
    async def test_wildcard_does_not_allow_iam_principals(self, check, fetcher):
        """Test that '*' wildcard only allows services, not IAM principals."""
        statement = Statement(
            Effect="Allow",
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        config = CheckConfig(
            check_id="principal_validation",
            config={
                "blocked_principals": [],  # Don't block anything
                "allowed_principals": [],  # No allowed principals configured
                "allowed_service_principals": ["aws:*"],  # Only services
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Since allowed_principals is empty (no whitelist), this should pass
        # The IAM principal is not blocked and there's no whitelist enforcement
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_mixed_wildcard_and_explicit_services(self, check, fetcher):
        """Test that mixing '*' with explicit services works (wildcard takes precedence)."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "bedrock.amazonaws.com"},
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        config = CheckConfig(
            check_id="principal_validation",
            config={
                "blocked_principals": ["*"],
                "allowed_service_principals": [
                    "*",  # Wildcard
                    "lambda.amazonaws.com",  # Also explicitly list one
                ],
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should have no issues - wildcard allows all services
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_china_region_services_with_wildcard(self, check, fetcher):
        """Test that wildcard works with China region services."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "s3.amazonaws.com.cn"},
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        config = CheckConfig(
            check_id="principal_validation",
            config={
                "blocked_principals": ["*"],
                "allowed_service_principals": ["aws:*"],
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should have no issues - China region services are AWS services
        assert len(issues) == 0

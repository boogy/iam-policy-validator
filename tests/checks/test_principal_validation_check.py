"""Tests for PrincipalValidationCheck."""

import pytest

from iam_validator.checks.principal_validation import PrincipalValidationCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
async def fetcher():
    """Create AWS service fetcher for tests."""
    async with AWSServiceFetcher(prefetch_common=False) as f:
        yield f


@pytest.fixture
def check():
    """Create PrincipalValidationCheck instance."""
    return PrincipalValidationCheck()


@pytest.fixture
def config():
    """Create default check config matching actual defaults."""
    return CheckConfig(
        check_id="principal_validation",
        enabled=True,
        config={
            "block_wildcard_principal": False,  # Default: allow * with conditions
            "blocked_principals": [],
            "allowed_principals": [],
            "allowed_service_principals": ["aws:*"],
        },
    )


class TestPrincipalValidationCheck:
    """Tests for PrincipalValidationCheck."""

    @pytest.mark.asyncio
    async def test_no_principal_no_issue(self, check, fetcher, config):
        """Test that statements without Principal don't trigger issues."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_blocked_principal_wildcard(self, check, fetcher):
        """Test that wildcard principal (*) can be blocked with strict mode."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "block_wildcard_principal": True,  # Strict mode: block * entirely
                "blocked_principals": [],
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "blocked_principal"

    @pytest.mark.asyncio
    async def test_service_principal_allowed(self, check, fetcher, config):
        """Test that service principals are allowed by default."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"Service": "lambda.amazonaws.com"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_aws_account_principal_allowed(self, check, fetcher, config):
        """Test that AWS account principals are allowed by default."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_allowed_principals_whitelist(self, check, fetcher):
        """Test that allowed_principals whitelist works."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "allowed_principals": ["arn:aws:iam::123456789012:root"],
            },
        )
        # This principal is in the whitelist
        statement1 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
        )
        issues1 = await check.execute(statement1, 0, fetcher, config)
        assert len(issues1) == 0

        # This principal is NOT in the whitelist
        statement2 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::999999999999:root"},
        )
        issues2 = await check.execute(statement2, 0, fetcher, config)
        assert len(issues2) == 1
        assert issues2[0].issue_type == "unauthorized_principal"

    @pytest.mark.asyncio
    async def test_not_principal_field(self, check, fetcher):
        """Test that NotPrincipal field is also validated when blocking enabled."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "block_wildcard_principal": True,  # Strict mode: block * entirely
                "blocked_principals": [],
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            NotPrincipal="*",
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "blocked_principal"


class TestPrincipalConditionRequirements:
    """Tests for advanced principal_condition_requirements feature."""

    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @pytest.mark.asyncio
    async def test_all_of_conditions(self, check, fetcher):
        """Test all_of logic - ALL conditions must be present."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": {
                            "all_of": [
                                {"condition_key": "aws:SourceArn"},
                                {"condition_key": "aws:SourceAccount"},
                            ]
                        },
                    }
                ],
            },
        )
        # Statement with only one condition
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
            Condition={"StringEquals": {"aws:SourceArn": "arn:aws:s3:::my-bucket"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "missing_principal_condition"
        assert "aws:SourceAccount" in issues[0].message

    @pytest.mark.asyncio
    async def test_any_of_conditions(self, check, fetcher):
        """Test any_of logic - at least ONE condition must be present."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": {
                            "any_of": [
                                {"condition_key": "aws:SourceIp"},
                                {"condition_key": "aws:SourceVpce"},
                            ]
                        },
                    }
                ],
            },
        )
        # Statement without any of the required conditions
        statement1 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )
        issues1 = await check.execute(statement1, 0, fetcher, config)
        assert len(issues1) == 1
        assert issues1[0].issue_type == "missing_principal_condition_any_of"

        # Statement with one of the conditions (should pass)
        statement2 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
            Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
        )
        issues2 = await check.execute(statement2, 0, fetcher, config)
        assert len(issues2) == 0

    @pytest.mark.asyncio
    async def test_none_of_conditions(self, check, fetcher):
        """Test none_of logic - NONE of these conditions should be present."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": {
                            "none_of": [
                                {
                                    "condition_key": "aws:SecureTransport",
                                    "expected_value": False,
                                }
                            ]
                        },
                    }
                ],
            },
        )
        # Statement with forbidden condition
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
            Condition={"Bool": {"aws:SecureTransport": "false"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "forbidden_principal_condition"


class TestServicePrincipalWildcardDetection:
    """Tests for detecting dangerous service principal wildcards like {"Service": "*"}."""

    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @pytest.mark.asyncio
    async def test_detects_service_principal_wildcard_string(self, check, fetcher):
        """Test detection of {"Service": "*"} pattern."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],  # Don't block regular *
                "block_service_principal_wildcard": True,  # Block {"Service": "*"}
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": "*"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "service_principal_wildcard"
        assert issues[0].severity == "critical"
        assert "any aws service" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_detects_service_principal_wildcard_in_list(self, check, fetcher):
        """Test detection of {"Service": ["lambda.amazonaws.com", "*"]} pattern."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "block_service_principal_wildcard": True,
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": ["lambda.amazonaws.com", "*"]},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "service_principal_wildcard"
        assert issues[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_not_principal_service_wildcard_not_flagged(self, check, fetcher):
        """Test that NotPrincipal with {"Service": "*"} is NOT flagged.

        NotPrincipal: {"Service": "*"} means "allow everyone EXCEPT all services"
        which is overly broad exclusion but NOT an overly permissive grant.
        The service_principal_wildcard check only applies to Principal field.
        """
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "block_service_principal_wildcard": True,
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            NotPrincipal={"Service": "*"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        # Should have no service_principal_wildcard issues for NotPrincipal
        service_wildcard_issues = [
            i for i in issues if i.issue_type == "service_principal_wildcard"
        ]
        assert len(service_wildcard_issues) == 0

    @pytest.mark.asyncio
    async def test_allows_specific_service_principals(self, check, fetcher):
        """Test that specific service principals are still allowed."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "block_service_principal_wildcard": True,
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": "lambda.amazonaws.com"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_allows_multiple_specific_service_principals(self, check, fetcher):
        """Test that multiple specific service principals are allowed."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "block_service_principal_wildcard": True,
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": ["lambda.amazonaws.com", "ec2.amazonaws.com"]},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_can_disable_service_principal_wildcard_check(self, check, fetcher):
        """Test that the check can be disabled via config."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "block_service_principal_wildcard": False,  # Explicitly disabled
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": "*"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        # Should have no issues because check is disabled
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_default_behavior_blocks_service_principal_wildcard(self, check, fetcher):
        """Test that service principal wildcards are blocked by default."""
        # Use default config (no explicit block_service_principal_wildcard setting)
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": "*"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        # Should detect issue because default is to block
        assert len(issues) == 1
        assert issues[0].issue_type == "service_principal_wildcard"

    @pytest.mark.asyncio
    async def test_does_not_flag_aws_principal_wildcard(self, check, fetcher):
        """Test that {"AWS": "*"} is handled by blocked_principals, not this check."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],  # Don't block AWS wildcards
                "block_service_principal_wildcard": True,
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Principal={"AWS": "*"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        # Should have no service_principal_wildcard issues
        service_wildcard_issues = [
            i for i in issues if i.issue_type == "service_principal_wildcard"
        ]
        assert len(service_wildcard_issues) == 0

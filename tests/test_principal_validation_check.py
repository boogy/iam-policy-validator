"""Tests for PrincipalValidationCheck."""

import pytest

from iam_validator.checks.principal_validation import PrincipalValidationCheck
from iam_validator.core.aws_fetcher import AWSServiceFetcher
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
    """Create default check config with proper defaults."""
    return CheckConfig(
        check_id="principal_validation",
        enabled=True,
        config={
            "blocked_principals": ["*"],  # Block public access by default
            "allowed_principals": [],
            "allowed_service_principals": ["aws:*"],  # Allow all AWS service principals
        },
    )


class TestPrincipalValidationCheck:
    """Tests for PrincipalValidationCheck."""

    def test_check_id(self, check):
        """Test check ID."""
        assert check.check_id == "principal_validation"

    def test_description(self, check):
        """Test check description."""
        assert "principal" in check.description.lower()

    def test_default_severity(self, check):
        """Test default severity is high."""
        assert check.default_severity == "high"

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
    async def test_blocked_principal_wildcard(self, check, fetcher, config):
        """Test that wildcard principal (*) is blocked by default."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].issue_type == "blocked_principal"
        assert "*" in issues[0].message

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
    async def test_custom_blocked_principals(self, check, fetcher):
        """Test custom blocked principals configuration."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": ["*", "arn:aws:iam::123456789012:*"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:user/test"},
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].issue_type == "blocked_principal"

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
    async def test_wildcard_patterns_in_allowed_principals(self, check, fetcher):
        """Test that wildcard patterns work in allowed_principals."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "allowed_principals": ["arn:aws:iam::123456789012:*"],
            },
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:user/test"},
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_principal_as_dict_with_list(self, check, fetcher, config):
        """Test principal with dict containing list of principals."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={
                "AWS": [
                    "arn:aws:iam::123456789012:root",
                    "arn:aws:iam::999999999999:root",
                ]
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # No blocked principals in the list
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_not_principal_field(self, check, fetcher, config):
        """Test that NotPrincipal field is also validated."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            NotPrincipal="*",
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # NotPrincipal with "*" should still be checked
        assert len(issues) == 1
        assert issues[0].issue_type == "blocked_principal"

    @pytest.mark.asyncio
    async def test_statement_with_sid(self, check, fetcher, config):
        """Test that statement SID is captured in issue."""
        statement = Statement(
            Sid="PublicAccess",
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_sid == "PublicAccess"

    @pytest.mark.asyncio
    async def test_statement_index(self, check, fetcher, config):
        """Test that statement index is captured."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )

        issues = await check.execute(statement, 4, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_index == 4

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, fetcher, config):
        """Test that line number is captured when available."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
            line_number=75,
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].line_number == 75

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity override."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            severity="critical",
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_custom_service_principals(self, check, fetcher):
        """Test custom allowed service principals configuration."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                # Need to have at least one allowed_principal to enable whitelist mode
                "allowed_principals": ["arn:aws:iam::*:role/*"],
                "allowed_service_principals": ["lambda.amazonaws.com"],
            },
        )

        # Lambda should be allowed (service principals always allowed)
        statement1 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"Service": "lambda.amazonaws.com"},
        )

        issues1 = await check.execute(statement1, 0, fetcher, config)
        assert len(issues1) == 0

        # S3 should NOT be allowed (not in custom allowed_service_principals list)
        statement2 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"Service": "s3.amazonaws.com"},
        )

        issues2 = await check.execute(statement2, 0, fetcher, config)
        assert len(issues2) == 1
        assert issues2[0].issue_type == "unauthorized_principal"

    @pytest.mark.asyncio
    async def test_blocked_principal_has_higher_priority(self, check, fetcher):
        """Test that blocked principals are checked before allowed principals."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": ["*"],
                "allowed_principals": ["*"],  # Even if allowed, blocked takes priority
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
    async def test_federated_principal(self, check, fetcher, config):
        """Test that federated principals are handled correctly."""
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRoleWithWebIdentity"],
            Resource=["*"],
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/example.com"},
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Federated principals should be allowed by default
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_multiple_principal_types(self, check, fetcher, config):
        """Test statement with multiple principal types."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={
                "AWS": "arn:aws:iam::123456789012:root",
                "Service": "lambda.amazonaws.com",
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Both principals should be allowed
        assert len(issues) == 0

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_empty_blocked_principals(self, check, fetcher):
        """Test with empty blocked principals list."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": []},
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # No principals blocked, so no issues
        assert len(issues) == 0


class TestPrincipalConditionRequirements:
    """Tests for advanced principal_condition_requirements feature."""

    @pytest.fixture
    def check(self):
        """Create PrincipalValidationCheck instance."""
        return PrincipalValidationCheck()

    @pytest.mark.asyncio
    async def test_simple_list_format(self, check, fetcher):
        """Test simple list format for principal condition requirements."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": [
                            {"condition_key": "aws:SourceArn"},
                            {"condition_key": "aws:SourceAccount"},
                        ],
                    }
                ],
            },
        )

        # Statement without required conditions
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should report 2 missing conditions
        assert len(issues) == 2
        assert all(issue.issue_type == "missing_principal_condition" for issue in issues)
        # Extract condition keys from messages like "Principal(s) ['*'] require condition 'aws:SourceArn'"
        condition_keys = set()
        for issue in issues:
            parts = issue.message.split("'")
            if len(parts) >= 4:
                condition_keys.add(parts[-2])  # Get the second-to-last quoted part
        assert "aws:SourceArn" in condition_keys
        assert "aws:SourceAccount" in condition_keys

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
                                {
                                    "condition_key": "aws:SourceArn",
                                    "description": "Limit by source ARN",
                                },
                                {
                                    "condition_key": "aws:SourceAccount",
                                    "description": "Limit by source account",
                                },
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

        # Should report missing aws:SourceAccount
        assert len(issues) == 1
        assert issues[0].issue_type == "missing_principal_condition"
        assert "aws:SourceAccount" in issues[0].message
        assert "ALL required:" in issues[0].message

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

        # Should report missing any_of conditions
        assert len(issues1) == 1
        assert issues1[0].issue_type == "missing_principal_condition_any_of"
        assert "at least ONE of these conditions" in issues1[0].message

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
                                    "description": "Insecure transport should never be allowed",
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

        # Should report forbidden condition
        assert len(issues) == 1
        assert issues[0].issue_type == "forbidden_principal_condition"
        assert "FORBIDDEN" in issues[0].message
        assert "aws:SecureTransport" in issues[0].message

    @pytest.mark.asyncio
    async def test_expected_value_validation(self, check, fetcher):
        """Test that expected values are validated correctly."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["arn:aws:iam::*:root"],
                        "required_conditions": [
                            {
                                "condition_key": "aws:PrincipalOrgID",
                                "operator": "StringEquals",
                                "expected_value": "o-123456",
                            }
                        ],
                    }
                ],
            },
        )

        # Statement with wrong value
        statement1 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Condition={"StringEquals": {"aws:PrincipalOrgID": "o-wrong"}},
        )

        issues1 = await check.execute(statement1, 0, fetcher, config)

        # Should report missing condition (wrong value = missing)
        assert len(issues1) == 1
        assert issues1[0].issue_type == "missing_principal_condition"

        # Statement with correct value (should pass)
        statement2 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Condition={"StringEquals": {"aws:PrincipalOrgID": "o-123456"}},
        )

        issues2 = await check.execute(statement2, 0, fetcher, config)
        assert len(issues2) == 0

    @pytest.mark.asyncio
    async def test_operator_validation(self, check, fetcher):
        """Test that operators are validated correctly."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": [
                            {
                                "condition_key": "aws:SourceIp",
                                "operator": "IpAddress",
                            }
                        ],
                    }
                ],
            },
        )

        # Statement with wrong operator
        statement1 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
            Condition={"StringEquals": {"aws:SourceIp": "10.0.0.0/8"}},
        )

        issues1 = await check.execute(statement1, 0, fetcher, config)

        # Should report missing condition (wrong operator = missing)
        assert len(issues1) == 1

        # Statement with correct operator (should pass)
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
    async def test_severity_override_per_requirement(self, check, fetcher):
        """Test that severity can be overridden per requirement."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "severity": "critical",
                        "required_conditions": [{"condition_key": "aws:SourceArn"}],
                    }
                ],
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
        assert issues[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_severity_override_per_condition(self, check, fetcher):
        """Test that severity can be overridden per condition."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            severity="medium",
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "severity": "high",
                        "required_conditions": [
                            {
                                "condition_key": "aws:SourceArn",
                                "severity": "critical",
                            }
                        ],
                    }
                ],
            },
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Condition-level severity should override
        assert len(issues) == 1
        assert issues[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_wildcard_principal_matching(self, check, fetcher):
        """Test that principal wildcard patterns work correctly."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["arn:aws:iam::123456789012:*"],
                        "required_conditions": [{"condition_key": "aws:SourceIp"}],
                    }
                ],
            },
        )

        # Principal matching pattern
        statement1 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:user/test"},
        )

        issues1 = await check.execute(statement1, 0, fetcher, config)
        assert len(issues1) == 1

        # Principal NOT matching pattern
        statement2 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::999999999999:user/test"},
        )

        issues2 = await check.execute(statement2, 0, fetcher, config)
        assert len(issues2) == 0

    @pytest.mark.asyncio
    async def test_multiple_requirements(self, check, fetcher):
        """Test multiple principal condition requirements."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": [{"condition_key": "aws:SourceArn"}],
                    },
                    {
                        "principals": ["arn:aws:iam::*:root"],
                        "required_conditions": [{"condition_key": "aws:PrincipalOrgID"}],
                    },
                ],
            },
        )

        # Principal matching BOTH requirements
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should report missing condition from first requirement
        assert len(issues) == 1
        assert "aws:SourceArn" in issues[0].message

    @pytest.mark.asyncio
    async def test_combined_all_of_and_any_of(self, check, fetcher):
        """Test combined all_of and any_of logic."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": {
                            "all_of": [{"condition_key": "aws:SourceArn"}],
                            "any_of": [
                                {"condition_key": "aws:SourceIp"},
                                {"condition_key": "aws:SourceVpce"},
                            ],
                        },
                    }
                ],
            },
        )

        # Statement with all_of but missing any_of
        statement1 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
            Condition={"StringEquals": {"aws:SourceArn": "arn:aws:s3:::my-bucket"}},
        )

        issues1 = await check.execute(statement1, 0, fetcher, config)

        # Should report missing any_of condition
        assert len(issues1) == 1
        assert issues1[0].issue_type == "missing_principal_condition_any_of"

        # Statement with both all_of and any_of
        statement2 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
            Condition={
                "StringEquals": {"aws:SourceArn": "arn:aws:s3:::my-bucket"},
                "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
            },
        )

        issues2 = await check.execute(statement2, 0, fetcher, config)
        assert len(issues2) == 0

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_description_in_suggestion(self, check, fetcher):
        """Test that description appears in suggestion."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": [
                            {
                                "condition_key": "aws:SourceArn",
                                "description": "This limits access by source ARN",
                            }
                        ],
                    }
                ],
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
        assert "This limits access by source ARN" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_custom_example_in_suggestion(self, check, fetcher):
        """Test that custom example appears in suggestion."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": [
                            {
                                "condition_key": "aws:SourceArn",
                                "example": '"Condition": {\n  "StringEquals": {\n    "aws:SourceArn": "arn:aws:s3:::my-bucket"\n  }\n}',
                            }
                        ],
                    }
                ],
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
        assert issues[0].example is not None
        assert "arn:aws:s3:::my-bucket" in issues[0].example

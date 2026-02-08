"""Tests for trust policy validation check."""

import pytest

from iam_validator.checks.trust_policy_validation import TrustPolicyValidationCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
def check():
    return TrustPolicyValidationCheck()


@pytest.fixture
def fetcher():
    return AWSServiceFetcher()


@pytest.fixture
def config():
    return CheckConfig(check_id="trust_policy_validation")


class TestTrustPolicyValidationCheck:
    """Test suite for TrustPolicyValidationCheck."""

    # ========================================================================
    # sts:AssumeRole Tests
    # ========================================================================

    @pytest.mark.asyncio
    async def test_assume_role_with_aws_principal_valid(self, check, fetcher, config):
        """Test that AssumeRole with AWS principal is valid."""
        statement = Statement(
            Effect="Allow",
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Action=["sts:AssumeRole"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_assume_role_with_service_principal_valid(self, check, fetcher, config):
        """Test that AssumeRole with Service principal is valid."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "lambda.amazonaws.com"},
            Action=["sts:AssumeRole"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_assume_role_with_federated_invalid(self, check, fetcher, config):
        """Test that AssumeRole with Federated principal is invalid."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"},
            Action=["sts:AssumeRole"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) > 0
        assert issues[0].issue_type == "invalid_principal_type_for_assume_action"
        assert "Federated" in issues[0].message
        assert "AWS" in issues[0].message or "Service" in issues[0].message

    # ========================================================================
    # sts:AssumeRoleWithSAML Tests
    # ========================================================================

    @pytest.mark.asyncio
    async def test_assume_role_with_saml_valid(self, check, fetcher, config):
        """Test that AssumeRoleWithSAML with Federated SAML principal is valid."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"},
            Action=["sts:AssumeRoleWithSAML"],
            Condition={"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_assume_role_with_saml_wrong_principal_type(self, check, fetcher, config):
        """Test that AssumeRoleWithSAML with AWS principal is invalid."""
        statement = Statement(
            Effect="Allow",
            Principal={"AWS": "arn:aws:iam::123456789012:user/alice"},
            Action=["sts:AssumeRoleWithSAML"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) > 0
        assert issues[0].issue_type == "invalid_principal_type_for_assume_action"
        assert "AWS" in issues[0].message
        assert "Federated" in issues[0].message

    @pytest.mark.asyncio
    async def test_assume_role_with_saml_invalid_provider_arn(self, check, fetcher, config):
        """Test that AssumeRoleWithSAML with OIDC provider is invalid."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/example.com"},
            Action=["sts:AssumeRoleWithSAML"],
            Condition={"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) > 0
        assert issues[0].issue_type == "invalid_provider_format"

    @pytest.mark.asyncio
    async def test_assume_role_with_saml_missing_condition(self, check, fetcher, config):
        """Test that AssumeRoleWithSAML without SAML:aud is invalid."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"},
            Action=["sts:AssumeRoleWithSAML"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) > 0
        assert any(
            issue.issue_type == "missing_required_condition_for_assume_action" for issue in issues
        )
        assert any("SAML:aud" in issue.message for issue in issues)

    # ========================================================================
    # sts:AssumeRoleWithWebIdentity Tests
    # ========================================================================

    @pytest.mark.asyncio
    async def test_assume_role_with_web_identity_valid(self, check, fetcher, config):
        """Test that AssumeRoleWithWebIdentity with Federated OIDC principal is valid."""
        statement = Statement(
            Effect="Allow",
            Principal={
                "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
            },
            Action=["sts:AssumeRoleWithWebIdentity"],
            Condition={
                "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_assume_role_with_web_identity_wrong_principal(self, check, fetcher, config):
        """Test that AssumeRoleWithWebIdentity with AWS principal is invalid."""
        statement = Statement(
            Effect="Allow",
            Principal={"AWS": "arn:aws:iam::123456789012:user/alice"},
            Action=["sts:AssumeRoleWithWebIdentity"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) > 0
        assert issues[0].issue_type == "invalid_principal_type_for_assume_action"

    @pytest.mark.asyncio
    async def test_assume_role_with_web_identity_saml_provider_invalid(
        self, check, fetcher, config
    ):
        """Test that AssumeRoleWithWebIdentity with SAML provider is invalid."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"},
            Action=["sts:AssumeRoleWithWebIdentity"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) > 0
        assert any(issue.issue_type == "invalid_provider_format" for issue in issues)

    # ========================================================================
    # Edge Cases & Configuration
    # ========================================================================

    @pytest.mark.asyncio
    async def test_multiple_assume_actions(self, check, fetcher, config):
        """Test statement with multiple assume actions."""
        statement = Statement(
            Effect="Allow",
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Action=["sts:AssumeRole", "sts:AssumeRoleWithSAML"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) > 0
        assert any("AssumeRoleWithSAML" in issue.message for issue in issues)

    @pytest.mark.asyncio
    async def test_no_principal_no_issues(self, check, fetcher, config):
        """Test that statements without principals are skipped."""
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_non_assume_action_skipped(self, check, fetcher, config):
        """Test that non-assume actions are skipped."""
        statement = Statement(
            Effect="Allow",
            Principal={"AWS": "*"},
            Action=["s3:GetObject"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_action_skipped(self, check, fetcher, config):
        """Test that wildcard actions are not validated."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123:saml-provider/Test"},
            Action=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_custom_validation_rules(self, check, fetcher):
        """Test custom validation rules override defaults."""
        custom_config = CheckConfig(
            check_id="trust_policy_validation",
            config={
                "validation_rules": {
                    "sts:AssumeRole": {
                        "allowed_principal_types": ["AWS"],
                        "required_conditions": ["sts:ExternalId"],
                    }
                }
            },
        )
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "lambda.amazonaws.com"},
            Action=["sts:AssumeRole"],
        )
        issues = await check.execute(statement, 0, fetcher, custom_config)
        assert len(issues) > 0
        assert any("Service" in issue.message for issue in issues)

    @pytest.mark.asyncio
    async def test_issue_metadata_populated(self, check, fetcher, config):
        """Test that issues have proper metadata."""
        statement = Statement(
            Sid="AssumeRolePolicy",
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123:saml-provider/Test"},
            Action=["sts:AssumeRole"],
            line_number=42,
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) > 0
        issue = issues[0]
        assert issue.statement_index == 0
        assert issue.statement_sid == "AssumeRolePolicy"
        assert issue.line_number == 42
        assert issue.action == "sts:AssumeRole"
        assert issue.suggestion is not None
        assert issue.example is not None

    # ========================================================================
    # Provider ARN Format Validation
    # ========================================================================

    @pytest.mark.asyncio
    async def test_invalid_saml_provider_format(self, check, fetcher, config):
        """Test that invalid SAML provider ARN is flagged."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::invalid:saml-provider/Test"},
            Action=["sts:AssumeRoleWithSAML"],
            Condition={"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) > 0
        assert any(issue.issue_type == "invalid_provider_format" for issue in issues)

    # ========================================================================
    # Multiple Principals Tests
    # ========================================================================

    @pytest.mark.asyncio
    async def test_multiple_federated_principals(self, check, fetcher, config):
        """Test statement with multiple federated principals."""
        statement = Statement(
            Effect="Allow",
            Principal={
                "Federated": [
                    "arn:aws:iam::123456789012:saml-provider/Provider1",
                    "arn:aws:iam::123456789012:saml-provider/Provider2",
                ]
            },
            Action=["sts:AssumeRoleWithSAML"],
            Condition={"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(issue.issue_type == "invalid_provider_format" for issue in issues)

    @pytest.mark.asyncio
    async def test_mixed_valid_and_invalid_providers(self, check, fetcher, config):
        """Test that mix of valid and invalid providers flags only invalid ones."""
        statement = Statement(
            Effect="Allow",
            Principal={
                "Federated": [
                    "arn:aws:iam::123456789012:saml-provider/ValidProvider",
                    "arn:aws:iam::123456789012:oidc-provider/invalid.com",
                ]
            },
            Action=["sts:AssumeRoleWithSAML"],
            Condition={"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) > 0
        assert any(issue.issue_type == "invalid_provider_format" for issue in issues)

    # ========================================================================
    # Real-World Examples
    # ========================================================================

    @pytest.mark.asyncio
    async def test_github_actions_oidc_trust_policy(self, check, fetcher, config):
        """Test realistic GitHub Actions OIDC trust policy."""
        statement = Statement(
            Effect="Allow",
            Principal={
                "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
            },
            Action=["sts:AssumeRoleWithWebIdentity"],
            Condition={
                "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                "StringLike": {"token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:*"},
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_cross_account_trust_with_external_id(self, check, fetcher, config):
        """Test cross-account trust policy with ExternalId."""
        statement = Statement(
            Effect="Allow",
            Principal={"AWS": "arn:aws:iam::999999999999:root"},
            Action=["sts:AssumeRole"],
            Condition={"StringEquals": {"sts:ExternalId": "my-unique-external-id-123"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0


class TestConfusedDeputyDetection:
    """Tests for confused deputy vulnerability detection."""

    @pytest.mark.asyncio
    async def test_service_principal_without_conditions_flagged(self, check, fetcher, config):
        """Service principal without SourceArn/SourceAccount should be flagged with suggestion."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "sns.amazonaws.com"},
            Action=["sts:AssumeRole"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        confused_deputy_issues = [i for i in issues if i.issue_type == "confused_deputy_risk"]
        assert len(confused_deputy_issues) == 1
        assert confused_deputy_issues[0].severity == "high"
        assert "sns.amazonaws.com" in confused_deputy_issues[0].message
        assert confused_deputy_issues[0].suggestion is not None
        assert "aws:SourceArn" in confused_deputy_issues[0].suggestion
        assert confused_deputy_issues[0].example is not None

    @pytest.mark.asyncio
    async def test_service_principal_with_source_arn_ok(self, check, fetcher, config):
        """Service principal with aws:SourceArn condition should pass."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "sns.amazonaws.com"},
            Action=["sts:AssumeRole"],
            Condition={"ArnLike": {"aws:SourceArn": "arn:aws:sns:us-east-1:123456789012:my-topic"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "confused_deputy_risk" for i in issues)

    @pytest.mark.asyncio
    async def test_service_principal_with_source_account_ok(self, check, fetcher, config):
        """Service principal with aws:SourceAccount condition should pass."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "sns.amazonaws.com"},
            Action=["sts:AssumeRole"],
            Condition={"StringEquals": {"aws:SourceAccount": "123456789012"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "confused_deputy_risk" for i in issues)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "service",
        [
            "lambda.amazonaws.com",
            "ec2.amazonaws.com",
        ],
    )
    async def test_safe_services_not_flagged(self, service, check, fetcher, config):
        """Services in CONFUSED_DEPUTY_SAFE_SERVICES should not be flagged."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": service},
            Action=["sts:AssumeRole"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "confused_deputy_risk" for i in issues)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "service",
        [
            "ecs-tasks.amazonaws.com",
            "eks.amazonaws.com",
            "codebuild.amazonaws.com",
            "guardduty.amazonaws.com",
            "monitoring.amazonaws.com",
            "ecs.amazonaws.com",
        ],
    )
    async def test_unsafe_services_flagged(self, service, check, fetcher, config):
        """Non-compute-bound services should be flagged for confused deputy."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": service},
            Action=["sts:AssumeRole"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        confused_deputy_issues = [i for i in issues if i.issue_type == "confused_deputy_risk"]
        assert len(confused_deputy_issues) == 1

    @pytest.mark.asyncio
    async def test_deny_statement_not_checked(self, check, fetcher, config):
        """Deny statements should not trigger confused deputy check."""
        statement = Statement(
            Effect="Deny",
            Principal={"Service": "sns.amazonaws.com"},
            Action=["sts:AssumeRole"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "confused_deputy_risk" for i in issues)

    @pytest.mark.asyncio
    async def test_aws_principal_not_checked_for_confused_deputy(self, check, fetcher, config):
        """AWS principals (not Service) should not trigger confused deputy check."""
        statement = Statement(
            Effect="Allow",
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Action=["sts:AssumeRole"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "confused_deputy_risk" for i in issues)

    @pytest.mark.asyncio
    async def test_multiple_service_principals_some_safe(self, check, fetcher, config):
        """Multiple service principals: safe ones pass, unsafe ones flagged."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": ["lambda.amazonaws.com", "sns.amazonaws.com"]},
            Action=["sts:AssumeRole"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        confused_deputy_issues = [i for i in issues if i.issue_type == "confused_deputy_risk"]
        assert len(confused_deputy_issues) == 1
        assert "sns.amazonaws.com" in confused_deputy_issues[0].message

    @pytest.mark.asyncio
    async def test_case_insensitive_condition_key_match(self, check, fetcher, config):
        """Condition key matching should be case-insensitive."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "sns.amazonaws.com"},
            Action=["sts:AssumeRole"],
            Condition={"ArnLike": {"AWS:SourceArn": "arn:aws:sns:us-east-1:123456789012:my-topic"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert not any(i.issue_type == "confused_deputy_risk" for i in issues)

"""Tests for trust policy validation check."""

import pytest

from iam_validator.checks.trust_policy_validation import TrustPolicyValidationCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestTrustPolicyValidationCheck:
    """Test suite for TrustPolicyValidationCheck."""

    @pytest.fixture
    def check(self):
        """Create a TrustPolicyValidationCheck instance."""
        return TrustPolicyValidationCheck()

    @pytest.fixture
    def fetcher(self):
        """Create a mock AWSServiceFetcher instance."""
        return AWSServiceFetcher()

    @pytest.fixture
    def config(self):
        """Create a default CheckConfig."""
        return CheckConfig(check_id="trust_policy_validation")

    def test_check_id(self, check):
        """Test check_id property."""
        assert check.check_id == "trust_policy_validation"

    def test_description(self, check):
        """Test description property."""
        assert "trust" in check.description.lower()
        assert "assumption" in check.description.lower() or "assume" in check.description.lower()

    def test_default_severity(self, check):
        """Test default_severity property."""
        assert check.default_severity == "high"

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
            Condition={
                "StringEquals": {
                    "SAML:aud": "https://signin.aws.amazon.com/saml"
                }
            },
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
            Condition={
                "StringEquals": {
                    "SAML:aud": "https://signin.aws.amazon.com/saml"
                }
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) > 0
        assert issues[0].issue_type == "invalid_provider_format"
        assert "saml-provider" in issues[0].message.lower() or "SAML" in issues[0].message

    @pytest.mark.asyncio
    async def test_assume_role_with_saml_missing_condition(self, check, fetcher, config):
        """Test that AssumeRoleWithSAML without SAML:aud is invalid."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"},
            Action=["sts:AssumeRoleWithSAML"],
            # Missing Condition
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) > 0
        assert any(
            issue.issue_type == "missing_required_condition_for_assume_action"
            for issue in issues
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
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
            Action=["sts:AssumeRoleWithWebIdentity"],
            Condition={
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                }
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
    async def test_assume_role_with_web_identity_saml_provider_invalid(self, check, fetcher, config):
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
    # Multiple Actions Tests
    # ========================================================================

    @pytest.mark.asyncio
    async def test_multiple_assume_actions(self, check, fetcher, config):
        """Test statement with multiple assume actions."""
        statement = Statement(
            Effect="Allow",
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Action=["sts:AssumeRole", "sts:AssumeRoleWithSAML"],  # Mix of compatible and incompatible
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag AssumeRoleWithSAML as incompatible with AWS principal
        assert len(issues) > 0
        assert any("AssumeRoleWithSAML" in issue.message for issue in issues)

    # ========================================================================
    # Edge Cases
    # ========================================================================

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

    # ========================================================================
    # Custom Configuration Tests
    # ========================================================================

    @pytest.mark.asyncio
    async def test_custom_validation_rules(self, check, fetcher):
        """Test custom validation rules override defaults."""
        custom_config = CheckConfig(
            check_id="trust_policy_validation",
            config={
                "validation_rules": {
                    "sts:AssumeRole": {
                        "allowed_principal_types": ["AWS"],  # Only AWS, not Service
                        "required_conditions": ["sts:ExternalId"],
                    }
                }
            },
        )

        # Service principal should be invalid with custom rules
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "lambda.amazonaws.com"},
            Action=["sts:AssumeRole"],
        )

        issues = await check.execute(statement, 0, fetcher, custom_config)

        assert len(issues) > 0
        assert any("Service" in issue.message for issue in issues)

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity from config."""
        custom_config = CheckConfig(
            check_id="trust_policy_validation",
            severity="critical",
        )

        statement = Statement(
            Effect="Allow",
            Principal={"AWS": "arn:aws:iam::123:user/alice"},
            Action=["sts:AssumeRoleWithSAML"],  # Wrong principal type
        )

        issues = await check.execute(statement, 0, fetcher, custom_config)

        assert len(issues) > 0
        # Note: severity override happens at registry level, not in check

    # ========================================================================
    # Metadata Tests
    # ========================================================================

    @pytest.mark.asyncio
    async def test_issue_metadata_populated(self, check, fetcher, config):
        """Test that issues have proper metadata."""
        statement = Statement(
            Sid="AssumeRolePolicy",
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123:saml-provider/Test"},
            Action=["sts:AssumeRole"],  # Wrong action for Federated
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
    async def test_saml_provider_valid_format(self, check, fetcher, config):
        """Test that valid SAML provider ARN passes."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"},
            Action=["sts:AssumeRoleWithSAML"],
            Condition={"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not have provider format issues
        assert not any(issue.issue_type == "invalid_provider_format" for issue in issues)

    @pytest.mark.asyncio
    async def test_oidc_provider_valid_format(self, check, fetcher, config):
        """Test that valid OIDC provider ARN passes."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
            Action=["sts:AssumeRoleWithWebIdentity"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not have provider format issues
        assert not any(issue.issue_type == "invalid_provider_format" for issue in issues)

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
    # Condition Validation Tests
    # ========================================================================

    @pytest.mark.asyncio
    async def test_saml_with_required_condition(self, check, fetcher, config):
        """Test that SAML with SAML:aud condition passes."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"},
            Action=["sts:AssumeRoleWithSAML"],
            Condition={
                "StringEquals": {
                    "SAML:aud": "https://signin.aws.amazon.com/saml"
                }
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not have missing condition issues
        assert not any(
            issue.issue_type == "missing_required_condition_for_assume_action"
            for issue in issues
        )

    @pytest.mark.asyncio
    async def test_saml_without_required_condition(self, check, fetcher, config):
        """Test that SAML without SAML:aud condition is flagged."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"},
            Action=["sts:AssumeRoleWithSAML"],
            # Missing Condition
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) > 0
        assert any(
            issue.issue_type == "missing_required_condition_for_assume_action"
            for issue in issues
        )
        assert any("SAML:aud" in issue.message for issue in issues)

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

        # Both providers should pass validation
        assert not any(issue.issue_type == "invalid_provider_format" for issue in issues)

    @pytest.mark.asyncio
    async def test_mixed_valid_and_invalid_providers(self, check, fetcher, config):
        """Test that mix of valid and invalid providers flags only invalid ones."""
        statement = Statement(
            Effect="Allow",
            Principal={
                "Federated": [
                    "arn:aws:iam::123456789012:saml-provider/ValidProvider",
                    "arn:aws:iam::123456789012:oidc-provider/invalid.com",  # Wrong type
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
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
            Action=["sts:AssumeRoleWithWebIdentity"],
            Condition={
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                },
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:*"
                },
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_lambda_service_role_trust_policy(self, check, fetcher, config):
        """Test realistic Lambda service role trust policy."""
        statement = Statement(
            Effect="Allow",
            Principal={"Service": "lambda.amazonaws.com"},
            Action=["sts:AssumeRole"],
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
            Condition={
                "StringEquals": {
                    "sts:ExternalId": "my-unique-external-id-123"
                }
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

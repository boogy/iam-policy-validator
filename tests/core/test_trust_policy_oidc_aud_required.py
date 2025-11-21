"""Tests for OIDC audience (aud) requirement in trust policies."""

import pytest

from iam_validator.checks.trust_policy_validation import TrustPolicyValidationCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestOIDCAudienceRequired:
    """Test that OIDC trust policies require audience condition."""

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

    @pytest.mark.asyncio
    async def test_oidc_with_aud_passes(self, check, fetcher, config):
        """Test that OIDC with aud condition passes."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/accounts.google.com"},
            Action=["sts:AssumeRoleWithWebIdentity"],
            Condition={
                "StringEquals": {
                    "accounts.google.com:aud": "my-app-client-id"
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
    async def test_oidc_without_aud_fails(self, check, fetcher, config):
        """Test that OIDC without aud condition fails."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/accounts.google.com"},
            Action=["sts:AssumeRoleWithWebIdentity"],
            # Missing aud condition!
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) > 0
        assert any(
            issue.issue_type == "missing_required_condition_for_assume_action"
            for issue in issues
        )
        assert any(":aud" in issue.message for issue in issues)

    @pytest.mark.asyncio
    async def test_github_actions_aud_passes(self, check, fetcher, config):
        """Test GitHub Actions OIDC with aud passes."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
            Action=["sts:AssumeRoleWithWebIdentity"],
            Condition={
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": "repo:org/repo:*"
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
    async def test_cognito_aud_passes(self, check, fetcher, config):
        """Test Amazon Cognito OIDC with aud passes."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/cognito-identity.amazonaws.com"},
            Action=["sts:AssumeRoleWithWebIdentity"],
            Condition={
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": "us-east-1:12345678-1234-1234-1234-123456789012"
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
    async def test_oidc_with_sub_but_no_aud_fails(self, check, fetcher, config):
        """Test that having sub condition but no aud still fails."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
            Action=["sts:AssumeRoleWithWebIdentity"],
            Condition={
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": "repo:org/repo:*"
                    # Missing :aud!
                }
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) > 0
        assert any(
            issue.issue_type == "missing_required_condition_for_assume_action"
            for issue in issues
        )
        assert any(":aud" in issue.message for issue in issues)

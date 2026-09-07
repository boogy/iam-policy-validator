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
    async def test_oidc_with_aud_only_is_flagged_for_missing_sub(self, check, fetcher, config):
        """`aud` alone is assumable by any workload of the provider; `sub` is required too."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/accounts.google.com"},
            Action=["sts:AssumeRoleWithWebIdentity"],
            Condition={"StringEquals": {"accounts.google.com:aud": "my-app-client-id"}},
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert any(issue.issue_type == "missing_required_condition_for_assume_action" for issue in issues)
        assert any("sub" in issue.message for issue in issues)

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
        assert any(issue.issue_type == "missing_required_condition_for_assume_action" for issue in issues)
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
                    "token.actions.githubusercontent.com:sub": "repo:org/repo:*",
                }
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not have missing condition issues
        assert not any(issue.issue_type == "missing_required_condition_for_assume_action" for issue in issues)

    @pytest.mark.asyncio
    async def test_cognito_aud_only_is_flagged_for_missing_sub(self, check, fetcher, config):
        """`aud` alone is assumable by any workload of the provider; `sub` is required too."""
        statement = Statement(
            Effect="Allow",
            Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/cognito-identity.amazonaws.com"},
            Action=["sts:AssumeRoleWithWebIdentity"],
            Condition={
                "StringEquals": {"cognito-identity.amazonaws.com:aud": "us-east-1:12345678-1234-1234-1234-123456789012"}
            },
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert any(issue.issue_type == "missing_required_condition_for_assume_action" for issue in issues)
        assert any("sub" in issue.message for issue in issues)

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
        assert any(issue.issue_type == "missing_required_condition_for_assume_action" for issue in issues)
        assert any(":aud" in issue.message for issue in issues)


async def test_oidc_without_sub_is_flagged(mock_fetcher, default_config):
    statement = Statement(
        effect="Allow",
        action=["sts:AssumeRoleWithWebIdentity"],
        principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
        condition={"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}},
    )
    check = TrustPolicyValidationCheck()
    issues = await check.execute(statement, 0, mock_fetcher, default_config)
    assert any("sub" in (i.condition_key or "") or ":sub" in i.message for i in issues)


async def test_oidc_with_aud_and_sub_is_clean(mock_fetcher, default_config):
    statement = Statement(
        effect="Allow",
        action=["sts:AssumeRoleWithWebIdentity"],
        principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
        condition={
            "StringEquals": {
                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                "token.actions.githubusercontent.com:sub": "repo:acme/app:ref:refs/heads/main",
            }
        },
    )
    check = TrustPolicyValidationCheck()
    issues = await check.execute(statement, 0, mock_fetcher, default_config)
    assert not [i for i in issues if ":sub" in i.message or ":aud" in i.message]


async def test_required_condition_key_matching_is_case_insensitive(mock_fetcher, default_config):
    statement = Statement(
        effect="Allow",
        action=["sts:AssumeRoleWithWebIdentity"],
        principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
        condition={
            "StringEquals": {
                "token.actions.githubusercontent.com:AUD": "sts.amazonaws.com",
                "token.actions.githubusercontent.com:Sub": "repo:acme/app:ref:refs/heads/main",
            }
        },
    )
    issues = await TrustPolicyValidationCheck().execute(statement, 0, mock_fetcher, default_config)
    assert not [i for i in issues if i.issue_type == "missing_required_condition_for_assume_action"]


async def test_null_true_does_not_satisfy_a_required_condition(mock_fetcher, default_config):
    statement = Statement(
        effect="Allow",
        action=["sts:AssumeRoleWithWebIdentity"],
        principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
        condition={
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "Null": {"token.actions.githubusercontent.com:sub": "true"},
        },
    )
    issues = await TrustPolicyValidationCheck().execute(statement, 0, mock_fetcher, default_config)
    assert any(i.issue_type == "missing_required_condition_for_assume_action" and ":sub" in i.message for i in issues)


async def test_null_false_does_satisfy_a_required_condition(mock_fetcher, default_config):
    statement = Statement(
        effect="Allow",
        action=["sts:AssumeRoleWithWebIdentity"],
        principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
        condition={
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "Null": {"token.actions.githubusercontent.com:sub": "false"},
        },
    )
    issues = await TrustPolicyValidationCheck().execute(statement, 0, mock_fetcher, default_config)
    assert not [i for i in issues if i.issue_type == "missing_required_condition_for_assume_action"]


async def test_negated_operator_does_not_satisfy_a_required_condition_on_allow(mock_fetcher, default_config):
    statement = Statement(
        effect="Allow",
        action=["sts:AssumeRoleWithWebIdentity"],
        principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
        condition={
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "StringNotEquals": {"token.actions.githubusercontent.com:sub": "repo:evil/app:ref:refs/heads/main"},
        },
    )
    issues = await TrustPolicyValidationCheck().execute(statement, 0, mock_fetcher, default_config)
    assert any(i.issue_type == "missing_required_condition_for_assume_action" and ":sub" in i.message for i in issues)


async def test_forallvalues_null_true_does_not_satisfy_a_required_condition(mock_fetcher, default_config):
    statement = Statement(
        effect="Allow",
        action=["sts:AssumeRoleWithWebIdentity"],
        principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
        condition={
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "ForAllValues:Null": {"token.actions.githubusercontent.com:sub": "true"},
        },
    )
    issues = await TrustPolicyValidationCheck().execute(statement, 0, mock_fetcher, default_config)
    assert any(i.issue_type == "missing_required_condition_for_assume_action" and ":sub" in i.message for i in issues)


async def test_negated_operator_on_deny_does_satisfy_a_required_condition(mock_fetcher, default_config):
    statement = Statement(
        effect="Deny",
        action=["sts:AssumeRoleWithWebIdentity"],
        principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
        condition={
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "StringNotEquals": {"token.actions.githubusercontent.com:sub": "repo:acme/app:ref:refs/heads/main"},
        },
    )
    issues = await TrustPolicyValidationCheck().execute(statement, 0, mock_fetcher, default_config)
    assert not [i for i in issues if i.issue_type == "missing_required_condition_for_assume_action"]

"""Tests for trust policy detection with multiple statements."""

import pytest

from iam_validator.checks.policy_structure import is_trust_policy
from iam_validator.core.models import IAMPolicy, Statement


class TestTrustPolicyMultipleStatements:
    """Test trust policy detection with multiple statements."""

    def test_multiple_assume_statements_all_valid(self):
        """Test trust policy with multiple assume role statements."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="AllowLambda",
                    Effect="Allow",
                    Principal={"Service": "lambda.amazonaws.com"},
                    Action="sts:AssumeRole",
                ),
                Statement(
                    Sid="AllowEC2",
                    Effect="Allow",
                    Principal={"Service": "ec2.amazonaws.com"},
                    Action="sts:AssumeRole",
                ),
                Statement(
                    Sid="AllowTagging",
                    Effect="Allow",
                    Principal={"AWS": "arn:aws:iam::123:root"},
                    Action="sts:TagSession",
                ),
            ],
        )

        # All statements are assume-related with no specific resources
        assert is_trust_policy(policy) is True

    def test_assume_statements_with_wildcard_resources(self):
        """Test that wildcard resources don't prevent detection."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"Service": "lambda.amazonaws.com"},
                    Action="sts:AssumeRole",
                    Resource="*",  # Wildcard is OK
                ),
                Statement(
                    Effect="Allow",
                    Principal={"Service": "ec2.amazonaws.com"},
                    Action="sts:AssumeRole",
                    # No Resource field - also OK
                ),
            ],
        )

        assert is_trust_policy(policy) is True

    def test_one_statement_with_specific_resource_fails(self):
        """Test that ANY statement with specific resource prevents detection."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"Service": "lambda.amazonaws.com"},
                    Action="sts:AssumeRole",
                    # No resource - valid trust statement
                ),
                Statement(
                    Effect="Allow",
                    Principal="*",
                    Action="s3:GetObject",
                    Resource="arn:aws:s3:::my-bucket/*",  # Specific resource - invalidates whole policy
                ),
            ],
        )

        # Should NOT be trust policy - has specific resource in one statement
        assert is_trust_policy(policy) is False

    def test_assume_statement_with_specific_resource_fails(self):
        """Test that assume statement with specific resource fails detection."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"AWS": "arn:aws:iam::123:root"},
                    Action="sts:AssumeRole",
                    Resource="arn:aws:iam::123:role/MyRole",  # Specific role ARN - weird but possible
                ),
            ],
        )

        # Should NOT be trust policy - assume statement has specific resource
        assert is_trust_policy(policy) is False

    def test_mixed_assume_and_tag_session(self):
        """Test combination of AssumeRole and TagSession."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"Federated": "arn:aws:iam::123:oidc-provider/accounts.google.com"},
                    Action=["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
                ),
            ],
        )

        assert is_trust_policy(policy) is True

    def test_all_three_assume_types_combined(self):
        """Test policy with all three assume action types."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="AllowStandardAssume",
                    Effect="Allow",
                    Principal={"AWS": "arn:aws:iam::123:root"},
                    Action="sts:AssumeRole",
                ),
                Statement(
                    Sid="AllowSAML",
                    Effect="Allow",
                    Principal={"Federated": "arn:aws:iam::123:saml-provider/Corp"},
                    Action="sts:AssumeRoleWithSAML",
                ),
                Statement(
                    Sid="AllowOIDC",
                    Effect="Allow",
                    Principal={"Federated": "arn:aws:iam::123:oidc-provider/accounts.google.com"},
                    Action="sts:AssumeRoleWithWebIdentity",
                ),
            ],
        )

        assert is_trust_policy(policy) is True

    def test_resource_ending_with_colon_star_allowed(self):
        """Test that Resource ending with :* is allowed (AWS wildcard pattern)."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"Service": "lambda.amazonaws.com"},
                    Action="sts:AssumeRole",
                    Resource="arn:aws:iam::*:*",  # Ends with :* (wildcard pattern)
                ),
            ],
        )

        assert is_trust_policy(policy) is True

    def test_deny_statement_prevents_detection(self):
        """Test that Deny Effect prevents trust policy detection."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Deny",  # Trust policies don't use Deny
                    Principal={"AWS": "*"},
                    Action="sts:AssumeRole",
                ),
            ],
        )

        assert is_trust_policy(policy) is False

    def test_real_world_lambda_execution_role(self):
        """Test real-world Lambda execution role trust policy."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"Service": "lambda.amazonaws.com"},
                    Action="sts:AssumeRole",
                )
            ],
        )

        assert is_trust_policy(policy) is True

    def test_real_world_github_actions_role(self):
        """Test real-world GitHub Actions OIDC role trust policy."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={
                        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                    },
                    Action="sts:AssumeRoleWithWebIdentity",
                    Condition={
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                        },
                        "StringLike": {
                            "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:*"
                        },
                    },
                )
            ],
        )

        assert is_trust_policy(policy) is True

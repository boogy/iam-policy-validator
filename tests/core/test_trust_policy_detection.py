"""Tests for trust policy detection logic."""

import pytest

from iam_validator.checks.policy_structure import detect_policy_type, is_trust_policy
from iam_validator.core.models import IAMPolicy, Statement


class TestTrustPolicyDetection:
    """Test suite for is_trust_policy() detection function."""

    def test_lambda_service_role_trust_policy(self):
        """Test detection of Lambda service role trust policy."""
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

        # is_trust_policy() still detects it (used for hints/validation logic)
        assert is_trust_policy(policy) is True
        # detect_policy_type() returns RESOURCE_POLICY (no auto-detection to TRUST_POLICY)
        # User must explicitly use --policy-type TRUST_POLICY
        assert detect_policy_type(policy) == "RESOURCE_POLICY"

    def test_github_actions_oidc_trust_policy(self):
        """Test detection of GitHub Actions OIDC trust policy."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={
                        "Federated": "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com"
                    },
                    Action="sts:AssumeRoleWithWebIdentity",
                )
            ],
        )

        assert is_trust_policy(policy) is True
        assert detect_policy_type(policy) == "RESOURCE_POLICY"  # No auto-detect to TRUST_POLICY

    def test_saml_trust_policy(self):
        """Test detection of SAML trust policy."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"Federated": "arn:aws:iam::123:saml-provider/MyProvider"},
                    Action="sts:AssumeRoleWithSAML",
                    Condition={"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
                )
            ],
        )

        assert is_trust_policy(policy) is True
        assert detect_policy_type(policy) == "RESOURCE_POLICY"  # No auto-detect to TRUST_POLICY

    def test_cross_account_trust_policy(self):
        """Test detection of cross-account trust policy."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"AWS": "arn:aws:iam::999999999999:root"},
                    Action="sts:AssumeRole",
                    Condition={"StringEquals": {"sts:ExternalId": "secret"}},
                )
            ],
        )

        assert is_trust_policy(policy) is True
        assert detect_policy_type(policy) == "RESOURCE_POLICY"  # No auto-detect to TRUST_POLICY

    def test_trust_policy_with_tag_session(self):
        """Test detection with sts:TagSession action."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"AWS": "arn:aws:iam::123:role/MyRole"},
                    Action=["sts:AssumeRole", "sts:TagSession"],
                )
            ],
        )

        assert is_trust_policy(policy) is True
        assert detect_policy_type(policy) == "RESOURCE_POLICY"  # No auto-detect to TRUST_POLICY

    # ========================================================================
    # Negative Tests - NOT Trust Policies
    # ========================================================================

    def test_s3_bucket_policy_not_trust_policy(self):
        """Test that S3 bucket policy is NOT detected as trust policy."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal="*",
                    Action="s3:GetObject",
                    Resource="arn:aws:s3:::my-bucket/*",  # Specific resource ARN
                )
            ],
        )

        assert is_trust_policy(policy) is False
        assert detect_policy_type(policy) == "RESOURCE_POLICY"

    def test_policy_with_deny_effect_not_trust_policy(self):
        """Test that policies with Deny effect are NOT trust policies."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Deny",  # Trust policies use Allow
                    Principal={"AWS": "*"},
                    Action="sts:AssumeRole",
                )
            ],
        )

        assert is_trust_policy(policy) is False

    def test_policy_with_specific_resource_not_trust_policy(self):
        """Test that policies with specific resources are NOT trust policies."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"AWS": "arn:aws:iam::123:root"},
                    Action="sts:AssumeRole",
                    Resource="arn:aws:iam::123:role/MyRole",  # Specific resource
                )
            ],
        )

        assert is_trust_policy(policy) is False

    def test_identity_policy_not_trust_policy(self):
        """Test that identity policy is NOT detected as trust policy."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Action="s3:GetObject",
                    Resource="arn:aws:s3:::my-bucket/*",
                )
            ],
        )

        assert is_trust_policy(policy) is False
        assert detect_policy_type(policy) == "IDENTITY_POLICY"

    def test_trust_policy_with_wildcard_resource_passes(self):
        """Test that trust policy with Resource: * is still detected."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"Service": "lambda.amazonaws.com"},
                    Action="sts:AssumeRole",
                    Resource="*",  # Wildcard is OK for trust policies
                )
            ],
        )

        assert is_trust_policy(policy) is True
        assert detect_policy_type(policy) == "RESOURCE_POLICY"  # No auto-detect to TRUST_POLICY

    def test_trust_policy_with_service_wildcard_resource(self):
        """Test that trust policy with Resource: service:* is still detected."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"AWS": "arn:aws:iam::123:root"},
                    Action="sts:AssumeRole",
                    Resource="arn:aws:iam::*:*",  # Ends with :* (OK)
                )
            ],
        )

        assert is_trust_policy(policy) is True

    def test_multiple_statements_mixed(self):
        """Test policy with both trust and non-trust statements."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"Service": "lambda.amazonaws.com"},
                    Action="sts:AssumeRole",
                ),
                Statement(
                    Effect="Allow",
                    Principal="*",
                    Action="s3:GetObject",
                    Resource="arn:aws:s3:::bucket/*",  # Specific resource in different statement
                ),
            ],
        )

        # Should NOT be detected as trust policy
        # Even though first statement is a trust statement, the second has specific resources
        # Trust policies should ONLY contain assume statements without specific resource ARNs
        # This prevents false positives from mixed-purpose policies
        assert is_trust_policy(policy) is False

    def test_wildcard_sts_action(self):
        """Test detection with sts:* wildcard."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"AWS": "arn:aws:iam::123:root"},
                    Action="sts:*",
                )
            ],
        )

        assert is_trust_policy(policy) is True
        assert detect_policy_type(policy) == "RESOURCE_POLICY"  # No auto-detect to TRUST_POLICY

    def test_no_principal_not_trust_policy(self):
        """Test that policy without Principal is NOT trust policy."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Action="sts:AssumeRole",
                    Resource="*",
                )
            ],
        )

        assert is_trust_policy(policy) is False
        assert detect_policy_type(policy) == "IDENTITY_POLICY"

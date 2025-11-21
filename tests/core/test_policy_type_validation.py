"""Tests for policy type validation (including RCP validation)."""

import pytest

from iam_validator.checks.policy_type_validation import execute_policy
from iam_validator.core.models import IAMPolicy, Statement


class TestPolicyTypeValidation:
    """Test suite for policy type validation."""

    @pytest.mark.asyncio
    async def test_identity_policy_no_principal(self):
        """Identity policies should not have Principal."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    action=["s3:GetObject"],
                    resource=["arn:aws:s3:::bucket/*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="IDENTITY_POLICY")
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_identity_policy_with_principal_hint(self):
        """Identity policies with Principal should generate helpful hint."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    principal="*",
                    action=["s3:GetObject"],
                    resource=["arn:aws:s3:::bucket/*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="IDENTITY_POLICY")
        assert len(issues) == 1
        assert issues[0].issue_type == "policy_type_hint"
        assert issues[0].severity == "info"
        assert "RESOURCE_POLICY" in issues[0].message

    @pytest.mark.asyncio
    async def test_resource_policy_requires_principal(self):
        """Resource policies must have Principal."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    action=["s3:GetObject"],
                    resource=["arn:aws:s3:::bucket/*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_POLICY")
        assert len(issues) == 1
        assert issues[0].issue_type == "missing_principal"
        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_resource_policy_with_principal_valid(self):
        """Resource policies with Principal should be valid."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    principal="arn:aws:iam::123456789012:root",
                    action=["s3:GetObject"],
                    resource=["arn:aws:s3:::bucket/*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_POLICY")
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_scp_no_principal(self):
        """SCPs must not have Principal."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    action=["ec2:*"],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="SERVICE_CONTROL_POLICY")
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_scp_with_principal_error(self):
        """SCPs with Principal should generate error."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    principal="*",
                    action=["ec2:*"],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="SERVICE_CONTROL_POLICY")
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_principal"
        assert issues[0].severity == "error"


class TestRCPValidation:
    """Test suite for Resource Control Policy validation."""

    @pytest.mark.asyncio
    async def test_rcp_valid_policy(self):
        """Valid RCP with all required elements."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    sid="EnforceEncryption",
                    effect="Deny",
                    principal="*",
                    action=["s3:*", "sqs:*"],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_rcp_invalid_effect_allow(self):
        """RCPs must use Deny effect."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    principal="*",
                    action=["s3:GetObject"],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_rcp_effect"
        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_rcp_missing_principal(self):
        """RCPs must have Principal."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    action=["s3:*"],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert len(issues) == 1
        assert issues[0].issue_type == "missing_rcp_principal"
        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_rcp_invalid_principal_specific_arn(self):
        """RCPs Principal must be exactly '*'."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    principal="arn:aws:iam::123456789012:root",
                    action=["s3:*"],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_rcp_principal"
        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_rcp_not_principal_not_supported(self):
        """RCPs don't support NotPrincipal."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    not_principal="arn:aws:iam::123456789012:root",
                    action=["s3:*"],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_rcp_not_principal"
        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_rcp_wildcard_action_not_allowed(self):
        """RCPs cannot use '*' alone in Action."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    principal="*",
                    action=["*"],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_rcp_wildcard_action"
        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_rcp_unsupported_service_ec2(self):
        """RCPs only support 5 services."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    principal="*",
                    action=["ec2:*"],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert len(issues) == 1
        assert issues[0].issue_type == "unsupported_rcp_service"
        assert issues[0].severity == "error"
        assert "ec2" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_rcp_supported_services(self):
        """RCPs support s3, sts, sqs, secretsmanager, kms."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    principal="*",
                    action=[
                        "s3:*",
                        "sts:AssumeRole",
                        "sqs:SendMessage",
                        "secretsmanager:GetSecretValue",
                        "kms:Decrypt",
                    ],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_rcp_not_action_not_supported(self):
        """RCPs don't support NotAction."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    principal="*",
                    not_action=["s3:GetObject"],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_rcp_not_action"
        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_rcp_missing_resource(self):
        """RCPs must have Resource or NotResource."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    principal="*",
                    action=["s3:*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert len(issues) == 1
        assert issues[0].issue_type == "missing_rcp_resource"
        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_rcp_multiple_violations(self):
        """RCP with multiple violations should report all."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",  # Wrong effect
                    action=["*"],  # Wildcard not allowed
                    # Missing principal
                    # Missing resource
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        # Should have: invalid_effect, wildcard_action, missing_principal, missing_resource
        assert len(issues) >= 3
        issue_types = {issue.issue_type for issue in issues}
        assert "invalid_rcp_effect" in issue_types
        assert "invalid_rcp_wildcard_action" in issue_types
        assert "missing_rcp_principal" in issue_types

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


class TestSCPValidationEnhancements:
    """Tests for SCP-specific validation improvements."""

    @pytest.mark.asyncio
    async def test_scp_size_limit_under_limit(self):
        """SCP under 5120 bytes should not trigger size error."""
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
        raw_dict = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "ec2:*", "Resource": "*"}],
        }
        issues = await execute_policy(
            policy, "test.json", policy_type="SERVICE_CONTROL_POLICY", raw_policy_dict=raw_dict
        )
        size_issues = [i for i in issues if i.issue_type == "scp_size_exceeded"]
        assert len(size_issues) == 0

    @pytest.mark.asyncio
    async def test_scp_size_limit_exceeded(self):
        """SCP over 5120 bytes should trigger size error."""
        # Create a large policy that exceeds 5120 bytes (need >5120 chars minified)
        large_actions = [f"service{i}:Action{j}" for i in range(60) for j in range(5)]
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    action=large_actions,
                    resource=["*"],
                )
            ],
        )
        raw_dict = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": large_actions, "Resource": "*"}],
        }
        issues = await execute_policy(
            policy, "test.json", policy_type="SERVICE_CONTROL_POLICY", raw_policy_dict=raw_dict
        )
        size_issues = [i for i in issues if i.issue_type == "scp_size_exceeded"]
        assert len(size_issues) == 1
        assert size_issues[0].severity == "error"
        assert "5,120" in size_issues[0].message

    @pytest.mark.asyncio
    async def test_scp_with_not_principal_error(self):
        """SCPs with NotPrincipal should generate separate error."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    not_principal={"AWS": "arn:aws:iam::123456789012:root"},
                    action=["ec2:*"],
                    resource=["*"],
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="SERVICE_CONTROL_POLICY")
        not_principal_issues = [i for i in issues if i.issue_type == "invalid_not_principal"]
        assert len(not_principal_issues) == 1
        assert not_principal_issues[0].severity == "error"
        assert "NotPrincipal" in not_principal_issues[0].message

    @pytest.mark.asyncio
    async def test_scp_principal_and_not_principal_separate_errors(self):
        """SCPs should give separate errors for Principal vs NotPrincipal."""
        # Test Principal error
        policy_with_principal = IAMPolicy(
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
        issues_principal = await execute_policy(
            policy_with_principal, "test.json", policy_type="SERVICE_CONTROL_POLICY"
        )
        principal_issues = [i for i in issues_principal if i.issue_type == "invalid_principal"]
        assert len(principal_issues) == 1

        # Test NotPrincipal error
        policy_with_not_principal = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    not_principal="*",
                    action=["ec2:*"],
                    resource=["*"],
                )
            ],
        )
        issues_not_principal = await execute_policy(
            policy_with_not_principal, "test.json", policy_type="SERVICE_CONTROL_POLICY"
        )
        not_principal_issues = [i for i in issues_not_principal if i.issue_type == "invalid_not_principal"]
        assert len(not_principal_issues) == 1


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
        """RCPs support s3, sts, sqs, kms, secretsmanager, cognito, dynamodb, ecr, aoss, logs."""
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
                        "kms:Decrypt",
                        "secretsmanager:GetSecretValue",
                        "cognito-idp:AdminInitiateAuth",
                        "cognito-identity:GetCredentialsForIdentity",
                        "dynamodb:GetItem",
                        "ecr:GetDownloadUrlForLayer",
                        "aoss:APIAccessAll",
                        "logs:PutLogEvents",
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


class TestSCPAllowStatementValidity:
    """SCPs support the full IAM policy language since 2025-09-19.

    Allow statements may use Condition, scoped resource ARNs, NotAction and
    NotResource — the old Resource:"*"-only / no-Condition restrictions must
    NOT be flagged anymore.
    """

    @pytest.mark.asyncio
    async def test_allow_scp_with_scoped_resource_is_clean(self):
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[Statement(effect="Allow", action=["s3:*"], resource=["arn:aws:s3:::x"])],
        )
        issues = await execute_policy(policy, "test.json", policy_type="SERVICE_CONTROL_POLICY")
        assert not [i for i in issues if i.issue_type.startswith("invalid_scp_allow")]

    @pytest.mark.asyncio
    async def test_allow_scp_with_condition_is_clean(self):
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    action=["s3:*"],
                    resource=["*"],
                    condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="SERVICE_CONTROL_POLICY")
        assert not [i for i in issues if i.issue_type.startswith("invalid_scp_allow")]

    @pytest.mark.asyncio
    async def test_allow_scp_with_not_resource_is_clean(self):
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[Statement(effect="Allow", action=["s3:*"], not_resource=["arn:aws:s3:::x"])],
        )
        issues = await execute_policy(policy, "test.json", policy_type="SERVICE_CONTROL_POLICY")
        assert not [i for i in issues if i.issue_type.startswith("invalid_scp_allow")]

    @pytest.mark.asyncio
    async def test_deny_scp_with_scoped_resource_and_condition_is_clean(self):
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    action=["s3:DeleteBucket"],
                    resource=["arn:aws:s3:::prod-*"],
                    condition={"StringNotEquals": {"aws:PrincipalOrgID": "o-example"}},
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="SERVICE_CONTROL_POLICY")
        assert not [i for i in issues if i.issue_type.startswith("invalid_scp_allow")]

    @pytest.mark.asyncio
    async def test_scp_with_principal_still_error(self):
        """Principal/NotPrincipal remain unsupported in SCPs."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[Statement(effect="Deny", principal="*", action=["s3:*"], resource=["*"])],
        )
        issues = await execute_policy(policy, "test.json", policy_type="SERVICE_CONTROL_POLICY")
        assert [i for i in issues if i.issue_type == "invalid_principal"]


class TestRCPSupportedServices:
    """RCP supported-service list (expanded to 26 prefixes, verified 2026-07-20)."""

    @staticmethod
    def _rcp_policy(action: str) -> IAMPolicy:
        return IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    principal="*",
                    action=[action],
                    resource=["*"],
                )
            ],
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "action",
        [
            "codebuild:*",
            "codecommit:GitPush",
            "textract:*",
            "signin:*",
            "autoscaling:*",
            "dax:*",
            "kinesisvideo:GetMedia",
            "support:*",
        ],
    )
    async def test_newly_supported_services_accepted(self, action):
        issues = await execute_policy(self._rcp_policy(action), "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert not [i for i in issues if i.issue_type == "unsupported_rcp_service"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", ["ec2:RunInstances", "lambda:InvokeFunction", "es:ESHttpGet"])
    async def test_unsupported_services_still_error(self, action):
        issues = await execute_policy(self._rcp_policy(action), "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert [i for i in issues if i.issue_type == "unsupported_rcp_service"]

    @pytest.mark.asyncio
    async def test_additional_rcp_services_config_extends_list(self):
        """Users can accept newer AWS launches without a validator release."""
        policy = self._rcp_policy("newservice:DoThing")
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert [i for i in issues if i.issue_type == "unsupported_rcp_service"]

        issues = await execute_policy(
            policy,
            "test.json",
            policy_type="RESOURCE_CONTROL_POLICY",
            additional_rcp_services=["newservice"],
        )
        assert not [i for i in issues if i.issue_type == "unsupported_rcp_service"]


class TestRCPShapeHint:
    """Un-declared policies matching the customer-RCP shape get a hint."""

    @staticmethod
    def _rcp_shaped_policy() -> IAMPolicy:
        return IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    principal="*",
                    action=["s3:*"],
                    resource=["*"],
                    condition={"StringNotEqualsIfExists": {"aws:PrincipalOrgID": "o-example"}},
                )
            ],
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("policy_type", ["IDENTITY_POLICY", "RESOURCE_POLICY"])
    async def test_rcp_shape_hint_emitted(self, policy_type):
        issues = await execute_policy(self._rcp_shaped_policy(), "test.json", policy_type=policy_type)
        hints = [i for i in issues if i.issue_type == "policy_type_hint"]
        assert len(hints) == 1
        assert "RESOURCE_CONTROL_POLICY" in hints[0].message

    @pytest.mark.asyncio
    async def test_no_hint_for_scoped_resource_deny_policy(self):
        """Deny-style resource policies with scoped ARNs (e.g. S3 TLS-only) don't hint."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    principal="*",
                    action=["s3:*"],
                    resource=["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
                    condition={"Bool": {"aws:SecureTransport": "false"}},
                )
            ],
        )
        issues = await execute_policy(policy, "test.json", policy_type="RESOURCE_POLICY")
        assert not [i for i in issues if i.issue_type == "policy_type_hint"]

    @pytest.mark.asyncio
    async def test_no_hint_when_declared_as_rcp(self):
        issues = await execute_policy(self._rcp_shaped_policy(), "test.json", policy_type="RESOURCE_CONTROL_POLICY")
        assert not [i for i in issues if i.issue_type == "policy_type_hint"]

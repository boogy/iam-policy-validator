"""Tests for IfExists condition usage check."""

import pytest

from iam_validator.checks.ifexists_condition_check import IfExistsConditionCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestIfExistsSecuritySensitiveAllow:
    """Test IfExists on security-sensitive keys in Allow statements."""

    @pytest.fixture
    def check(self):
        return IfExistsConditionCheck()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="ifexists_condition_usage")

    @pytest.mark.asyncio
    async def test_ifexists_source_ip_allow_warns(self, check, config):
        """IfExists on SourceIp in Allow should warn."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"IpAddressIfExists": {"aws:SourceIp": "10.0.0.0/8"}},
        )
        issues = await check.execute(statement, 0, None, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "ifexists_weakens_security_condition"
        assert "aws:SourceIp" in issues[0].message
        assert "bypassed" in issues[0].message

    @pytest.mark.asyncio
    async def test_no_ifexists_source_ip_allow_no_warn(self, check, config):
        """IpAddress without IfExists on SourceIp in Allow should not warn."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
        )
        issues = await check.execute(statement, 0, None, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_ifexists_source_ip_deny_no_security_warn(self, check, config):
        """IfExists on SourceIp in Deny should not warn about security bypass."""
        statement = Statement(
            Effect="Deny",
            Action=["*"],
            Resource=["*"],
            Condition={"IpAddressIfExists": {"aws:SourceIp": "10.0.0.0/8"}},
        )
        issues = await check.execute(statement, 0, None, config)
        # Should not have Allow-specific warning
        assert not any(
            i.issue_type == "ifexists_weakens_security_condition" for i in issues
        )

    @pytest.mark.asyncio
    async def test_ifexists_secure_transport_allow_redundant(self, check, config):
        """IfExists on SecureTransport (always-present) should flag as redundant, not security."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["arn:aws:s3:::mybucket/*"],
            Condition={"BoolIfExists": {"aws:SecureTransport": "true"}},
        )
        issues = await check.execute(statement, 0, None, config)
        # SecureTransport is always present, so IfExists is redundant (not a security bypass)
        assert not any(
            i.issue_type == "ifexists_weakens_security_condition" for i in issues
        )
        assert any(
            i.issue_type == "ifexists_on_always_present_key" for i in issues
        )

    @pytest.mark.asyncio
    async def test_ifexists_principal_arn_allow_warns(self, check, config):
        """IfExists on PrincipalArn (absent for anonymous) in Allow should warn."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={
                "ArnLikeIfExists": {
                    "aws:PrincipalArn": "arn:aws:iam::123:role/*"
                }
            },
        )
        issues = await check.execute(statement, 0, None, config)
        assert any(
            i.issue_type == "ifexists_weakens_security_condition" for i in issues
        )

    @pytest.mark.asyncio
    async def test_ifexists_non_security_key_allow_no_warn(self, check, config):
        """IfExists on non-security key in Allow should not warn."""
        statement = Statement(
            Effect="Allow",
            Action=["ec2:RunInstances"],
            Resource=["*"],
            Condition={"StringLikeIfExists": {"ec2:InstanceType": ["t3.*"]}},
        )
        issues = await check.execute(statement, 0, None, config)
        assert not any(
            i.issue_type == "ifexists_weakens_security_condition" for i in issues
        )

    @pytest.mark.asyncio
    async def test_ifexists_with_null_check_suppresses_warning(self, check, config):
        """IfExists with complementary Null check should not warn."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={
                "IpAddressIfExists": {"aws:SourceIp": "10.0.0.0/8"},
                "Null": {"aws:SourceIp": "false"},
            },
        )
        issues = await check.execute(statement, 0, None, config)
        assert not any(
            i.issue_type == "ifexists_weakens_security_condition" for i in issues
        )

    @pytest.mark.asyncio
    async def test_ifexists_mfa_key_skipped(self, check, config):
        """IfExists on MultiFactorAuthPresent should be skipped (handled by mfa check)."""
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
            Condition={"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
        )
        issues = await check.execute(statement, 0, None, config)
        assert not any(
            i.issue_type == "ifexists_weakens_security_condition" for i in issues
        )

    @pytest.mark.asyncio
    async def test_forallvalues_ifexists_security_key_warns(self, check, config):
        """ForAllValues:StringEqualsIfExists on security key should warn."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={
                "ForAllValues:StringEqualsIfExists": {
                    "aws:PrincipalOrgPaths": ["o-123/r-abc/"]
                }
            },
        )
        issues = await check.execute(statement, 0, None, config)
        assert any(
            i.issue_type == "ifexists_weakens_security_condition" for i in issues
        )


class TestIfExistsDenyPatterns:
    """Test IfExists patterns in Deny statements."""

    @pytest.fixture
    def check(self):
        return IfExistsConditionCheck()

    @pytest.fixture
    def config(self):
        return CheckConfig(
            check_id="ifexists_condition_usage",
            config={"suggest_deny_ifexists": True},
        )

    @pytest.mark.asyncio
    async def test_negated_ifexists_deny_no_warning(self, check, config):
        """Negated IfExists in Deny is safe, no warning."""
        statement = Statement(
            Effect="Deny",
            Action=["*"],
            Resource=["*"],
            Condition={
                "StringNotEqualsIfExists": {"aws:PrincipalOrgID": "o-123456"}
            },
        )
        issues = await check.execute(statement, 0, None, config)
        assert not any(i.issue_type == "ifexists_weakens_deny" for i in issues)

    @pytest.mark.asyncio
    async def test_non_negated_ifexists_deny_warns(self, check, config):
        """Non-negated IfExists in Deny weakens the Deny, should warn."""
        statement = Statement(
            Effect="Deny",
            Action=["s3:DeleteBucket"],
            Resource=["*"],
            Condition={
                "StringEqualsIfExists": {"aws:SourceVpc": "vpc-123456"}
            },
        )
        issues = await check.execute(statement, 0, None, config)
        assert any(i.issue_type == "ifexists_weakens_deny" for i in issues)

    @pytest.mark.asyncio
    async def test_suggest_ifexists_for_negated_deny_without_it(self, check, config):
        """Should suggest adding IfExists for negated operator in Deny."""
        statement = Statement(
            Effect="Deny",
            Action=["*"],
            Resource=["*"],
            Condition={"StringNotEquals": {"aws:SourceVpc": "vpc-123456"}},
        )
        issues = await check.execute(statement, 0, None, config)
        assert any(i.issue_type == "ifexists_deny_suggestion" for i in issues)

    @pytest.mark.asyncio
    async def test_no_suggestion_for_always_present_key(self, check, config):
        """Should not suggest IfExists for always-present keys."""
        statement = Statement(
            Effect="Deny",
            Action=["*"],
            Resource=["*"],
            Condition={
                "StringNotEquals": {
                    "aws:PrincipalAccount": "123456789012"
                }
            },
        )
        issues = await check.execute(statement, 0, None, config)
        assert not any(i.issue_type == "ifexists_deny_suggestion" for i in issues)

    @pytest.mark.asyncio
    async def test_suggestion_disabled_by_config(self, check):
        """Deny suggestions disabled when config is off."""
        config = CheckConfig(
            check_id="ifexists_condition_usage",
            config={"suggest_deny_ifexists": False},
        )
        statement = Statement(
            Effect="Deny",
            Action=["*"],
            Resource=["*"],
            Condition={"StringNotEquals": {"aws:SourceVpc": "vpc-123456"}},
        )
        issues = await check.execute(statement, 0, None, config)
        assert not any(i.issue_type == "ifexists_deny_suggestion" for i in issues)


class TestIfExistsAlwaysPresentKeys:
    """Test IfExists on always-present condition keys."""

    @pytest.fixture
    def check(self):
        return IfExistsConditionCheck()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="ifexists_condition_usage")

    @pytest.mark.asyncio
    async def test_ifexists_principal_account_redundant(self, check, config):
        """IfExists on PrincipalAccount should flag as redundant."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={
                "StringEqualsIfExists": {
                    "aws:PrincipalAccount": "123456789012"
                }
            },
        )
        issues = await check.execute(statement, 0, None, config)
        redundant = [
            i for i in issues if i.issue_type == "ifexists_on_always_present_key"
        ]
        assert len(redundant) == 1
        assert "always present" in redundant[0].message
        assert "StringEquals" in redundant[0].message

    @pytest.mark.asyncio
    async def test_ifexists_on_sometimes_absent_key_no_redundant(self, check, config):
        """IfExists on sometimes-absent key should not flag as redundant."""
        statement = Statement(
            Effect="Allow",
            Action=["ec2:RunInstances"],
            Resource=["*"],
            Condition={
                "StringLikeIfExists": {"ec2:InstanceType": ["t3.*"]}
            },
        )
        issues = await check.execute(statement, 0, None, config)
        assert not any(
            i.issue_type == "ifexists_on_always_present_key" for i in issues
        )

    @pytest.mark.asyncio
    async def test_warn_always_present_disabled(self, check):
        """Should not warn when config disables it."""
        config = CheckConfig(
            check_id="ifexists_condition_usage",
            config={"warn_always_present_keys": False},
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={
                "StringEqualsIfExists": {
                    "aws:PrincipalAccount": "123456789012"
                }
            },
        )
        issues = await check.execute(statement, 0, None, config)
        assert not any(
            i.issue_type == "ifexists_on_always_present_key" for i in issues
        )


class TestCheckMetadata:
    """Test check metadata."""

    def test_check_id(self):
        check = IfExistsConditionCheck()
        assert check.check_id == "ifexists_condition_usage"

    def test_default_severity(self):
        check = IfExistsConditionCheck()
        assert check.default_severity == "warning"

    @pytest.mark.asyncio
    async def test_no_conditions_returns_empty(self):
        check = IfExistsConditionCheck()
        config = CheckConfig(check_id="ifexists_condition_usage")
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, None, config)
        assert len(issues) == 0

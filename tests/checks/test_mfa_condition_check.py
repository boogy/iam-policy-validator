"""Tests for MFA condition anti-pattern check."""

import pytest

from iam_validator.checks.mfa_condition_check import MFAConditionCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestMFAConditionCheck:
    """Test suite for MFAConditionCheck."""

    @pytest.fixture
    def check(self):
        return MFAConditionCheck()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="mfa_condition_antipattern")

    @pytest.mark.asyncio
    async def test_no_conditions(self, check, config):
        """Test statement with no conditions."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, None, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_bool_mfa_present_true(self, check, config):
        """Test correct MFA pattern (Bool with true)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )
        issues = await check.execute(statement, 0, None, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_bool_mfa_present_false(self, check, config):
        """Test dangerous pattern: Bool with MFA false."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        )
        issues = await check.execute(statement, 0, None, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "mfa_antipattern_bool_false"

    @pytest.mark.asyncio
    async def test_null_mfa_present_false(self, check, config):
        """Test dangerous pattern: Null with MFA false."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Null": {"aws:MultiFactorAuthPresent": "false"}},
        )
        issues = await check.execute(statement, 0, None, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "mfa_antipattern_null_false"

    @pytest.mark.asyncio
    async def test_null_mfa_present_true_detects_antipattern(self, check, config):
        """Test Null with MFA true (IS an anti-pattern - checks if key doesn't exist)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Null": {"aws:MultiFactorAuthPresent": "true"}},
        )
        issues = await check.execute(statement, 0, None, config)
        # Null: true means "key doesn't exist" = no MFA, which is dangerous
        assert len(issues) == 1
        assert issues[0].issue_type == "mfa_antipattern_null_true"

    @pytest.mark.asyncio
    async def test_boolif_exists_mfa_present_false(self, check, config):
        """Test dangerous pattern: BoolIfExists with MFA false (worse than Bool)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
        )
        issues = await check.execute(statement, 0, None, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "mfa_antipattern_boolif_exists_false"
        # BoolIfExists with false is higher severity than Bool
        assert issues[0].severity == "high"

    @pytest.mark.asyncio
    async def test_both_antipatterns_detected(self, check, config):
        """Test both anti-patterns in the same statement."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={
                "Bool": {"aws:MultiFactorAuthPresent": "false"},
                "Null": {"aws:MultiFactorAuthPresent": "false"},
            },
        )
        issues = await check.execute(statement, 0, None, config)
        assert len(issues) == 2
        issue_types = {issue.issue_type for issue in issues}
        assert "mfa_antipattern_bool_false" in issue_types
        assert "mfa_antipattern_null_false" in issue_types

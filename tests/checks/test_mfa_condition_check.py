"""Tests for MFA condition anti-pattern check."""

import pytest

from iam_validator.checks.mfa_condition_check import MFAConditionCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestMFAConditionCheck:
    """Test suite for MFAConditionCheck."""

    @pytest.fixture
    def check(self):
        """Create an MFAConditionCheck instance."""
        return MFAConditionCheck()

    @pytest.fixture
    def config(self):
        """Create a default CheckConfig."""
        return CheckConfig(check_id="mfa_condition_antipattern")

    def test_check_id(self, check):
        """Test check_id property."""
        assert check.check_id == "mfa_condition_antipattern"

    def test_description(self, check):
        """Test description property."""
        assert check.description == "Detects dangerous MFA-related condition patterns"

    def test_default_severity(self, check):
        """Test default_severity property."""
        assert check.default_severity == "warning"

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
    async def test_bool_mfa_present_false_string(self, check, config):
        """Test dangerous pattern: Bool with MFA false (string value)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        )
        issues = await check.execute(statement, 0, None, config)

        assert len(issues) == 1
        assert issues[0].severity == "warning"
        assert issues[0].issue_type == "mfa_antipattern_bool_false"
        assert "does not enforce MFA" in issues[0].message
        assert "BoolIfExists" in issues[0].message

    @pytest.mark.asyncio
    async def test_bool_mfa_present_false_boolean(self, check, config):
        """Test dangerous pattern: Bool with MFA false (boolean value)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Bool": {"aws:MultiFactorAuthPresent": False}},
        )
        issues = await check.execute(statement, 0, None, config)

        assert len(issues) == 1
        assert issues[0].issue_type == "mfa_antipattern_bool_false"

    @pytest.mark.asyncio
    async def test_bool_mfa_case_insensitive(self, check, config):
        """Test that MFA key matching is case-insensitive."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Bool": {"AWS:MULTIFACTORAUTHPRESENT": "false"}},
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
        assert issues[0].severity == "warning"
        assert issues[0].issue_type == "mfa_antipattern_null_false"
        assert "only checks if the key exists" in issues[0].message

    @pytest.mark.asyncio
    async def test_null_mfa_present_true(self, check, config):
        """Test Null with MFA true (not an anti-pattern, just unusual)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Null": {"aws:MultiFactorAuthPresent": "true"}},
        )
        issues = await check.execute(statement, 0, None, config)

        # This is not an anti-pattern (it checks if MFA key is missing)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_multiple_conditions_with_mfa_antipattern(self, check, config):
        """Test multiple conditions including MFA anti-pattern."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={
                "Bool": {"aws:MultiFactorAuthPresent": "false"},
                "StringEquals": {"aws:username": "admin"},
            },
        )
        issues = await check.execute(statement, 0, None, config)

        assert len(issues) == 1
        assert issues[0].issue_type == "mfa_antipattern_bool_false"

    @pytest.mark.asyncio
    async def test_both_antipatterns_in_same_statement(self, check, config):
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

        # Should detect both anti-patterns
        assert len(issues) == 2
        issue_types = {issue.issue_type for issue in issues}
        assert "mfa_antipattern_bool_false" in issue_types
        assert "mfa_antipattern_null_false" in issue_types

    @pytest.mark.asyncio
    async def test_statement_with_sid(self, check, config):
        """Test that statement SID is captured."""
        statement = Statement(
            Sid="EnforceMFA",
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        )
        issues = await check.execute(statement, 0, None, config)

        assert issues[0].statement_sid == "EnforceMFA"

    @pytest.mark.asyncio
    async def test_statement_index(self, check, config):
        """Test that statement index is captured."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        )
        issues = await check.execute(statement, 5, None, config)

        assert issues[0].statement_index == 5

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, config):
        """Test that line number is captured when available."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        )
        statement.line_number = 42

        issues = await check.execute(statement, 0, None, config)

        assert issues[0].line_number == 42

    @pytest.mark.asyncio
    async def test_custom_severity(self, check):
        """Test custom severity from config."""
        config = CheckConfig(check_id="mfa_condition_antipattern", severity="error")

        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        )
        issues = await check.execute(statement, 0, None, config)

        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_array_of_values(self, check, config):
        """Test MFA condition with array of values."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Bool": {"aws:MultiFactorAuthPresent": ["false", "true"]}},
        )
        issues = await check.execute(statement, 0, None, config)

        # Should detect the false value in the array
        assert len(issues) == 1
        assert issues[0].issue_type == "mfa_antipattern_bool_false"

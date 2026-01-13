"""Tests for action validation check."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.checks.action_validation import ActionValidationCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestActionValidationCheck:
    """Test suite for ActionValidationCheck."""

    @pytest.fixture
    def check(self):
        """Create an ActionValidationCheck instance."""
        return ActionValidationCheck()

    @pytest.fixture
    def fetcher(self):
        """Create a mock AWSServiceFetcher instance."""
        mock = MagicMock(spec=AWSServiceFetcher)
        mock.validate_action = AsyncMock()
        return mock

    @pytest.fixture
    def config(self):
        """Create a default CheckConfig."""
        return CheckConfig(check_id="action_validation")

    def test_check_id(self, check):
        """Test check_id property."""
        assert check.check_id == "action_validation"

    def test_description(self, check):
        """Test description property."""
        assert check.description == "Validates that actions exist in AWS service definitions"

    def test_default_severity(self, check):
        """Test default_severity property."""
        assert check.default_severity == "error"

    @pytest.mark.asyncio
    async def test_valid_action(self, check, fetcher, config):
        """Test valid action passes."""
        fetcher.validate_action.return_value = (True, None, False)

        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        fetcher.validate_action.assert_called_once_with("s3:GetObject")

    @pytest.mark.asyncio
    async def test_invalid_action(self, check, fetcher, config):
        """Test invalid action is flagged."""
        fetcher.validate_action.return_value = (
            False,
            "Action 's3:InvalidAction' does not exist",
            False,
        )

        statement = Statement(
            Effect="Allow", Action=["s3:InvalidAction"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].issue_type == "invalid_action"
        assert issues[0].action == "s3:InvalidAction"
        assert "does not exist" in issues[0].message

    @pytest.mark.asyncio
    async def test_wildcard_action_skipped(self, check, fetcher, config):
        """Test wildcard-only action is skipped."""
        statement = Statement(Effect="Allow", Action=["*"], Resource=["arn:aws:s3:::bucket/*"])
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        fetcher.validate_action.assert_not_called()

    @pytest.mark.asyncio
    async def test_wildcard_pattern_action_valid(self, check, fetcher, config):
        """Test valid wildcard pattern actions are validated and pass."""
        fetcher.validate_action.return_value = (True, None, True)

        statement = Statement(
            Effect="Allow", Action=["s3:Put*"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # No issues - wildcard matches at least one action
        assert len(issues) == 0
        # validate_action IS called for wildcard patterns (to ensure they match real actions)
        fetcher.validate_action.assert_called_once_with("s3:Put*")

    @pytest.mark.asyncio
    async def test_wildcard_pattern_action_invalid(self, check, fetcher, config):
        """Test invalid wildcard pattern (typo) is flagged."""
        fetcher.validate_action.return_value = (
            False,
            "Action pattern `Putt*` does not match any actions in service `s3`",
            True,
        )

        # Typo in wildcard pattern - "Putt*" instead of "Put*"
        statement = Statement(
            Effect="Allow", Action=["s3:Putt*"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Invalid wildcard pattern should be flagged
        assert len(issues) == 1
        assert issues[0].action == "s3:Putt*"
        assert "does not match any actions" in issues[0].message

    @pytest.mark.asyncio
    async def test_multiple_actions(self, check, fetcher, config):
        """Test multiple actions are validated."""

        async def validate_side_effect(action):
            if action == "s3:GetObject":
                return (True, None, False)
            else:
                return (False, f"Action '{action}' does not exist", False)

        fetcher.validate_action.side_effect = validate_side_effect

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "s3:InvalidAction"],
            Resource=["arn:aws:s3:::bucket/*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].action == "s3:InvalidAction"
        assert fetcher.validate_action.call_count == 2

    @pytest.mark.asyncio
    async def test_statement_with_sid(self, check, fetcher, config):
        """Test that statement SID is captured."""
        fetcher.validate_action.return_value = (False, "Invalid action", False)

        statement = Statement(
            Sid="TestStatement",
            Effect="Allow",
            Action=["s3:InvalidAction"],
            Resource=["arn:aws:s3:::bucket/*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].statement_sid == "TestStatement"

    @pytest.mark.asyncio
    async def test_statement_index(self, check, fetcher, config):
        """Test that statement index is captured."""
        fetcher.validate_action.return_value = (False, "Invalid action", False)

        statement = Statement(
            Effect="Allow", Action=["s3:InvalidAction"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 3, fetcher, config)

        assert issues[0].statement_index == 3

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, fetcher, config):
        """Test that line number is captured when available."""
        fetcher.validate_action.return_value = (False, "Invalid action", False)

        statement = Statement(
            Effect="Allow", Action=["s3:InvalidAction"], Resource=["arn:aws:s3:::bucket/*"]
        )
        statement.line_number = 42

        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].line_number == 42

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity from config."""
        fetcher.validate_action.return_value = (False, "Invalid action", False)

        config = CheckConfig(check_id="action_validation", severity="warning")
        statement = Statement(
            Effect="Allow", Action=["s3:InvalidAction"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].severity == "warning"

    @pytest.mark.asyncio
    async def test_string_action(self, check, fetcher, config):
        """Test action as string instead of list."""
        fetcher.validate_action.return_value = (True, None, False)

        statement = Statement(
            Effect="Allow", Action="s3:GetObject", Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        fetcher.validate_action.assert_called_once_with("s3:GetObject")

    @pytest.mark.asyncio
    async def test_no_actions(self, check, fetcher, config):
        """Test statement with no Action field."""
        statement = Statement(Effect="Allow", Resource=["arn:aws:s3:::bucket/*"])
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        fetcher.validate_action.assert_not_called()

    @pytest.mark.asyncio
    async def test_error_message_fallback(self, check, fetcher, config):
        """Test fallback error message when none provided."""
        fetcher.validate_action.return_value = (False, None, False)

        statement = Statement(
            Effect="Allow", Action=["s3:InvalidAction"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Invalid action: `s3:InvalidAction`" in issues[0].message

    @pytest.mark.asyncio
    async def test_not_action_valid(self, check, fetcher, config):
        """Test valid NotAction passes."""
        fetcher.validate_action.return_value = (True, None, False)

        statement = Statement(
            Effect="Deny", NotAction=["s3:GetObject"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        fetcher.validate_action.assert_called_once_with("s3:GetObject")

    @pytest.mark.asyncio
    async def test_not_action_invalid(self, check, fetcher, config):
        """Test invalid NotAction is flagged."""
        fetcher.validate_action.return_value = (
            False,
            "Action 's3:InvalidAction' does not exist",
            False,
        )

        statement = Statement(
            Effect="Deny", NotAction=["s3:InvalidAction"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].issue_type == "invalid_action"
        assert issues[0].action == "s3:InvalidAction"
        assert issues[0].field_name == "not_action"

    @pytest.mark.asyncio
    async def test_not_action_wildcard_pattern_invalid(self, check, fetcher, config):
        """Test invalid NotAction wildcard pattern is flagged."""
        fetcher.validate_action.return_value = (
            False,
            "Action pattern `Gett*` does not match any actions in service `s3`",
            True,
        )

        # Typo in NotAction wildcard - "Gett*" instead of "Get*"
        statement = Statement(
            Effect="Deny", NotAction=["s3:Gett*"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].action == "s3:Gett*"
        assert issues[0].field_name == "not_action"

    @pytest.mark.asyncio
    async def test_both_action_and_not_action(self, check, fetcher, config):
        """Test statement with both Action and NotAction (unusual but valid IAM)."""

        async def validate_side_effect(action):
            if action == "s3:GetObject":
                return (True, None, False)
            else:
                return (False, f"Action '{action}' does not exist", False)

        fetcher.validate_action.side_effect = validate_side_effect

        # Both Action and NotAction in same statement (IAM allows this, though unusual)
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            NotAction=["s3:InvalidAction"],
            Resource=["arn:aws:s3:::bucket/*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag the invalid NotAction
        assert len(issues) == 1
        assert issues[0].action == "s3:InvalidAction"
        assert issues[0].field_name == "not_action"

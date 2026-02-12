"""Tests for NotPrincipal validation check."""

from unittest.mock import MagicMock

import pytest

from iam_validator.checks.not_principal_validation import NotPrincipalValidationCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
def check() -> NotPrincipalValidationCheck:
    return NotPrincipalValidationCheck()


@pytest.fixture
def config() -> CheckConfig:
    return CheckConfig(check_id="not_principal_validation", enabled=True)


@pytest.fixture
def mock_fetcher() -> MagicMock:
    return MagicMock()


class TestNotPrincipalValidationCheck:
    """Tests for NotPrincipalValidationCheck."""

    @pytest.mark.asyncio
    async def test_no_not_principal_no_issues(self, check, config, mock_fetcher):
        """Test that statements without NotPrincipal produce no issues."""
        statement = Statement(
            effect="Allow",
            action=["s3:GetObject"],
            resource=["arn:aws:s3:::bucket/*"],
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_no_not_principal_with_principal_no_issues(self, check, config, mock_fetcher):
        """Test that statements with Principal (not NotPrincipal) produce no issues."""
        statement = Statement(
            effect="Allow",
            principal="*",
            action=["s3:GetObject"],
            resource=["arn:aws:s3:::bucket/*"],
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_not_principal_with_allow_is_error(self, check, config, mock_fetcher):
        """Test that NotPrincipal with Allow effect produces an error with suggestion."""
        statement = Statement(
            effect="Allow",
            not_principal={"AWS": "arn:aws:iam::123456789012:root"},
            action=["s3:GetObject"],
            resource=["arn:aws:s3:::bucket/*"],
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].issue_type == "not_principal_with_allow"
        assert "not supported" in issues[0].message.lower()
        assert issues[0].suggestion is not None
        assert "Principal" in issues[0].suggestion
        assert issues[0].example is not None

    @pytest.mark.asyncio
    async def test_not_principal_with_deny_is_warning(self, check, config, mock_fetcher):
        """Test that NotPrincipal with Deny effect produces a warning with suggestion."""
        statement = Statement(
            effect="Deny",
            not_principal={"AWS": "arn:aws:iam::123456789012:root"},
            action=["s3:*"],
            resource=["arn:aws:s3:::bucket/*"],
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "warning"
        assert issues[0].issue_type == "not_principal_usage"
        assert "recommends" in issues[0].message.lower()
        assert issues[0].suggestion is not None
        assert "ArnNotEquals" in issues[0].suggestion or "StringNotEquals" in issues[0].suggestion
        assert issues[0].example is not None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "not_principal",
        [
            "arn:aws:iam::123456789012:root",  # String format
            "*",  # Wildcard
        ],
    )
    async def test_not_principal_alternative_formats(self, not_principal, check, config, mock_fetcher):
        """Test NotPrincipal with string and wildcard formats."""
        statement = Statement(
            effect="Deny",
            not_principal=not_principal,
            action=["s3:*"],
            resource=["arn:aws:s3:::bucket/*"],
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "not_principal_usage"

    @pytest.mark.asyncio
    async def test_issue_metadata_populated(self, check, config, mock_fetcher):
        """Test that issues have proper metadata."""
        statement = Statement(
            sid="DenyNotPrincipal",
            effect="Allow",
            not_principal={"AWS": "arn:aws:iam::123456789012:root"},
            action=["s3:GetObject"],
            resource=["arn:aws:s3:::bucket/*"],
            line_number=10,
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].statement_index == 0
        assert issues[0].statement_sid == "DenyNotPrincipal"
        assert issues[0].line_number == 10
        assert issues[0].field_name == "principal"

    @pytest.mark.asyncio
    async def test_custom_severity_for_deny(self, check, mock_fetcher):
        """Test that custom severity from config is used for Deny issues."""
        custom_config = CheckConfig(
            check_id="not_principal_validation",
            enabled=True,
            severity="high",
        )
        statement = Statement(
            effect="Deny",
            not_principal={"AWS": "arn:aws:iam::123456789012:root"},
            action=["s3:*"],
            resource=["arn:aws:s3:::bucket/*"],
        )
        issues = await check.execute(statement, 0, mock_fetcher, custom_config)
        assert len(issues) == 1
        assert issues[0].severity == "high"

    @pytest.mark.asyncio
    async def test_allow_severity_always_error(self, check, mock_fetcher):
        """Test that Allow + NotPrincipal is always error regardless of config severity."""
        custom_config = CheckConfig(
            check_id="not_principal_validation",
            enabled=True,
            severity="low",
        )
        statement = Statement(
            effect="Allow",
            not_principal={"AWS": "arn:aws:iam::123456789012:root"},
            action=["s3:GetObject"],
            resource=["arn:aws:s3:::bucket/*"],
        )
        issues = await check.execute(statement, 0, mock_fetcher, custom_config)
        assert len(issues) == 1
        assert issues[0].severity == "error"

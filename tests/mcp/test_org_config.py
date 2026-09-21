"""Tests for session configuration management in MCP server.

This module tests ``SessionState`` and the MCP org-config tool implementations.
All validation is done by the IAM validator's built-in checks - these tests
verify config loading and session management.
"""

import pytest

from iam_validator.core.config.config_loader import ValidatorConfig
from iam_validator.mcp.context import SessionState


class TestValidatorConfigBasics:
    """Tests for ValidatorConfig basic operations."""

    def test_default_config(self):
        """Test that default config works."""
        config = ValidatorConfig(use_defaults=False)
        assert config.settings is not None

    def test_check_config_access(self):
        """Test that check configs can be accessed."""
        config = ValidatorConfig(
            {"wildcard_action": {"enabled": True, "severity": "critical"}},
            use_defaults=False,
        )

        check_config = config.get_check_config("wildcard_action")
        assert check_config["enabled"] is True
        assert check_config["severity"] == "critical"

    def test_settings_access(self):
        """Test that settings can be accessed."""
        config = ValidatorConfig(
            {"settings": {"fail_on_severity": ["error", "critical", "high"]}},
            use_defaults=False,
        )

        assert config.settings.get("fail_on_severity") == ["error", "critical", "high"]

    def test_get_setting_with_default(self):
        """Test get_setting with default value."""
        config = ValidatorConfig(use_defaults=False)

        value = config.get_setting("nonexistent", default="fallback")
        assert value == "fallback"


class TestSessionState:
    """Tests for the SessionState class's organization-config methods."""

    @pytest.fixture
    def session(self):
        return SessionState()

    def test_set_and_get_config(self, session):
        """Test setting and getting configuration."""
        session.set_config({"settings": {"fail_on_severity": ["error"]}}, source="test")

        retrieved = session.get_config()
        assert retrieved is not None
        assert retrieved.settings.get("fail_on_severity") == ["error"]
        assert session.get_config_source() == "test"

    def test_has_config(self, session):
        """Test has_config method."""
        assert not session.has_config()

        session.set_config({})

        assert session.has_config()

    def test_clear_config(self, session):
        """Test clearing configuration."""
        session.set_config({})
        assert session.has_config()

        had_config = session.clear_config()

        assert had_config is True
        assert not session.has_config()
        assert session.get_config() is None

    def test_clear_config_when_none_set(self, session):
        """Test clearing when no config is set."""
        had_config = session.clear_config()

        assert had_config is False

    def test_load_from_yaml(self, session):
        """Test loading configuration from YAML."""
        yaml_content = """
settings:
  fail_on_severity:
    - error
    - critical

wildcard_action:
  enabled: true
  severity: high
"""
        config, warnings = session.load_config_from_yaml(yaml_content)

        assert config.settings.get("fail_on_severity") == ["error", "critical"]
        assert config.get_check_config("wildcard_action")["enabled"] is True
        assert session.get_config_source() == "yaml"

    def test_load_from_yaml_with_organization_key(self, session):
        """Test loading YAML with 'organization' wrapper key (legacy format)."""
        yaml_content = """
organization:
  fail_on_severity:
    - error
"""
        config, warnings = session.load_config_from_yaml(yaml_content)

        assert config.settings.get("fail_on_severity") == ["error"]
        assert any("organization" in w.lower() for w in warnings)

    def test_load_from_yaml_invalid(self, session):
        """Test that invalid YAML raises an error."""
        yaml_content = "invalid: yaml: content:"

        with pytest.raises(ValueError, match="Invalid YAML"):
            session.load_config_from_yaml(yaml_content)


class TestOrgConfigToolImplementations:
    """Tests for the org config tool implementations.

    These tests verify the business logic of org config tools by calling
    the implementation functions directly with an explicit SessionState.
    """

    @pytest.fixture
    def session(self):
        return SessionState()

    async def test_set_organization_config(self, session):
        """Test the set_organization_config implementation."""
        from iam_validator.mcp.tools.config import (
            set_organization_config_impl,
        )

        result = await set_organization_config_impl(
            {
                "settings": {"fail_on_severity": ["error", "critical"]},
                "wildcard_action": {"enabled": True, "severity": "high"},
            },
            session,
        )

        assert result["success"] is True
        assert "settings" in result["applied_config"]
        assert session.has_config()

    async def test_set_organization_config_no_session(self):
        """Hosted mode (session=None) reports a structured error, not a crash."""
        from iam_validator.mcp.tools.config import (
            set_organization_config_impl,
        )

        result = await set_organization_config_impl({"settings": {}}, None)

        assert result["success"] is False
        assert "error" in result

    async def test_get_organization_config_none_set(self, session):
        """Test get_organization_config when none is set."""
        from iam_validator.mcp.tools.config import (
            get_organization_config_impl,
        )

        result = await get_organization_config_impl(session)

        assert result["has_config"] is False
        assert result["config"] is None
        assert result["source"] == "none"

    async def test_get_organization_config_with_config(self, session):
        """Test get_organization_config when config is set."""
        from iam_validator.mcp.tools.config import (
            get_organization_config_impl,
            set_organization_config_impl,
        )

        await set_organization_config_impl(
            {
                "settings": {"fail_on_severity": ["error"]},
            },
            session,
        )
        result = await get_organization_config_impl(session)

        assert result["has_config"] is True
        assert "settings" in result["config"]
        assert result["source"] == "session"

    async def test_clear_organization_config(self, session):
        """Test clearing organization config."""
        from iam_validator.mcp.tools.config import (
            clear_organization_config_impl,
            get_organization_config_impl,
            set_organization_config_impl,
        )

        await set_organization_config_impl({"settings": {}}, session)
        result = await clear_organization_config_impl(session)

        assert result["status"] == "cleared"

        get_result = await get_organization_config_impl(session)
        assert get_result["has_config"] is False

    async def test_clear_organization_config_when_none(self, session):
        """Test clearing when no config is set."""
        from iam_validator.mcp.tools.config import (
            clear_organization_config_impl,
        )

        result = await clear_organization_config_impl(session)

        assert result["status"] == "no_config_set"

    async def test_clear_organization_config_no_session(self):
        """Hosted mode (session=None) reports no_config_set rather than crashing."""
        from iam_validator.mcp.tools.config import (
            clear_organization_config_impl,
        )

        result = await clear_organization_config_impl(None)

        assert result["status"] == "no_config_set"

    async def test_load_organization_config_from_yaml(self, session):
        """Test loading config from YAML."""
        from iam_validator.mcp.tools.config import (
            load_organization_config_from_yaml_impl,
        )

        yaml_content = """
settings:
  fail_on_severity:
    - error
    - critical
"""
        result = await load_organization_config_from_yaml_impl(yaml_content, session)

        assert result["success"] is True
        assert "settings" in result["applied_config"]

    async def test_load_organization_config_from_yaml_invalid(self, session):
        """Test loading invalid YAML."""
        from iam_validator.mcp.tools.config import (
            load_organization_config_from_yaml_impl,
        )

        result = await load_organization_config_from_yaml_impl("invalid: yaml: :", session)

        assert result["success"] is False
        assert "error" in result

    async def test_load_organization_config_from_yaml_no_session(self):
        """Hosted mode (session=None) reports a structured error, not a crash."""
        from iam_validator.mcp.tools.config import (
            load_organization_config_from_yaml_impl,
        )

        result = await load_organization_config_from_yaml_impl("settings: {}", None)

        assert result["success"] is False
        assert "error" in result

    async def test_check_org_compliance_no_config(self, session):
        """Test compliance check when no org config is set."""
        from iam_validator.mcp.tools.config import check_org_compliance_impl

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }

        result = await check_org_compliance_impl(policy, session)

        assert result["has_org_config"] is False
        # Should use default validation settings

    async def test_check_org_compliance_with_config(self, session):
        """Test compliance check with a session config set."""
        from iam_validator.mcp.tools.config import (
            check_org_compliance_impl,
            set_organization_config_impl,
        )

        # Set a config that enables certain checks
        await set_organization_config_impl(
            {
                "settings": {"fail_on_severity": ["error", "critical"]},
            },
            session,
        )

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }

        result = await check_org_compliance_impl(policy, session)

        assert result["has_org_config"] is True
        # The result depends on what checks find issues

    async def test_check_org_compliance_no_session(self):
        """Hosted mode (session=None) behaves like no config set."""
        from iam_validator.mcp.tools.config import check_org_compliance_impl

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }

        result = await check_org_compliance_impl(policy, None)

        assert result["has_org_config"] is False

    async def test_validate_with_config_impl(self):
        """Test validating with inline config."""
        from iam_validator.mcp.tools.config import validate_with_config_impl

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["*"],
                    "Resource": "*",
                }
            ],
        }

        # Config that makes wildcard checks critical
        config = {
            "settings": {"fail_on_severity": ["critical"]},
            "full_wildcard": {"enabled": True, "severity": "critical"},
        }

        result = await validate_with_config_impl(policy, config)

        # Should have issues due to wildcard action/resource
        assert "issues" in result
        assert result["config_applied"] is not None

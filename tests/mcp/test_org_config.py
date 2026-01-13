"""Tests for session configuration management in MCP server.

This module tests the SessionConfigManager and the MCP tools for managing
session configurations. All validation is done by the IAM validator's
built-in checks - these tests verify config loading and session management.
"""

import pytest

from iam_validator.core.config.config_loader import ValidatorConfig
from iam_validator.mcp.session_config import (
    SessionConfigManager,
    merge_conditions,
)


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


class TestSessionConfigManager:
    """Tests for the SessionConfigManager class."""

    def setup_method(self):
        """Clear any existing config before each test."""
        SessionConfigManager.clear_config()

    def teardown_method(self):
        """Clean up after each test."""
        SessionConfigManager.clear_config()

    def test_set_and_get_config(self):
        """Test setting and getting configuration."""
        config = SessionConfigManager.set_config(
            {"settings": {"fail_on_severity": ["error"]}}, source="test"
        )

        retrieved = SessionConfigManager.get_config()
        assert retrieved is not None
        assert retrieved.settings.get("fail_on_severity") == ["error"]
        assert SessionConfigManager.get_config_source() == "test"

    def test_has_config(self):
        """Test has_config method."""
        assert not SessionConfigManager.has_config()

        SessionConfigManager.set_config({})

        assert SessionConfigManager.has_config()

    def test_clear_config(self):
        """Test clearing configuration."""
        SessionConfigManager.set_config({})
        assert SessionConfigManager.has_config()

        had_config = SessionConfigManager.clear_config()

        assert had_config is True
        assert not SessionConfigManager.has_config()
        assert SessionConfigManager.get_config() is None

    def test_clear_config_when_none_set(self):
        """Test clearing when no config is set."""
        had_config = SessionConfigManager.clear_config()

        assert had_config is False

    def test_load_from_yaml(self):
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
        config, warnings = SessionConfigManager.load_from_yaml(yaml_content)

        assert config.settings.get("fail_on_severity") == ["error", "critical"]
        assert config.get_check_config("wildcard_action")["enabled"] is True
        assert SessionConfigManager.get_config_source() == "yaml"

    def test_load_from_yaml_with_organization_key(self):
        """Test loading YAML with 'organization' wrapper key (legacy format)."""
        yaml_content = """
organization:
  fail_on_severity:
    - error
"""
        config, warnings = SessionConfigManager.load_from_yaml(yaml_content)

        assert config.settings.get("fail_on_severity") == ["error"]
        assert any("organization" in w.lower() for w in warnings)

    def test_load_from_yaml_invalid(self):
        """Test that invalid YAML raises an error."""
        yaml_content = "invalid: yaml: content:"

        with pytest.raises(ValueError, match="Invalid YAML"):
            SessionConfigManager.load_from_yaml(yaml_content)


class TestMergeConditions:
    """Tests for the merge_conditions utility function."""

    def test_merge_with_none_base(self):
        """Test merging when base conditions are None."""
        required = {"Bool": {"aws:SecureTransport": "true"}}

        result = merge_conditions(None, required)

        assert result == required

    def test_merge_with_empty_required(self):
        """Test merging when required conditions are empty."""
        base = {"StringEquals": {"s3:prefix": "data/"}}

        result = merge_conditions(base, {})

        assert result == base

    def test_merge_different_operators(self):
        """Test merging conditions with different operators."""
        base = {"StringEquals": {"s3:prefix": "data/"}}
        required = {"Bool": {"aws:SecureTransport": "true"}}

        result = merge_conditions(base, required)

        assert "StringEquals" in result
        assert "Bool" in result
        assert result["StringEquals"]["s3:prefix"] == "data/"
        assert result["Bool"]["aws:SecureTransport"] == "true"

    def test_merge_same_operator(self):
        """Test merging conditions with the same operator."""
        base = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
        required = {"Bool": {"aws:SecureTransport": "true"}}

        result = merge_conditions(base, required)

        assert "Bool" in result
        assert result["Bool"]["aws:MultiFactorAuthPresent"] == "true"
        assert result["Bool"]["aws:SecureTransport"] == "true"

    def test_required_overwrites_base_for_same_key(self):
        """Test that required conditions overwrite base for the same key."""
        base = {"Bool": {"aws:SecureTransport": "false"}}
        required = {"Bool": {"aws:SecureTransport": "true"}}

        result = merge_conditions(base, required)

        assert result["Bool"]["aws:SecureTransport"] == "true"


class TestOrgConfigToolImplementations:
    """Tests for the org config tool implementations.

    These tests verify the business logic of org config tools by calling
    the implementation functions directly.
    """

    def setup_method(self):
        """Clear any existing config before each test."""
        SessionConfigManager.clear_config()

    def teardown_method(self):
        """Clean up after each test."""
        SessionConfigManager.clear_config()

    @pytest.mark.asyncio
    async def test_set_organization_config(self):
        """Test the set_organization_config implementation."""
        from iam_validator.mcp.tools.org_config_tools import (
            set_organization_config_impl,
        )

        result = await set_organization_config_impl({
            "settings": {"fail_on_severity": ["error", "critical"]},
            "wildcard_action": {"enabled": True, "severity": "high"},
        })

        assert result["success"] is True
        assert "settings" in result["applied_config"]
        assert SessionConfigManager.has_config()

    @pytest.mark.asyncio
    async def test_get_organization_config_none_set(self):
        """Test get_organization_config when none is set."""
        from iam_validator.mcp.tools.org_config_tools import (
            get_organization_config_impl,
        )

        result = await get_organization_config_impl()

        assert result["has_config"] is False
        assert result["config"] is None
        assert result["source"] == "none"

    @pytest.mark.asyncio
    async def test_get_organization_config_with_config(self):
        """Test get_organization_config when config is set."""
        from iam_validator.mcp.tools.org_config_tools import (
            get_organization_config_impl,
            set_organization_config_impl,
        )

        await set_organization_config_impl({
            "settings": {"fail_on_severity": ["error"]},
        })
        result = await get_organization_config_impl()

        assert result["has_config"] is True
        assert "settings" in result["config"]
        assert result["source"] == "session"

    @pytest.mark.asyncio
    async def test_clear_organization_config(self):
        """Test clearing organization config."""
        from iam_validator.mcp.tools.org_config_tools import (
            clear_organization_config_impl,
            get_organization_config_impl,
            set_organization_config_impl,
        )

        await set_organization_config_impl({"settings": {}})
        result = await clear_organization_config_impl()

        assert result["status"] == "cleared"

        get_result = await get_organization_config_impl()
        assert get_result["has_config"] is False

    @pytest.mark.asyncio
    async def test_clear_organization_config_when_none(self):
        """Test clearing when no config is set."""
        from iam_validator.mcp.tools.org_config_tools import (
            clear_organization_config_impl,
        )

        result = await clear_organization_config_impl()

        assert result["status"] == "no_config_set"

    @pytest.mark.asyncio
    async def test_load_organization_config_from_yaml(self):
        """Test loading config from YAML."""
        from iam_validator.mcp.tools.org_config_tools import (
            load_organization_config_from_yaml_impl,
        )

        yaml_content = """
settings:
  fail_on_severity:
    - error
    - critical
"""
        result = await load_organization_config_from_yaml_impl(yaml_content)

        assert result["success"] is True
        assert "settings" in result["applied_config"]

    @pytest.mark.asyncio
    async def test_load_organization_config_from_yaml_invalid(self):
        """Test loading invalid YAML."""
        from iam_validator.mcp.tools.org_config_tools import (
            load_organization_config_from_yaml_impl,
        )

        result = await load_organization_config_from_yaml_impl("invalid: yaml: :")

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_check_org_compliance_no_config(self):
        """Test compliance check when no org config is set."""
        from iam_validator.mcp.tools.org_config_tools import check_org_compliance_impl

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

        result = await check_org_compliance_impl(policy)

        assert result["has_org_config"] is False
        # Should use default validation settings

    @pytest.mark.asyncio
    async def test_check_org_compliance_with_config(self):
        """Test compliance check with a session config set."""
        from iam_validator.mcp.tools.org_config_tools import (
            check_org_compliance_impl,
            set_organization_config_impl,
        )

        # Set a config that enables certain checks
        await set_organization_config_impl({
            "settings": {"fail_on_severity": ["error", "critical"]},
        })

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

        result = await check_org_compliance_impl(policy)

        assert result["has_org_config"] is True
        # The result depends on what checks find issues

    @pytest.mark.asyncio
    async def test_validate_with_config_impl(self):
        """Test validating with inline config."""
        from iam_validator.mcp.tools.org_config_tools import validate_with_config_impl

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

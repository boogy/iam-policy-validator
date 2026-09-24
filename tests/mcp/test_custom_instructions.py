"""Tests for custom-instructions handling: SessionState + startup resolution."""

import tempfile
from pathlib import Path

import pytest

from iam_validator.core.config.config_loader import ValidatorConfig
from iam_validator.mcp.context import SessionState, _resolve_startup_instructions
from iam_validator.mcp.settings import ServerSettings

# Check if fastmcp is available for tests that need it
try:
    import fastmcp  # noqa: F401

    HAS_FASTMCP = True
except ImportError:
    HAS_FASTMCP = False


class TestSessionStateInstructions:
    """Test suite for SessionState's custom-instructions methods."""

    @pytest.fixture
    def session(self):
        return SessionState()

    def test_set_and_get_instructions(self, session):
        """Should set and retrieve custom instructions."""
        instructions = "Always require MFA for sensitive actions"
        session.set_instructions(instructions, source="test")

        assert session.has_instructions()
        assert session.get_instructions() == instructions
        assert session.get_instructions_source() == "test"

    def test_clear_instructions(self, session):
        """Should clear instructions and return to default state."""
        session.set_instructions("Some instructions", source="test")
        assert session.has_instructions()

        result = session.clear_instructions()

        assert result is True
        assert not session.has_instructions()
        assert session.get_instructions() is None
        assert session.get_instructions_source() == "none"

    def test_clear_when_no_instructions(self, session):
        """Should return False when clearing without any instructions set."""
        result = session.clear_instructions()
        assert result is False

    def test_set_instructions_strips_whitespace(self, session):
        """Should strip whitespace from instructions."""
        instructions = "  \n  Some instructions  \n  "
        session.set_instructions(instructions, source="test")

        assert session.get_instructions() == "Some instructions"

    def test_set_empty_instructions_clears(self, session):
        """Should clear instructions when setting empty string."""
        session.set_instructions("Some instructions", source="test")
        session.set_instructions("   ", source="test")

        assert not session.has_instructions()
        assert session.get_instructions_source() == "none"

    def test_source_tracking(self, session):
        """Should track the source of instructions correctly."""
        session.set_instructions("API instructions", source="api")
        assert session.get_instructions_source() == "api"

        session.set_instructions("Config instructions", source="config")
        assert session.get_instructions_source() == "config"

        session.set_instructions("CLI instructions", source="cli")
        assert session.get_instructions_source() == "cli"


class TestResolveStartupInstructions:
    """Test suite for ``_resolve_startup_instructions`` (settings -> startup text).

    This is where file/env-sourced instructions are now resolved: ServerSettings
    itself reads IAM_VALIDATOR_MCP_INSTRUCTIONS / _INSTRUCTIONS_FILE from the
    environment (see test_settings.py), and this function turns the resolved
    settings into the text appended to BASE_INSTRUCTIONS at lifespan startup.
    """

    def test_inline_instructions_take_precedence(self):
        settings = ServerSettings(instructions="Inline text", instructions_file=None)
        config = ValidatorConfig({"custom_instructions": "Config text"})
        assert _resolve_startup_instructions(settings, config) == "Inline text"

    def test_loads_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("## Custom Rules\n- Rule 1\n- Rule 2")
            temp_path = f.name

        try:
            settings = ServerSettings(instructions_file=temp_path)
            config = ValidatorConfig({})
            result = _resolve_startup_instructions(settings, config)
            assert result is not None
            assert "Custom Rules" in result
        finally:
            Path(temp_path).unlink()

    def test_returns_none_when_neither_set(self):
        settings = ServerSettings()
        config = ValidatorConfig({})
        assert _resolve_startup_instructions(settings, config) is None

    def test_falls_back_to_config_custom_instructions(self):
        settings = ServerSettings()
        config = ValidatorConfig({"custom_instructions": "From config"})
        assert _resolve_startup_instructions(settings, config) == "From config"


@pytest.mark.skipif(not HAS_FASTMCP, reason="MCP tests require 'pip install iam-policy-validator[mcp]'")
class TestGetInstructions:
    """Test suite for the module-level ``get_instructions`` function."""

    def test_returns_base_when_no_custom(self):
        from iam_validator.mcp.instructions import BASE_INSTRUCTIONS, get_instructions

        result = get_instructions()
        assert result == BASE_INSTRUCTIONS

    def test_appends_custom_instructions(self):
        from iam_validator.mcp.instructions import BASE_INSTRUCTIONS, get_instructions

        custom = "Always require MFA"
        result = get_instructions(custom)

        assert BASE_INSTRUCTIONS in result
        assert "## ORGANIZATION-SPECIFIC INSTRUCTIONS" in result
        assert custom in result


class TestSessionConfigCustomInstructions:
    """Test custom_instructions key in YAML config, applied to a SessionState."""

    @pytest.fixture
    def session(self):
        return SessionState()

    def test_load_custom_instructions_from_yaml(self, session):
        """Should extract custom_instructions from YAML config."""
        yaml_content = """
settings:
  fail_on_severity: [error, critical]

custom_instructions: |
  ## Organization Rules
  - Always add MFA condition
  - Restrict to our org ID

wildcard_action:
  enabled: true
"""

        config, warnings = session.load_config_from_yaml(yaml_content)

        # Custom instructions should be loaded onto the same session
        assert session.has_instructions()
        assert "Organization Rules" in session.get_instructions()
        assert session.get_instructions_source() == "config"

        # Warning should be generated
        assert any("custom instructions" in w.lower() for w in warnings)

        # Config should not include custom_instructions key
        assert "custom_instructions" not in config.checks_config

    def test_empty_custom_instructions_ignored(self, session):
        """Should ignore empty custom_instructions in YAML."""
        yaml_content = """
settings:
  fail_on_severity: [error]

custom_instructions: ""
"""

        config, warnings = session.load_config_from_yaml(yaml_content)

        assert not session.has_instructions()

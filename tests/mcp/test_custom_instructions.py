"""Tests for CustomInstructionsManager."""

import os
import tempfile
from pathlib import Path

import pytest

from iam_validator.mcp.session_config import CustomInstructionsManager

# Check if fastmcp is available for tests that need it
try:
    import fastmcp
    HAS_FASTMCP = True
except ImportError:
    HAS_FASTMCP = False


class TestCustomInstructionsManager:
    """Test suite for CustomInstructionsManager."""

    def setup_method(self):
        """Clear instructions before each test."""
        CustomInstructionsManager.clear_instructions()

    def teardown_method(self):
        """Clear instructions after each test."""
        CustomInstructionsManager.clear_instructions()

    def test_set_and_get_instructions(self):
        """Should set and retrieve custom instructions."""
        instructions = "Always require MFA for sensitive actions"
        CustomInstructionsManager.set_instructions(instructions, source="test")

        assert CustomInstructionsManager.has_instructions()
        assert CustomInstructionsManager.get_instructions() == instructions
        assert CustomInstructionsManager.get_source() == "test"

    def test_clear_instructions(self):
        """Should clear instructions and return to default state."""
        CustomInstructionsManager.set_instructions("Some instructions", source="test")
        assert CustomInstructionsManager.has_instructions()

        result = CustomInstructionsManager.clear_instructions()

        assert result is True
        assert not CustomInstructionsManager.has_instructions()
        assert CustomInstructionsManager.get_instructions() is None
        assert CustomInstructionsManager.get_source() == "none"

    def test_clear_when_no_instructions(self):
        """Should return False when clearing without any instructions set."""
        result = CustomInstructionsManager.clear_instructions()
        assert result is False

    def test_set_instructions_strips_whitespace(self):
        """Should strip whitespace from instructions."""
        instructions = "  \n  Some instructions  \n  "
        CustomInstructionsManager.set_instructions(instructions, source="test")

        assert CustomInstructionsManager.get_instructions() == "Some instructions"

    def test_set_empty_instructions_clears(self):
        """Should clear instructions when setting empty string."""
        CustomInstructionsManager.set_instructions("Some instructions", source="test")
        CustomInstructionsManager.set_instructions("   ", source="test")

        assert not CustomInstructionsManager.has_instructions()
        assert CustomInstructionsManager.get_source() == "none"

    def test_load_from_file(self):
        """Should load instructions from a file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("## Custom Rules\n- Rule 1\n- Rule 2")
            temp_path = f.name

        try:
            CustomInstructionsManager.load_from_file(temp_path)

            assert CustomInstructionsManager.has_instructions()
            assert "Custom Rules" in CustomInstructionsManager.get_instructions()
            assert CustomInstructionsManager.get_source() == "file"
        finally:
            Path(temp_path).unlink()

    def test_load_from_nonexistent_file_raises(self):
        """Should raise FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            CustomInstructionsManager.load_from_file("/nonexistent/path.md")

    def test_load_from_env(self, monkeypatch):
        """Should load instructions from environment variable."""
        monkeypatch.setenv("IAM_VALIDATOR_MCP_INSTRUCTIONS", "Env instructions")

        result = CustomInstructionsManager.load_from_env()

        assert result is True
        assert CustomInstructionsManager.get_instructions() == "Env instructions"
        assert CustomInstructionsManager.get_source() == "env"

    def test_load_from_env_when_not_set(self, monkeypatch):
        """Should return False when env var is not set."""
        monkeypatch.delenv("IAM_VALIDATOR_MCP_INSTRUCTIONS", raising=False)

        result = CustomInstructionsManager.load_from_env()

        assert result is False
        assert not CustomInstructionsManager.has_instructions()

    def test_source_tracking(self):
        """Should track the source of instructions correctly."""
        # API source
        CustomInstructionsManager.set_instructions("API instructions", source="api")
        assert CustomInstructionsManager.get_source() == "api"

        # Config source
        CustomInstructionsManager.set_instructions("Config instructions", source="config")
        assert CustomInstructionsManager.get_source() == "config"

        # CLI source
        CustomInstructionsManager.set_instructions("CLI instructions", source="cli")
        assert CustomInstructionsManager.get_source() == "cli"


@pytest.mark.skipif(not HAS_FASTMCP, reason="MCP tests require 'pip install iam-policy-validator[mcp]'")
class TestGetInstructions:
    """Test suite for get_instructions function."""

    def setup_method(self):
        """Clear instructions before each test."""
        CustomInstructionsManager.clear_instructions()

    def teardown_method(self):
        """Clear instructions after each test."""
        CustomInstructionsManager.clear_instructions()

    def test_returns_base_when_no_custom(self):
        """Should return base instructions when no custom instructions set."""
        from iam_validator.mcp.server import BASE_INSTRUCTIONS, get_instructions

        result = get_instructions()
        assert result == BASE_INSTRUCTIONS

    def test_appends_custom_instructions(self):
        """Should append custom instructions with section header."""
        from iam_validator.mcp.server import BASE_INSTRUCTIONS, get_instructions

        custom = "Always require MFA"
        CustomInstructionsManager.set_instructions(custom, source="test")

        result = get_instructions()

        assert BASE_INSTRUCTIONS in result
        assert "## ORGANIZATION-SPECIFIC INSTRUCTIONS" in result
        assert custom in result


class TestSessionConfigCustomInstructions:
    """Test custom_instructions key in YAML config."""

    def setup_method(self):
        """Clear state before each test."""
        CustomInstructionsManager.clear_instructions()
        from iam_validator.mcp.session_config import SessionConfigManager

        SessionConfigManager.clear_config()

    def teardown_method(self):
        """Clear state after each test."""
        CustomInstructionsManager.clear_instructions()
        from iam_validator.mcp.session_config import SessionConfigManager

        SessionConfigManager.clear_config()

    def test_load_custom_instructions_from_yaml(self):
        """Should extract custom_instructions from YAML config."""
        from iam_validator.mcp.session_config import SessionConfigManager

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

        config, warnings = SessionConfigManager.load_from_yaml(yaml_content)

        # Custom instructions should be loaded
        assert CustomInstructionsManager.has_instructions()
        assert "Organization Rules" in CustomInstructionsManager.get_instructions()
        assert CustomInstructionsManager.get_source() == "config"

        # Warning should be generated
        assert any("custom instructions" in w.lower() for w in warnings)

        # Config should not include custom_instructions key
        assert "custom_instructions" not in config.checks_config

    def test_empty_custom_instructions_ignored(self):
        """Should ignore empty custom_instructions in YAML."""
        from iam_validator.mcp.session_config import SessionConfigManager

        yaml_content = """
settings:
  fail_on_severity: [error]

custom_instructions: ""
"""

        config, warnings = SessionConfigManager.load_from_yaml(yaml_content)

        assert not CustomInstructionsManager.has_instructions()

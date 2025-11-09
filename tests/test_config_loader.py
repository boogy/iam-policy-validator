"""Unit tests for Config Loader module."""

import tempfile
from pathlib import Path

import pytest
import yaml

from iam_validator.core.check_registry import CheckRegistry, PolicyCheck
from iam_validator.core.config.config_loader import (
    ConfigLoader,
    ValidatorConfig,
    load_validator_config,
)


class MockCheckForConfig(PolicyCheck):
    """Mock check for config testing."""

    @property
    def check_id(self) -> str:
        return "mock_check"

    @property
    def description(self) -> str:
        return "Mock check"

    async def execute(self, statement, statement_idx, fetcher, config):
        return []


class TestValidatorConfig:
    """Test the ValidatorConfig class."""

    def test_empty_initialization(self):
        """Test ValidatorConfig with no config dict and no defaults."""
        config = ValidatorConfig(use_defaults=False)

        assert config.config_dict == {}
        assert config.checks_config == {}
        assert config.custom_checks == []
        assert config.custom_checks_dir is None
        assert config.settings == {}

    def test_initialization_with_config_dict(self):
        """Test ValidatorConfig with a config dictionary and no defaults."""
        config_dict = {
            "checks": {
                "action_validation": {"enabled": True, "severity": "error"},
                "condition_validation": {"enabled": False},
            },
            "custom_checks": [{"module": "my_module.MyCheck", "enabled": True}],
            "custom_checks_dir": "/path/to/checks",
            "settings": {"parallel_execution": True, "cache_ttl": 3600},
        }

        config = ValidatorConfig(config_dict, use_defaults=False)

        assert config.checks_config == config_dict["checks"]
        assert config.custom_checks == config_dict["custom_checks"]
        assert config.custom_checks_dir == "/path/to/checks"
        assert config.settings == {"parallel_execution": True, "cache_ttl": 3600}

    def test_get_check_config(self):
        """Test getting configuration for a specific check."""
        config_dict = {"checks": {"action_validation": {"enabled": True, "severity": "error"}}}
        config = ValidatorConfig(config_dict)

        check_config = config.get_check_config("action_validation")
        assert check_config == {"enabled": True, "severity": "error"}

    def test_get_check_config_nonexistent(self):
        """Test getting config for non-existent check returns empty dict."""
        config = ValidatorConfig(use_defaults=False)
        check_config = config.get_check_config("nonexistent_check")
        assert check_config == {}

    def test_is_check_enabled_default_true(self):
        """Test that checks are enabled by default."""
        config = ValidatorConfig()
        assert config.is_check_enabled("any_check") is True

    def test_is_check_enabled_explicitly_set(self):
        """Test checking if a check is explicitly enabled/disabled."""
        config_dict = {
            "checks": {
                "enabled_check": {"enabled": True},
                "disabled_check": {"enabled": False},
            }
        }
        config = ValidatorConfig(config_dict)

        assert config.is_check_enabled("enabled_check") is True
        assert config.is_check_enabled("disabled_check") is False

    def test_get_check_severity(self):
        """Test getting severity override for a check."""
        config_dict = {"checks": {"my_check": {"enabled": True, "severity": "error"}}}
        config = ValidatorConfig(config_dict)

        severity = config.get_check_severity("my_check")
        assert severity == "error"

    def test_get_check_severity_not_set(self):
        """Test getting severity when not set returns None."""
        config = ValidatorConfig(use_defaults=False)
        severity = config.get_check_severity("any_check")
        assert severity is None

    def test_get_setting(self):
        """Test getting a global setting."""
        config_dict = {"settings": {"parallel_execution": True, "cache_ttl": 3600}}
        config = ValidatorConfig(config_dict)

        assert config.get_setting("parallel_execution") is True
        assert config.get_setting("cache_ttl") == 3600

    def test_get_setting_with_default(self):
        """Test getting a setting with default value."""
        config = ValidatorConfig(use_defaults=False)

        assert config.get_setting("nonexistent", default="default_value") == "default_value"
        assert config.get_setting("nonexistent") is None


class TestConfigLoader:
    """Test the ConfigLoader class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_default_config_names(self):
        """Test that default config names are defined."""
        assert len(ConfigLoader.DEFAULT_CONFIG_NAMES) > 0
        assert "iam-validator.yaml" in ConfigLoader.DEFAULT_CONFIG_NAMES
        assert "iam-validator.yml" in ConfigLoader.DEFAULT_CONFIG_NAMES

    def test_find_config_file_explicit_path(self, temp_dir):
        """Test finding config file with explicit path."""
        config_path = temp_dir / "my-config.yaml"
        config_path.write_text("checks: {}")

        found = ConfigLoader.find_config_file(explicit_path=str(config_path))
        assert found == config_path

    def test_find_config_file_explicit_path_not_found(self):
        """Test that explicit path not found raises error."""
        with pytest.raises(FileNotFoundError):
            ConfigLoader.find_config_file(explicit_path="/nonexistent/config.yaml")

    def test_find_config_file_in_current_directory(self, temp_dir):
        """Test finding config file in current directory."""
        config_path = temp_dir / "iam-validator.yaml"
        config_path.write_text("checks: {}")

        found = ConfigLoader.find_config_file(search_path=temp_dir)
        assert found == config_path

    def test_find_config_file_in_parent_directory(self, temp_dir):
        """Test finding config file in parent directory."""
        config_path = temp_dir / "iam-validator.yaml"
        config_path.write_text("checks: {}")

        # Create subdirectory and search from there
        sub_dir = temp_dir / "subdir"
        sub_dir.mkdir()

        found = ConfigLoader.find_config_file(search_path=sub_dir)
        assert found == config_path

    def test_find_config_file_not_found(self, temp_dir):
        """Test that None is returned when config not found."""
        found = ConfigLoader.find_config_file(search_path=temp_dir)
        assert found is None

    def test_find_config_file_prefers_visible_over_hidden(self, temp_dir):
        """Test that visible config files are preferred over hidden ones."""
        # Create both visible and hidden config files
        visible = temp_dir / "iam-validator.yaml"
        hidden = temp_dir / ".iam-validator.yaml"

        visible.write_text("checks: {visible: true}")
        hidden.write_text("checks: {hidden: true}")

        found = ConfigLoader.find_config_file(search_path=temp_dir)
        assert found == visible

    def test_load_yaml_valid(self, temp_dir):
        """Test loading a valid YAML file."""
        config_path = temp_dir / "config.yaml"
        config_data = {
            "checks": {"action_validation": {"enabled": True}},
            "settings": {"parallel": True},
        }
        config_path.write_text(yaml.dump(config_data))

        loaded = ConfigLoader.load_yaml(config_path)
        assert loaded == config_data

    def test_load_yaml_invalid(self, temp_dir):
        """Test loading an invalid YAML file raises error."""
        config_path = temp_dir / "invalid.yaml"
        config_path.write_text("invalid: yaml: [unclosed")

        with pytest.raises(ValueError, match="Invalid YAML"):
            ConfigLoader.load_yaml(config_path)

    def test_load_yaml_empty_file(self, temp_dir):
        """Test loading an empty YAML file returns empty dict."""
        config_path = temp_dir / "empty.yaml"
        config_path.write_text("")

        loaded = ConfigLoader.load_yaml(config_path)
        assert loaded == {}

    def test_load_config_success(self, temp_dir):
        """Test successfully loading a config file."""
        config_path = temp_dir / "iam-validator.yaml"
        config_data = {"checks": {"action_validation": {"enabled": True, "severity": "error"}}}
        config_path.write_text(yaml.dump(config_data))

        config = ConfigLoader.load_config(search_path=temp_dir)

        assert isinstance(config, ValidatorConfig)
        assert config.is_check_enabled("action_validation") is True
        assert config.get_check_severity("action_validation") == "error"

    def test_load_config_not_found_allow_missing(self, temp_dir):
        """Test loading config when file not found with allow_missing=True.

        When allow_missing=True and no config file is found, the system should
        return a ValidatorConfig with default configuration loaded.
        """
        config = ConfigLoader.load_config(search_path=temp_dir, allow_missing=True)

        assert isinstance(config, ValidatorConfig)
        # Should have default configuration loaded
        assert config.config_dict != {}
        assert "settings" in config.config_dict
        # Verify some key default settings exist
        assert config.config_dict["settings"]["fail_fast"] is False
        assert "action_validation" in config.config_dict

    def test_load_config_not_found_disallow_missing(self, temp_dir):
        """Test loading config when file not found with allow_missing=False."""
        with pytest.raises(FileNotFoundError, match="No configuration file found"):
            ConfigLoader.load_config(search_path=temp_dir, allow_missing=False)

    def test_apply_config_to_registry(self):
        """Test applying configuration to a check registry."""
        registry = CheckRegistry()
        check = MockCheckForConfig()
        registry.register(check)

        config_dict = {"checks": {"mock_check": {"enabled": False, "severity": "error"}}}
        config = ValidatorConfig(config_dict)

        ConfigLoader.apply_config_to_registry(config, registry)

        assert registry.is_enabled("mock_check") is False
        check_config = registry.get_config("mock_check")
        assert check_config.severity == "error"

    def test_apply_config_preserves_defaults(self):
        """Test that applying config preserves defaults for unspecified checks."""
        registry = CheckRegistry()
        check = MockCheckForConfig()
        registry.register(check)

        # Empty config
        config = ValidatorConfig({})
        ConfigLoader.apply_config_to_registry(config, registry)

        # Check should still be enabled (default)
        assert registry.is_enabled("mock_check") is True

    def test_load_custom_checks_none(self):
        """Test loading custom checks when none are configured."""
        config = ValidatorConfig(use_defaults=False)
        registry = CheckRegistry()

        loaded = ConfigLoader.load_custom_checks(config, registry)

        assert loaded == []

    def test_load_custom_checks_invalid_module_path(self):
        """Test loading custom checks with invalid module path."""
        config_dict = {"custom_checks": [{"module": "invalid_format", "enabled": True}]}
        config = ValidatorConfig(config_dict)
        registry = CheckRegistry()

        # Should not raise, but log warning
        loaded = ConfigLoader.load_custom_checks(config, registry)
        assert loaded == []

    def test_load_custom_checks_module_not_found(self):
        """Test loading custom checks when module doesn't exist."""
        config_dict = {"custom_checks": [{"module": "nonexistent.module.Check", "enabled": True}]}
        config = ValidatorConfig(config_dict)
        registry = CheckRegistry()

        # Should not raise, but log warning
        loaded = ConfigLoader.load_custom_checks(config, registry)
        assert loaded == []

    def test_load_custom_checks_disabled(self):
        """Test that disabled custom checks are not loaded."""
        config_dict = {"custom_checks": [{"module": "some.module.Check", "enabled": False}]}
        config = ValidatorConfig(config_dict)
        registry = CheckRegistry()

        loaded = ConfigLoader.load_custom_checks(config, registry)
        assert loaded == []

    def test_discover_checks_in_directory_not_found(self, temp_dir):
        """Test discovering checks in non-existent directory."""
        nonexistent = temp_dir / "nonexistent"
        registry = CheckRegistry()

        loaded = ConfigLoader.discover_checks_in_directory(nonexistent, registry)
        assert loaded == []

    def test_discover_checks_in_directory_is_file(self, temp_dir):
        """Test discovering checks when path is a file."""
        file_path = temp_dir / "file.txt"
        file_path.write_text("not a directory")
        registry = CheckRegistry()

        loaded = ConfigLoader.discover_checks_in_directory(file_path, registry)
        assert loaded == []

    def test_discover_checks_in_directory_empty(self, temp_dir):
        """Test discovering checks in empty directory."""
        registry = CheckRegistry()
        loaded = ConfigLoader.discover_checks_in_directory(temp_dir, registry)
        assert loaded == []

    def test_discover_checks_skips_private_files(self, temp_dir):
        """Test that files starting with _ or . are skipped."""
        (temp_dir / "_private.py").write_text("# Private check")
        (temp_dir / ".hidden.py").write_text("# Hidden check")
        registry = CheckRegistry()

        loaded = ConfigLoader.discover_checks_in_directory(temp_dir, registry)
        assert loaded == []

    def test_discover_checks_skips_non_python_files(self, temp_dir):
        """Test that non-Python files are skipped."""
        (temp_dir / "readme.txt").write_text("Not a Python file")
        (temp_dir / "config.yaml").write_text("checks: {}")
        registry = CheckRegistry()

        loaded = ConfigLoader.discover_checks_in_directory(temp_dir, registry)
        assert loaded == []

    def test_discover_checks_loads_valid_check(self, temp_dir):
        """Test discovering and loading a valid custom check."""
        check_file = temp_dir / "custom_check.py"
        check_code = """
from iam_validator.core.check_registry import PolicyCheck

class CustomSecurityCheck(PolicyCheck):
    @property
    def check_id(self) -> str:
        return "custom_security_check"

    @property
    def description(self) -> str:
        return "A custom security check"

    async def execute(self, statement, statement_idx, fetcher, config):
        return []
"""
        check_file.write_text(check_code)
        registry = CheckRegistry()

        loaded = ConfigLoader.discover_checks_in_directory(temp_dir, registry)

        assert len(loaded) == 1
        assert "custom_security_check" in loaded
        assert registry.get_check("custom_security_check") is not None
        # Auto-discovered checks should be disabled by default
        assert registry.is_enabled("custom_security_check") is False

    def test_discover_checks_multiple_files(self, temp_dir):
        """Test discovering checks from multiple files."""
        check1 = temp_dir / "check1.py"
        check1_code = """
from iam_validator.core.check_registry import PolicyCheck

class Check1(PolicyCheck):
    @property
    def check_id(self) -> str:
        return "check_1"

    @property
    def description(self) -> str:
        return "First check"

    async def execute(self, statement, statement_idx, fetcher, config):
        return []
"""
        check1.write_text(check1_code)

        check2 = temp_dir / "check2.py"
        check2_code = """
from iam_validator.core.check_registry import PolicyCheck

class Check2(PolicyCheck):
    @property
    def check_id(self) -> str:
        return "check_2"

    @property
    def description(self) -> str:
        return "Second check"

    async def execute(self, statement, statement_idx, fetcher, config):
        return []
"""
        check2.write_text(check2_code)

        registry = CheckRegistry()
        loaded = ConfigLoader.discover_checks_in_directory(temp_dir, registry)

        assert len(loaded) == 2
        assert "check_1" in loaded
        assert "check_2" in loaded


class TestLoadValidatorConfig:
    """Test the load_validator_config convenience function."""

    def test_load_validator_config_allow_missing(self):
        """Test loading with allow_missing=True."""
        config = load_validator_config(config_path=None, allow_missing=True)

        assert isinstance(config, ValidatorConfig)

    def test_load_validator_config_explicit_path(self, tmp_path):
        """Test loading with explicit config path."""
        config_path = tmp_path / "config.yaml"
        config_data = {"checks": {"test": {"enabled": True}}}
        config_path.write_text(yaml.dump(config_data))

        config = load_validator_config(config_path=str(config_path))

        assert isinstance(config, ValidatorConfig)
        assert config.is_check_enabled("test") is True

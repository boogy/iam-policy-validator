"""Session configuration management for MCP server.

This module provides session-scoped configuration management using the core
ValidatorConfig system. It stores the validator configuration for the MCP
session lifetime, enabling consistent validation across tool calls.

Example usage:
    # Set session config from a YAML file
    SessionConfigManager.load_from_file("/path/to/config.yaml")

    # Or set from YAML content
    SessionConfigManager.load_from_yaml(yaml_content)

    # Or set from a dictionary
    SessionConfigManager.set_config({"settings": {"fail_on_severity": ["error", "critical"]}})

    # Get the current config
    config = SessionConfigManager.get_config()
    if config:
        # Use config for validation
        check_config = config.get_check_config("wildcard_action")
"""

from typing import Any

import yaml

from iam_validator.core.config.config_loader import ValidatorConfig


class SessionConfigManager:
    """Manages session-scoped configuration for MCP tools.

    This class provides session-scoped storage for ValidatorConfig.
    The config is stored as a class variable and persists for the lifetime
    of the MCP session.

    The configuration uses the same schema as the CLI validator, so you can
    use the same YAML configuration files for both CLI and MCP usage.
    """

    _session_config: ValidatorConfig | None = None
    _config_source: str = "none"

    @classmethod
    def set_config(cls, config_dict: dict[str, Any], source: str = "session") -> ValidatorConfig:
        """Set the session configuration from a dictionary.

        Args:
            config_dict: Configuration dictionary (same format as YAML config files)
            source: Source identifier ("session", "yaml", "file")

        Returns:
            The created ValidatorConfig instance
        """
        cls._session_config = ValidatorConfig(config_dict, use_defaults=True)
        cls._config_source = source
        return cls._session_config

    @classmethod
    def get_config(cls) -> ValidatorConfig | None:
        """Get the current session configuration.

        Returns:
            Current ValidatorConfig, or None if not set
        """
        return cls._session_config

    @classmethod
    def get_config_source(cls) -> str:
        """Get the source of the current configuration.

        Returns:
            Source identifier: "session", "yaml", "file", or "none"
        """
        return cls._config_source

    @classmethod
    def clear_config(cls) -> bool:
        """Clear the session configuration.

        Returns:
            True if config was cleared, False if no config was set
        """
        had_config = cls._session_config is not None
        cls._session_config = None
        cls._config_source = "none"
        return had_config

    @classmethod
    def has_config(cls) -> bool:
        """Check if a session configuration is set.

        Returns:
            True if config is set, False otherwise
        """
        return cls._session_config is not None

    @classmethod
    def load_from_yaml(cls, yaml_content: str) -> tuple[ValidatorConfig, list[str]]:
        """Load session configuration from YAML content.

        Args:
            yaml_content: YAML string containing configuration

        Returns:
            Tuple of (ValidatorConfig, list of warnings)

        Raises:
            ValueError: If YAML parsing or validation fails
        """
        warnings: list[str] = []

        try:
            config_dict = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}") from e

        if not isinstance(config_dict, dict):
            raise ValueError("YAML content must be a dictionary")

        # Support legacy "organization" key for backwards compatibility
        if "organization" in config_dict:
            org_config = config_dict.pop("organization")
            # Merge organization settings into settings
            if "settings" not in config_dict:
                config_dict["settings"] = {}
            config_dict["settings"].update(org_config)
            warnings.append("Migrated 'organization' key to 'settings'")

        config = cls.set_config(config_dict, source="yaml")
        return config, warnings

    @classmethod
    def load_from_file(cls, file_path: str) -> tuple[ValidatorConfig, list[str]]:
        """Load session configuration from a YAML file.

        Args:
            file_path: Path to YAML configuration file

        Returns:
            Tuple of (ValidatorConfig, list of warnings)

        Raises:
            ValueError: If file reading or parsing fails
            FileNotFoundError: If file doesn't exist
        """
        from pathlib import Path

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        yaml_content = path.read_text()
        config, warnings = cls.load_from_yaml(yaml_content)
        cls._config_source = "file"
        return config, warnings


def merge_conditions(
    base_conditions: dict[str, Any] | None,
    required_conditions: dict[str, Any],
) -> dict[str, Any]:
    """Merge required conditions into base conditions.

    This performs a deep merge of condition blocks, combining operators
    and their nested conditions appropriately.

    Args:
        base_conditions: Existing conditions (may be None)
        required_conditions: Required conditions to merge in

    Returns:
        Merged conditions dictionary
    """
    if not required_conditions:
        return base_conditions or {}

    if not base_conditions:
        return required_conditions.copy()

    result = base_conditions.copy()

    for operator, conditions in required_conditions.items():
        if operator in result:
            # Merge conditions under the same operator
            if isinstance(result[operator], dict) and isinstance(conditions, dict):
                result[operator] = {**result[operator], **conditions}
            else:
                # Can't merge non-dict values, required takes precedence
                result[operator] = conditions
        else:
            result[operator] = conditions

    return result


__all__ = [
    "SessionConfigManager",
    "merge_conditions",
]

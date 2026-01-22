"""
Configuration loader for IAM Policy Validator.

Loads and parses configuration from YAML files, environment variables,
and command-line arguments.
"""

import importlib
import importlib.util
import inspect
import logging
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from iam_validator.core.check_registry import CheckConfig, CheckRegistry, PolicyCheck
from iam_validator.core.config.defaults import get_default_config
from iam_validator.core.constants import DEFAULT_CONFIG_FILENAMES

logger = logging.getLogger(__name__)

# Valid severity levels for validation
SEVERITY_LEVELS = frozenset(["error", "warning", "info", "critical", "high", "medium", "low"])

# Known built-in check IDs for validation warnings
KNOWN_CHECK_IDS = frozenset(
    [
        "action_validation",
        "condition_key_validation",
        "condition_type_mismatch",
        "resource_validation",
        "sid_uniqueness",
        "policy_size",
        "policy_structure",
        "set_operator_validation",
        "mfa_condition_check",
        "principal_validation",
        "policy_type_validation",
        "action_resource_matching",
        "trust_policy_validation",
        "wildcard_action",
        "wildcard_resource",
        "full_wildcard",
        "service_wildcard",
        "sensitive_action",
        "action_condition_enforcement",
        "not_action_not_resource",
    ]
)


# =============================================================================
# Pydantic Configuration Schemas
# =============================================================================


class IgnorePatternSchema(BaseModel):
    """Schema for ignore patterns within check configurations."""

    model_config = ConfigDict(extra="forbid")

    # At least one of these should be specified
    file: str | None = None
    action: str | None = None
    resource: str | None = None
    sid: str | None = None


class CheckConfigSchema(BaseModel):
    """Flexible check config - validates core fields, allows extras for custom options.

    This schema validates common check configuration fields while allowing
    arbitrary additional options that specific checks may require (e.g.,
    allowed_wildcards, categories, requirements).
    """

    model_config = ConfigDict(extra="allow")  # Allow arbitrary check-specific options

    enabled: bool = True
    severity: str | None = None
    description: str | None = None
    ignore_patterns: list[dict[str, Any]] = []
    hide_severities: list[str] | None = None  # Per-check severity filtering

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str | None) -> str | None:
        if v is not None and v not in SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity: {v}. Must be one of: {sorted(SEVERITY_LEVELS)}")
        return v

    @field_validator("hide_severities")
    @classmethod
    def validate_hide_severities(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            for severity in v:
                if severity not in SEVERITY_LEVELS:
                    raise ValueError(
                        f"Invalid severity in hide_severities: {severity}. "
                        f"Must be one of: {sorted(SEVERITY_LEVELS)}"
                    )
        return v


class IgnoreSettingsSchema(BaseModel):
    """Schema for ignore settings."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    allowed_users: list[str] = []
    post_denial_feedback: bool = False


class DocumentationSettingsSchema(BaseModel):
    """Schema for documentation settings."""

    model_config = ConfigDict(extra="forbid")

    base_url: str | None = None
    include_aws_docs: bool = True


class SettingsSchema(BaseModel):
    """Schema for global settings."""

    model_config = ConfigDict(extra="allow")  # Allow additional settings

    fail_fast: bool = False
    parallel: bool = True
    max_workers: int | None = None
    fail_on_severity: list[str] = ["error", "critical"]
    severity_labels: dict[str, str | list[str]] = {}
    ignore_settings: IgnoreSettingsSchema = IgnoreSettingsSchema()
    documentation: DocumentationSettingsSchema = DocumentationSettingsSchema()
    hide_severities: list[str] | None = None  # Global severity filtering

    @field_validator("fail_on_severity")
    @classmethod
    def validate_fail_on_severity(cls, v: list[str]) -> list[str]:
        for severity in v:
            if severity not in SEVERITY_LEVELS:
                raise ValueError(
                    f"Invalid severity in fail_on_severity: {severity}. "
                    f"Must be one of: {sorted(SEVERITY_LEVELS)}"
                )
        return v

    @field_validator("hide_severities")
    @classmethod
    def validate_hide_severities(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            for severity in v:
                if severity not in SEVERITY_LEVELS:
                    raise ValueError(
                        f"Invalid severity in hide_severities: {severity}. "
                        f"Must be one of: {sorted(SEVERITY_LEVELS)}"
                    )
        return v


class CustomCheckSchema(BaseModel):
    """Schema for custom check definitions."""

    model_config = ConfigDict(extra="allow")

    module: str
    enabled: bool = True
    severity: str | None = None
    description: str | None = None
    config: dict[str, Any] = {}

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str | None) -> str | None:
        if v is not None and v not in SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity: {v}. Must be one of: {sorted(SEVERITY_LEVELS)}")
        return v


class ConfigSchema(BaseModel):
    """Top-level configuration schema.

    Validates the overall structure while allowing flexibility for check configs.
    """

    model_config = ConfigDict(extra="allow")  # Allow check configs at top level

    settings: SettingsSchema = SettingsSchema()
    custom_checks: list[CustomCheckSchema] = []
    custom_checks_dir: str | None = None

    @model_validator(mode="after")
    def warn_unknown_checks(self) -> "ConfigSchema":
        """Warn about unknown check IDs (potential typos)."""
        # Get all extra fields that might be check configs
        if not self.model_extra:
            return self

        for key, value in self.model_extra.items():
            if isinstance(value, dict):
                # This looks like a check config
                check_id = key.removesuffix("_check") if key.endswith("_check") else key
                if check_id not in KNOWN_CHECK_IDS:
                    logger.warning(
                        f"Unknown check ID '{check_id}' in configuration. "
                        f"This may be a custom check or a typo."
                    )
        return self


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(
            "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        )


def validate_config(config_dict: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate configuration dictionary against schema.

    Args:
        config_dict: Raw configuration dictionary

    Returns:
        Tuple of (is_valid, list of error messages)
    """
    errors: list[str] = []

    try:
        ConfigSchema.model_validate(config_dict)
    except Exception as e:
        # Parse Pydantic validation errors
        if hasattr(e, "errors"):
            for error in e.errors():  # type: ignore
                loc = ".".join(str(x) for x in error.get("loc", []))
                msg = error.get("msg", str(e))
                errors.append(f"{loc}: {msg}")
        else:
            errors.append(str(e))

    return len(errors) == 0, errors


def deep_merge(base: dict, override: dict) -> dict:
    """
    Deep merge two dictionaries, with override taking precedence.

    Args:
        base: Base dictionary with default values
        override: Dictionary with override values

    Returns:
        Merged dictionary where override values take precedence
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class ValidatorConfig:
    """Main configuration object for the validator."""

    def __init__(self, config_dict: dict[str, Any] | None = None, use_defaults: bool = True):
        """
        Initialize configuration from a dictionary.

        Args:
            config_dict: Dictionary loaded from YAML config file.
                        If None, either uses default configuration (if use_defaults=True)
                        or creates an empty configuration (if use_defaults=False).
                        If provided, merges with defaults (user config takes precedence).
            use_defaults: Whether to load default configuration. Set to False for testing
                         or when you want an empty configuration.
        """
        # Start with default configuration if requested
        if use_defaults:
            default_config = get_default_config()
            # Merge user config with defaults if provided
            if config_dict:
                self.config_dict = deep_merge(default_config, config_dict)
            else:
                self.config_dict = default_config
        else:
            # No defaults - use provided config or empty dict
            self.config_dict = config_dict or {}

        # Support both nested and flat structure
        # 1. Old nested structure: all checks under "checks" key
        # 2. New flat structure: each check is a top-level key ending with "_check"
        # 3. Default config structure: check IDs directly at top level (without "_check" suffix)
        if "checks" in self.config_dict:
            # Old nested structure
            self.checks_config = self.config_dict.get("checks", {})
        else:
            # New flat structure and default config structure
            # Extract all keys ending with "_check" OR that look like check configurations
            self.checks_config = {}

            # First, add keys ending with "_check"
            for key, value in self.config_dict.items():
                if key.endswith("_check") and isinstance(value, dict):
                    self.checks_config[key.replace("_check", "")] = value

            # Then, add top-level keys that look like check configurations
            # (they have dict values and contain typical check config keys like enabled, severity, etc.)
            for key, value in self.config_dict.items():
                if (
                    key
                    not in [
                        "settings",
                        "custom_checks",
                        "custom_checks_dir",
                    ]  # Skip special config keys
                    and not key.endswith("_check")  # Skip if already processed above
                    and isinstance(value, dict)  # Must be a dict
                    and key not in self.checks_config  # Not already added
                ):
                    # This looks like a check configuration
                    self.checks_config[key] = value

        self.custom_checks = self.config_dict.get("custom_checks", [])
        self.custom_checks_dir = self.config_dict.get("custom_checks_dir")
        self.settings = self.config_dict.get("settings", {})

    def get_check_config(self, check_id: str) -> dict[str, Any]:
        """Get configuration for a specific check."""
        return self.checks_config.get(check_id, {})

    def is_check_enabled(self, check_id: str) -> bool:
        """Check if a specific check is enabled."""
        check_config = self.get_check_config(check_id)
        return check_config.get("enabled", True)

    def get_check_severity(self, check_id: str) -> str | None:
        """Get severity override for a check."""
        check_config = self.get_check_config(check_id)
        return check_config.get("severity")

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a global setting value."""
        return self.settings.get(key, default)


class ConfigLoader:
    """Loads configuration from various sources."""

    # Load default config names from constants module
    DEFAULT_CONFIG_NAMES = DEFAULT_CONFIG_FILENAMES

    @staticmethod
    def find_config_file(
        explicit_path: str | None = None, search_path: Path | None = None
    ) -> Path | None:
        """
        Find configuration file.

        Search order:
        1. Explicit path if provided
        2. Current directory
        3. Parent directories (walk up to root)
        4. User home directory

        Args:
            explicit_path: Explicit config file path
            search_path: Starting directory for search (defaults to cwd)

        Returns:
            Path to config file or None if not found
        """
        # Check explicit path first
        if explicit_path:
            path = Path(explicit_path)
            if path.exists() and path.is_file():
                return path
            raise FileNotFoundError(f"Config file not found: {explicit_path}")

        # Start from search path or current directory
        current = search_path or Path.cwd()

        # Search current and parent directories
        while True:
            for config_name in ConfigLoader.DEFAULT_CONFIG_NAMES:
                config_path = current / config_name
                if config_path.exists() and config_path.is_file():
                    return config_path

            # Stop at filesystem root
            parent = current.parent
            if parent == current:
                break
            current = parent

        # Check home directory
        home = Path.home()
        for config_name in ConfigLoader.DEFAULT_CONFIG_NAMES:
            config_path = home / config_name
            if config_path.exists() and config_path.is_file():
                return config_path

        return None

    @staticmethod
    def load_yaml(file_path: Path) -> dict[str, Any]:
        """
        Load YAML configuration file.

        Args:
            file_path: Path to YAML file

        Returns:
            Parsed configuration dictionary
        """
        try:
            with open(file_path) as f:
                config = yaml.safe_load(f)
                return config or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config file {file_path}: {e}")
        except Exception as e:
            raise ValueError(f"Error reading config file {file_path}: {e}")

    @staticmethod
    def load_config(
        explicit_path: str | None = None,
        search_path: Path | None = None,
        allow_missing: bool = True,
    ) -> ValidatorConfig:
        """
        Load configuration from file.

        Args:
            explicit_path: Explicit path to config file
            search_path: Starting directory for config search
            allow_missing: If True, return default config when file not found

        Returns:
            ValidatorConfig object

        Raises:
            FileNotFoundError: If config not found and allow_missing=False
        """
        config_file = ConfigLoader.find_config_file(explicit_path, search_path)

        if not config_file:
            if allow_missing:
                return ValidatorConfig()  # Return default config
            raise FileNotFoundError(
                f"No configuration file found. Searched for: {', '.join(ConfigLoader.DEFAULT_CONFIG_NAMES)}"
            )

        config_dict = ConfigLoader.load_yaml(config_file)
        return ValidatorConfig(config_dict)

    @staticmethod
    def apply_config_to_registry(config: ValidatorConfig, registry: CheckRegistry) -> None:
        """
        Apply configuration to a check registry.

        This configures all registered checks based on the loaded configuration.

        Args:
            config: Loaded configuration
            registry: Check registry to configure
        """
        # Get global hide_severities from settings (for fallback)
        global_hide_severities = config.settings.get("hide_severities")

        # Configure built-in checks
        for check in registry.get_all_checks():
            check_id = check.check_id
            check_config_dict = config.get_check_config(check_id)

            # Get existing config to preserve defaults set during registration
            existing_config = registry.get_config(check_id)
            existing_enabled = existing_config.enabled if existing_config else True

            # Parse hide_severities: per-check overrides global
            hide_severities = check_config_dict.get("hide_severities")
            if hide_severities is None:
                hide_severities = global_hide_severities
            if hide_severities is not None:
                hide_severities = frozenset(hide_severities)

            # Create CheckConfig object
            # If there's explicit config, use it; otherwise preserve existing enabled state
            check_config = CheckConfig(
                check_id=check_id,
                enabled=check_config_dict.get("enabled", existing_enabled),
                severity=check_config_dict.get("severity"),
                config=check_config_dict,
                description=check_config_dict.get("description", check.description),
                root_config=config.config_dict,  # Pass full config for cross-check access
                ignore_patterns=check_config_dict.get("ignore_patterns", []),
                hide_severities=hide_severities,
            )

            registry.configure_check(check_id, check_config)

    @staticmethod
    def load_custom_checks(config: ValidatorConfig, registry: CheckRegistry) -> list[str]:
        """
        Load custom checks from Python modules.

        Args:
            config: Loaded configuration
            registry: Check registry to add custom checks to

        Returns:
            List of loaded check IDs

        Note:
            Custom check modules should export a class that inherits from PolicyCheck.
            The module path should be importable (e.g., "my_package.my_check.MyCheck").
        """
        loaded_checks = []

        # Handle None or missing custom_checks
        if not config.custom_checks:
            return loaded_checks

        for custom_check_config in config.custom_checks:
            if not custom_check_config.get("enabled", True):
                continue

            module_path = custom_check_config.get("module")
            if not module_path:
                continue

            try:
                # Dynamic import of custom check class
                # Format: "package.module.ClassName"
                parts = module_path.rsplit(".", 1)
                if len(parts) != 2:
                    raise ValueError(
                        f"Invalid module path: {module_path}. "
                        "Expected format: 'package.module.ClassName'"
                    )

                module_name, class_name = parts

                # Import the module
                module = importlib.import_module(module_name)
                check_class = getattr(module, class_name)

                # Instantiate and register the check
                check_instance = check_class()
                registry.register(check_instance)

                # Configure the check
                check_config = CheckConfig(
                    check_id=check_instance.check_id,
                    enabled=True,
                    severity=custom_check_config.get("severity"),
                    config=custom_check_config.get("config", {}),
                    description=custom_check_config.get("description", check_instance.description),
                )
                registry.configure_check(check_instance.check_id, check_config)

                loaded_checks.append(check_instance.check_id)

            except Exception as e:
                # Log error but continue loading other checks
                print(f"Warning: Failed to load custom check '{module_path}': {e}")

        return loaded_checks

    @staticmethod
    def discover_checks_in_directory(directory: Path, registry: CheckRegistry) -> list[str]:
        """
        Auto-discover and load custom checks from a directory.

        This method scans a directory for Python files, imports them,
        and automatically registers any PolicyCheck subclasses found.

        Args:
            directory: Path to directory containing custom check modules
            registry: Check registry to add discovered checks to

        Returns:
            List of loaded check IDs

        Note:
            - All .py files in the directory will be scanned (non-recursive)
            - Files starting with '_' or '.' are skipped
            - Each file can contain multiple PolicyCheck subclasses
            - Classes must inherit from PolicyCheck and implement required methods
        """
        loaded_checks = []

        if not directory.exists():
            logger.warning(f"Custom checks directory does not exist: {directory}")
            return loaded_checks

        if not directory.is_dir():
            logger.warning(f"Custom checks path is not a directory: {directory}")
            return loaded_checks

        logger.info(f"Scanning for custom checks in: {directory}")

        # Get all Python files in the directory
        python_files = [
            f
            for f in directory.iterdir()
            if f.is_file()
            and f.suffix == ".py"
            and not f.name.startswith("_")
            and not f.name.startswith(".")
        ]

        for py_file in python_files:
            try:
                # Load module from file
                module_name = f"custom_checks_{py_file.stem}"
                spec = importlib.util.spec_from_file_location(module_name, py_file)

                if spec is None or spec.loader is None:
                    logger.warning(f"Could not load spec from {py_file}")
                    continue

                module = importlib.util.module_from_spec(spec)

                # Add to sys.modules to support relative imports
                sys.modules[module_name] = module

                # Execute the module
                spec.loader.exec_module(module)

                # Find all PolicyCheck subclasses in the module
                for name, obj in inspect.getmembers(module):
                    # Skip imported classes and non-classes
                    if not inspect.isclass(obj):
                        continue

                    # Skip the base PolicyCheck class itself
                    if obj is PolicyCheck:
                        continue

                    # Check if it's a PolicyCheck subclass
                    if issubclass(obj, PolicyCheck) and obj.__module__ == module_name:
                        try:
                            # Instantiate and register the check
                            check_instance = obj()

                            # Verify the check has required properties
                            if not hasattr(check_instance, "check_id"):
                                logger.warning(
                                    f"Check class {name} in {py_file} missing check_id property"
                                )
                                continue

                            registry.register(check_instance)

                            # Create default config (disabled by default - must be explicitly enabled in config)
                            check_config = CheckConfig(
                                check_id=check_instance.check_id,
                                enabled=False,
                                description=check_instance.description,
                            )
                            registry.configure_check(check_instance.check_id, check_config)

                            loaded_checks.append(check_instance.check_id)
                            logger.info(
                                f"Loaded custom check '{check_instance.check_id}' from {py_file.name}"
                            )

                        except Exception as e:
                            logger.warning(
                                f"Failed to instantiate check {name} from {py_file}: {e}"
                            )

            except Exception as e:
                logger.warning(f"Failed to load custom check module {py_file}: {e}")

        if loaded_checks:
            logger.info(
                f"Auto-discovered {len(loaded_checks)} custom checks: {', '.join(loaded_checks)}"
            )

        return loaded_checks


def load_validator_config(
    config_path: str | None = None, allow_missing: bool = True
) -> ValidatorConfig:
    """
    Convenience function to load validator configuration.

    Args:
        config_path: Optional explicit path to config file
        allow_missing: If True, return default config when file not found

    Returns:
        ValidatorConfig object
    """
    return ConfigLoader.load_config(explicit_path=config_path, allow_missing=allow_missing)

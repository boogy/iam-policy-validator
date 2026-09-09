"""The shipped example configs must load, validate, and name only real checks."""

import logging
from pathlib import Path

import pytest

from iam_validator.core.check_registry import create_default_registry
from iam_validator.core.config.config_loader import (
    KNOWN_CHECK_IDS,
    ConfigLoader,
    ValidatorConfig,
    validate_config,
)

CONFIG_DIR = Path(__file__).resolve().parents[2] / "examples" / "configs"
EXAMPLE_CONFIGS = sorted(CONFIG_DIR.glob("*.yaml"))
REFERENCE_CONFIG = CONFIG_DIR / "full-reference-config.yaml"


def test_example_configs_discovered():
    assert EXAMPLE_CONFIGS, f"no example configs found under {CONFIG_DIR}"
    assert REFERENCE_CONFIG in EXAMPLE_CONFIGS


@pytest.mark.parametrize("config_path", EXAMPLE_CONFIGS, ids=lambda p: p.name)
def test_example_config_passes_schema_validation(config_path: Path):
    is_valid, errors = validate_config(ConfigLoader.load_yaml(config_path))
    assert is_valid, f"{config_path.name} failed schema validation: {errors}"


@pytest.mark.parametrize("config_path", EXAMPLE_CONFIGS, ids=lambda p: p.name)
def test_example_config_emits_no_unknown_check_warnings(config_path: Path, caplog):
    with caplog.at_level(logging.WARNING, logger="iam_validator.core.config.config_loader"):
        validate_config(ConfigLoader.load_yaml(config_path))
    unknown = [r.message for r in caplog.records if "Unknown check ID" in r.message]
    assert not unknown, f"{config_path.name}: {unknown}"


def test_known_check_ids_matches_registry():
    registered = {check.check_id for check in create_default_registry().get_all_checks()}
    assert registered == set(KNOWN_CHECK_IDS)


def test_reference_config_covers_every_registered_check():
    config = ValidatorConfig(ConfigLoader.load_yaml(REFERENCE_CONFIG))
    registered = {check.check_id for check in create_default_registry().get_all_checks()}
    assert registered <= set(config.checks_config)


def test_reference_config_documents_every_settings_key():
    from iam_validator.core.config.config_loader import SettingsSchema

    text = REFERENCE_CONFIG.read_text()
    missing = [key for key in SettingsSchema.model_fields if key not in text]
    assert not missing, f"undocumented settings keys: {missing}"

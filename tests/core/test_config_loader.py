"""Unit tests for ConfigLoader logging behavior and config/defaults consistency."""

import logging
from pathlib import Path

from iam_validator.core.check_registry import CheckRegistry
from iam_validator.core.config.config_loader import ConfigLoader, ValidatorConfig
from iam_validator.core.config.defaults import DEFAULT_CONFIG

_REPO_ROOT = Path(__file__).resolve().parents[2]

# Declared in defaults.py and documented, but with no consumer yet (see docs/user-guide/configuration.md:369).
DOCUMENTED_UNIMPLEMENTED = {"documentation"}


def test_custom_check_load_failure_is_logged_not_printed(caplog, capsys):
    config = ValidatorConfig({"custom_checks": [{"module": "no.such.module.Nope"}]}, use_defaults=False)
    with caplog.at_level(logging.WARNING):
        ConfigLoader.load_custom_checks(config, CheckRegistry())

    assert capsys.readouterr().out == ""
    assert any("no.such.module" in r.message for r in caplog.records)


def test_no_dead_settings_in_defaults():
    sources = [
        path.read_text(encoding="utf-8")
        for path in (_REPO_ROOT / "iam_validator").rglob("*.py")
        if path.parts[-2:] != ("config", "defaults.py")
    ]
    assert sources, "no sources found to scan"

    dead = [
        key
        for key in DEFAULT_CONFIG["settings"]
        if not any(f'"{key}"' in text or f"'{key}'" in text for text in sources)
    ]

    assert set(dead) <= DOCUMENTED_UNIMPLEMENTED, f"dead settings: {sorted(dead)}"

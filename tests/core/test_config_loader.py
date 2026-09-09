"""Unit tests for ConfigLoader logging behavior and config/defaults consistency."""

import logging
import subprocess
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
    dead = []
    for key in DEFAULT_CONFIG["settings"]:
        hits: list[str] = []
        for pattern in (f'"{key}"', f"'{key}'"):
            out = subprocess.run(
                ["rg", "-n", "-F", pattern, str(_REPO_ROOT / "iam_validator")],
                capture_output=True,
                text=True,
            ).stdout.splitlines()
            hits += [h for h in out if "config/defaults.py" not in h]
        if not hits:
            dead.append(key)

    assert set(dead) <= DOCUMENTED_UNIMPLEMENTED, f"dead settings: {sorted(dead)}"

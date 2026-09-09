"""Unit tests for ConfigLoader logging behavior and config/defaults consistency."""

import logging
import re
from pathlib import Path

import yaml

from iam_validator.core.check_registry import CheckRegistry
from iam_validator.core.config.config_loader import ConfigLoader, SettingsSchema, ValidatorConfig
from iam_validator.core.config.defaults import DEFAULT_CONFIG

_REPO_ROOT = Path(__file__).resolve().parents[2]

# Declared in defaults.py and documented, but with no consumer yet (see docs/user-guide/configuration.md:369).
DOCUMENTED_UNIMPLEMENTED = {"documentation"}

_CONFIGURATION_MD = _REPO_ROOT / "docs" / "user-guide" / "configuration.md"
_MCP_SERVER_MD = _REPO_ROOT / "docs" / "integrations" / "mcp-server.md"

# Read straight from the raw settings dict (config.root_config / config.config)
# rather than through SettingsSchema, so `extra="allow"` never validates them —
# but they are genuinely wired up (see action_resource_matching.py,
# resource_validation.py), so they aren't phantom.
_NON_SCHEMA_FUNCTIONAL_SETTINGS = {"allow_template_variables"}

# Settings that have appeared in docs but never existed as a setting anywhere
# in the codebase (`SettingsSchema` field or otherwise).
_KNOWN_PHANTOM_SETTING_KEYS = ("parallel", "max_workers", "fail_fast")


def _extract_fenced_yaml_block(text: str, heading: str) -> str:
    """Return the content of the first ```yaml fenced block after `heading`."""
    start = text.index(heading)
    fence_start = text.index("```yaml", start)
    body_start = fence_start + len("```yaml")
    fence_end = text.index("```", body_start)
    return text[body_start:fence_end]


def _extract_markdown_table_keys(text: str, heading: str) -> set[str]:
    """Return backtick-quoted names from the first markdown table after `heading`."""
    start = text.index(heading)
    section = text[start:]
    next_heading = re.search(r"\n#{1,6} ", section[1:])
    if next_heading:
        section = section[: next_heading.start() + 1]
    return set(re.findall(r"\|\s*`([a-zA-Z_][a-zA-Z0-9_]*)`\s*\|", section))


def test_documented_global_settings_match_schema():
    """Every key documented under `settings:` in the configuration.md reference
    block must be a real SettingsSchema field (or a known functional
    non-schema setting). `SettingsSchema` uses `extra="allow"`, so a typo'd or
    invented key like the historical `parallel` / `max_workers` validates
    silently and just does nothing — this is the only guard against that.
    """
    block = _extract_fenced_yaml_block(_CONFIGURATION_MD.read_text(encoding="utf-8"), "### Global Settings")
    documented_keys = set(yaml.safe_load(block)["settings"].keys())

    allowed = set(SettingsSchema.model_fields.keys()) | _NON_SCHEMA_FUNCTIONAL_SETTINGS
    phantom = documented_keys - allowed
    assert not phantom, f"docs/user-guide/configuration.md documents non-existent settings: {sorted(phantom)}"


def test_mcp_server_common_settings_match_schema():
    keys = _extract_markdown_table_keys(_MCP_SERVER_MD.read_text(encoding="utf-8"), "#### Common Settings")

    allowed = set(SettingsSchema.model_fields.keys()) | _NON_SCHEMA_FUNCTIONAL_SETTINGS
    phantom = keys - allowed
    assert not phantom, (
        f"docs/integrations/mcp-server.md Common Settings table documents non-existent settings: {sorted(phantom)}"
    )


def test_known_phantom_settings_absent_from_docs():
    for path in (_CONFIGURATION_MD, _MCP_SERVER_MD):
        text = path.read_text(encoding="utf-8")
        for key in _KNOWN_PHANTOM_SETTING_KEYS:
            assert f"`{key}`" not in text, f"{path} documents phantom setting '{key}' in a table"
            assert not re.search(rf"^\s*{key}:\s", text, re.MULTILINE), (
                f"{path} documents phantom setting key '{key}:' in a YAML block"
            )


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

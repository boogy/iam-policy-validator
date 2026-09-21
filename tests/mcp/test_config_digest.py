"""Tests for ServerContext.config_digest: stability and sensitivity to registry provenance."""

import subprocess
import sys
import textwrap

import pytest

from iam_validator.core.check_registry import CheckConfig, create_default_registry
from iam_validator.core.config.config_loader import ValidatorConfig
from iam_validator.mcp.context import _compute_config_digest

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

_BASE_CONFIG_DICT = {"settings": {"fail_on_severity": ["error", "critical"]}}


def _digest_for(config_dict: dict) -> str:
    config = ValidatorConfig(config_dict)
    registry = create_default_registry()
    return _compute_config_digest(config, registry)


def test_digest_stable_across_two_processes(tmp_path):
    script = textwrap.dedent(
        """
        from iam_validator.core.check_registry import create_default_registry
        from iam_validator.core.config.config_loader import ValidatorConfig
        from iam_validator.mcp.context import _compute_config_digest

        config = ValidatorConfig({"settings": {"fail_on_severity": ["error", "critical"]}})
        registry = create_default_registry()
        print(_compute_config_digest(config, registry))
        """
    )
    script_path = tmp_path / "digest_script.py"
    script_path.write_text(script)

    outputs = [
        subprocess.run([sys.executable, str(script_path)], capture_output=True, text=True, check=True).stdout.strip()
        for _ in range(2)
    ]

    assert outputs[0], "digest script produced no output"
    assert outputs[0] == outputs[1]


def test_digest_changes_when_a_check_severity_changes():
    config = ValidatorConfig(_BASE_CONFIG_DICT)
    registry = create_default_registry()
    baseline = _compute_config_digest(config, registry)

    check_id = registry.get_all_checks()[0].check_id
    original = registry.get_config(check_id)
    registry.configure_check(
        check_id,
        CheckConfig(check_id=check_id, enabled=original.enabled if original else True, severity="critical"),
    )
    changed = _compute_config_digest(config, registry)

    assert changed != baseline


def test_digest_changes_when_a_check_is_disabled():
    config = ValidatorConfig(_BASE_CONFIG_DICT)
    registry = create_default_registry()
    baseline = _compute_config_digest(config, registry)

    check_id = registry.get_all_checks()[0].check_id
    registry.configure_check(check_id, CheckConfig(check_id=check_id, enabled=False))
    changed = _compute_config_digest(config, registry)

    assert changed != baseline


def test_digest_changes_when_an_entry_point_check_is_added():
    from iam_validator.core.check_registry import PolicyCheck

    config = ValidatorConfig(_BASE_CONFIG_DICT)
    registry = create_default_registry()
    baseline = _compute_config_digest(config, registry)

    class _ExtraEntryPointCheck(PolicyCheck):
        check_id = "extra_entry_point_check"
        description = "test-only entry-point check"

        async def execute(self, statement, statement_idx, fetcher, config):
            return []

    registry.register(_ExtraEntryPointCheck(), source="entry_point")
    registry.configure_check("extra_entry_point_check", CheckConfig(check_id="extra_entry_point_check"))
    changed = _compute_config_digest(config, registry)

    assert changed != baseline

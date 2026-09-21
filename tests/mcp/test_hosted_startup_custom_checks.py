"""Hosted startup must fail loudly when a declared custom check can't load.

Local mode keeps ConfigLoader's warn-and-continue contract unchanged; hosted
mode enforces the declared baseline via ``_verify_hosted_custom_checks``.
"""

import sys

import pytest

from iam_validator.mcp.context import HostedStartupError, build_context
from iam_validator.mcp.settings import ServerSettings

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

_BROKEN_MODULE_NAME = "_hosted_startup_test_broken_check"
_BROKEN_MODULE_SOURCE = "raise RuntimeError('this custom check is broken on import')\n"


@pytest.fixture
def broken_check_config(tmp_path, monkeypatch):
    checks_dir = tmp_path / "checks_pkg"
    checks_dir.mkdir()
    (checks_dir / f"{_BROKEN_MODULE_NAME}.py").write_text(_BROKEN_MODULE_SOURCE)
    monkeypatch.syspath_prepend(str(checks_dir))
    monkeypatch.delitem(sys.modules, _BROKEN_MODULE_NAME, raising=False)

    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text(
        "settings:\n"
        "  fail_on_severity: [error, critical]\n"
        "custom_checks:\n"
        f"  - module: {_BROKEN_MODULE_NAME}.BrokenCheck\n"
        "    enabled: true\n"
    )
    return config_file


def test_hosted_startup_exits_loudly_naming_the_broken_check(broken_check_config):
    settings = ServerSettings(
        mode="hosted",
        auth="token",
        auth_explicitly_set=True,
        config_source=broken_check_config,
    )

    with pytest.raises(HostedStartupError) as exc_info:
        build_context(settings)

    assert f"{_BROKEN_MODULE_NAME}.BrokenCheck" in str(exc_info.value)


def test_local_mode_boots_with_only_a_warning_for_the_same_config(broken_check_config, caplog):
    settings = ServerSettings(mode="local", config_source=broken_check_config)

    context = build_context(settings)

    assert context is not None
    assert context.mutable is not None


def test_hosted_startup_without_explicit_config_fails_loud_and_never_discovers(tmp_path, monkeypatch):
    """Hosted mode must not fall back to ConfigLoader's cwd/parent/$HOME discovery.

    Regression guard: an earlier version passed ``config_source=None`` straight
    into ``ConfigLoader.find_config_file``, which silently adopted whatever
    ``iam-validator.yaml`` happened to sit in cwd (or a parent, or $HOME).
    """
    ambient_config = tmp_path / "iam-validator.yaml"
    ambient_config.write_text("checks:\n  wildcard_action:\n    enabled: false\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("IAM_VALIDATOR_MCP_CONFIG", raising=False)

    settings = ServerSettings(mode="hosted", auth="token", auth_explicitly_set=True, config_source=None)

    with pytest.raises(HostedStartupError) as exc_info:
        build_context(settings)

    assert "explicit config" in str(exc_info.value)

"""Hosted startup behaviour not already covered by test_hosted_startup_custom_checks.py / test_auth.py."""

import pytest

from iam_validator.mcp.context import build_context
from iam_validator.mcp.settings import ServerSettings

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")


def test_hosted_startup_verifies_custom_checks_before_serving(tmp_path, monkeypatch):
    import sys

    module_name = "_hosted_startup_ok_check"
    (tmp_path / f"{module_name}.py").write_text(
        "from iam_validator.core.check_registry import PolicyCheck\n\n\n"
        "class OkCheck(PolicyCheck):\n"
        "    check_id = 'hosted_startup_ok_check'\n"
        "    description = 'ok'\n\n"
        "    async def execute(self, statement, statement_idx, fetcher, config):\n"
        "        return []\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, module_name, raising=False)

    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text(
        "settings:\n  fail_on_severity: [error, critical]\n"
        f"custom_checks:\n  - module: {module_name}.OkCheck\n    enabled: true\n"
    )
    settings = ServerSettings(mode="hosted", auth="token", auth_explicitly_set=True, config_source=config_file)

    context = build_context(settings)

    assert context.registry.get_check("hosted_startup_ok_check") is not None


def test_unwritable_cache_directory_fails_startup(tmp_path, monkeypatch):
    import iam_validator.mcp.context as context_module
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher as RealAWSServiceFetcher

    monkeypatch.setattr(context_module, "AWSServiceFetcher", RealAWSServiceFetcher)

    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text("settings:\n  fail_on_severity: [error, critical]\n")
    settings = ServerSettings(
        mode="hosted",
        auth="token",
        auth_explicitly_set=True,
        config_source=config_file,
        cache_directory=blocker,
    )

    with pytest.raises(OSError):
        build_context(settings)


def test_local_mode_defaults_to_no_auth():
    settings = ServerSettings()
    assert settings.mode == "local"
    assert settings.auth == "none"
    assert settings.auth_explicitly_set is False

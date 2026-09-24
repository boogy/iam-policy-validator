"""_resolve_run_context reuses ServerContext.registry across calls -- no rebuild, no re-import."""

from types import SimpleNamespace

import pytest

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

from iam_validator.mcp.context import build_context  # noqa: E402
from iam_validator.mcp.settings import ServerSettings  # noqa: E402
from iam_validator.mcp.tools import validate as validate_module  # noqa: E402
from iam_validator.mcp.tools.validate import validate_policies  # noqa: E402

_COUNTER_MODULE_SOURCE = (
    "import iam_validator.core.check_registry as check_registry_module\n\n"
    "INSTANTIATION_COUNT = 0\n\n\n"
    "class RegistryReuseCounterCheck(check_registry_module.PolicyCheck):\n"
    "    check_id = 'registry_reuse_counter_check'\n"
    "    description = 'counts how many times it is instantiated'\n\n"
    "    def __init__(self):\n"
    "        global INSTANTIATION_COUNT\n"
    "        INSTANTIATION_COUNT += 1\n\n"
    "    async def execute(self, statement, statement_idx, fetcher, config):\n"
    "        return []\n"
)


def _fake_ctx(context) -> SimpleNamespace:
    return SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))


async def test_build_registry_never_called_again_from_the_validate_path(tmp_path, monkeypatch):
    call_count = 0
    real_build_registry = validate_module.build_registry

    def counting_build_registry(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return real_build_registry(*args, **kwargs)

    monkeypatch.setattr(validate_module, "build_registry", counting_build_registry)

    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text("settings:\n  fail_on_severity: [error, critical]\n")
    context = build_context(ServerSettings(mode="local", config_source=config_file))
    ctx = _fake_ctx(context)
    assert call_count == 0

    await validate_policies(policies=[{"Version": "2012-10-17", "Statement": []}], ctx=ctx)
    await validate_policies(policies=[{"Version": "2012-10-17", "Statement": []}], ctx=ctx)

    assert call_count == 0


async def test_discovered_custom_check_is_instantiated_once_across_repeat_validate_calls(tmp_path):
    checks_dir = tmp_path / "checks_pkg"
    checks_dir.mkdir()
    (checks_dir / "registry_reuse_counter_check.py").write_text(_COUNTER_MODULE_SOURCE)

    settings = ServerSettings(mode="local", custom_checks_dir=checks_dir)
    context = build_context(settings)
    ctx = _fake_ctx(context)

    import custom_checks_registry_reuse_counter_check as counter_module

    assert counter_module.INSTANTIATION_COUNT == 1

    await validate_policies(policies=[{"Version": "2012-10-17", "Statement": []}], ctx=ctx)
    await validate_policies(policies=[{"Version": "2012-10-17", "Statement": []}], ctx=ctx)

    assert counter_module.INSTANTIATION_COUNT == 1

"""A check registered at runtime must reach iam://checks and describe_checks
with zero edits under iam_validator/mcp/ -- both read the registry, never a
hardcoded check list.
"""

import json
import textwrap
from types import SimpleNamespace
from typing import ClassVar
from unittest.mock import MagicMock

import pytest

from iam_validator.core.check_registry import CheckRegistry, PolicyCheck, create_default_registry
from iam_validator.core.config.config_loader import ConfigLoader, ValidatorConfig
from iam_validator.mcp.context import ServerContext
from iam_validator.mcp.resources import checks_resource
from iam_validator.mcp.tools.checks import describe_checks

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")


class _DummyRuntimeCheck(PolicyCheck):
    """Registration-only fixture; execute() is never invoked by these tests."""

    check_id: ClassVar[str] = "dummy_runtime_check"
    description: ClassVar[str] = "Registered at test runtime, not built in"

    async def execute(self, statement, statement_idx, fetcher, config):
        return []


def _registry_with_dummy(source: str) -> CheckRegistry:
    registry = create_default_registry()
    registry.register(_DummyRuntimeCheck(), source=source)
    return registry


def _fake_ctx(registry: CheckRegistry) -> SimpleNamespace:
    context = ServerContext(
        config=ValidatorConfig({}),
        registry=registry,
        formatters=MagicMock(),
        fetcher=MagicMock(),
        aws_sessions={},
        settings=MagicMock(),
        mutable=None,
    )
    return SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))


async def test_dynamic_check_appears_in_checks_resource():
    ctx = _fake_ctx(_registry_with_dummy("discovered"))

    catalog = json.loads(await checks_resource(ctx))

    assert "dummy_runtime_check" in {c["check_id"] for c in catalog}


async def test_dynamic_check_appears_in_describe_checks():
    ctx = _fake_ctx(_registry_with_dummy("discovered"))

    result = await describe_checks(check_ids=["dummy_runtime_check"], ctx=ctx)

    assert len(result["checks"]) == 1
    entry = result["checks"][0]
    assert entry["check_id"] == "dummy_runtime_check"
    assert entry["description"] == "Registered at test runtime, not built in"
    assert entry["source"] == "discovered"


async def test_builtin_check_is_reported_as_builtin():
    registry = create_default_registry()
    ctx = _fake_ctx(registry)

    result = await describe_checks(check_ids=["wildcard_action"], ctx=ctx)

    assert result["checks"][0]["source"] == "builtin"


async def test_entry_point_check_is_reported_as_entry_point(monkeypatch):
    class _FakeEntryPoint:
        name = "fake_plugin_check"

        def load(self):
            class FakePluginCheck(PolicyCheck):
                check_id = "fake_plugin_check"
                description = "registered via entry point"
                default_severity = "low"

                async def execute(self, statement, statement_idx, fetcher, config):
                    return []

            return FakePluginCheck

    monkeypatch.setattr(
        "iam_validator.core.check_registry.entry_points",
        lambda group: [_FakeEntryPoint()],
    )
    registry = create_default_registry()  # loads entry-point checks internally
    ctx = _fake_ctx(registry)

    result = await describe_checks(check_ids=["fake_plugin_check"], ctx=ctx)

    assert result["checks"][0]["source"] == "entry_point"


async def test_config_module_check_is_reported_as_config_module(tmp_path, monkeypatch):
    package = tmp_path / "describe_checks_module_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "check.py").write_text(
        textwrap.dedent(
            """
            from iam_validator.core.check_registry import PolicyCheck

            class ModuleCheck(PolicyCheck):
                check_id = "module_provenance_check"
                description = "registered via custom_checks module entry"
                default_severity = "low"

                async def execute(self, statement, statement_idx, fetcher, config):
                    return []
            """
        )
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    registry = create_default_registry()
    config = ValidatorConfig(
        {"custom_checks": [{"module": "describe_checks_module_pkg.check.ModuleCheck"}]},
        use_defaults=False,
    )
    ConfigLoader.load_custom_checks(config, registry)
    ctx = _fake_ctx(registry)

    result = await describe_checks(check_ids=["module_provenance_check"], ctx=ctx)

    assert result["checks"][0]["source"] == "config_module"


async def test_discovered_check_is_reported_as_discovered(tmp_path):
    (tmp_path / "check.py").write_text(
        textwrap.dedent(
            """
            from iam_validator.core.check_registry import PolicyCheck

            class DiscoveredCheck(PolicyCheck):
                check_id = "directory_provenance_check"
                description = "auto-discovered from custom_checks_dir"
                default_severity = "low"

                async def execute(self, statement, statement_idx, fetcher, config):
                    return []
            """
        )
    )

    registry = create_default_registry()
    ConfigLoader.discover_checks_in_directory(tmp_path, registry)
    ctx = _fake_ctx(registry)

    result = await describe_checks(check_ids=["directory_provenance_check"], ctx=ctx)

    assert result["checks"][0]["source"] == "discovered"


async def test_describe_checks_reports_nonempty_docstring_for_a_builtin_check():
    """Guards against -OO/PYTHONOPTIMIZE=2 silently blanking check docstrings."""
    result = await describe_checks()

    docstrings = [c["docstring"] for c in result["checks"] if c["docstring"]]
    assert docstrings, "expected at least one built-in check to carry a non-empty docstring"

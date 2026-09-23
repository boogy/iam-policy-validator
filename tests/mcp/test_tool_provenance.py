"""Every registered MCP tool must map to a CLI command or SDK export a caller could use without MCP."""

from pathlib import Path

import pytest

from iam_validator.commands import ALL_COMMANDS
from iam_validator.core.config.config_loader import ConfigLoader as ConfigLoader  # noqa: F401 (see mapping)
from iam_validator.core.policy_checks import build_registry as build_registry  # noqa: F401 (see mapping)
from iam_validator.sdk import __all__ as _sdk_exports

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

from iam_validator.mcp.build import build_server
from iam_validator.mcp.settings import ServerSettings

REPO_ROOT = Path(__file__).resolve().parents[2]

# tool name -> its CLI/SDK equivalent; "sdk:"/"cli:" disambiguate an ambiguous name.
_PROVENANCE: dict[str, str] = {
    "validate_policies": "cli:validate",
    "query": "cli:query",
    "analyze_policy": "cli:analyze",
    "describe_checks": "sdk:build_registry",
    "get_config": "sdk:ConfigLoader",
}

# set_config edits session state, an MCP-only concept with no CLI/SDK counterpart.
_EXEMPT_TOOLS = frozenset({"set_config"})


async def _registered_tool_names() -> set[str]:
    names: set[str] = set()
    for mode, transport in (("local", "stdio"), ("hosted", "http")):
        settings = ServerSettings(mode=mode, transport=transport, auth="none", auth_explicitly_set=(mode == "hosted"))
        mcp = build_server(settings)
        names |= {t.name for t in await mcp.list_tools()}
    return names


class TestEveryToolHasNonMcpProvenance:
    async def test_every_registered_tool_is_mapped_or_the_one_exemption(self):
        registered = await _registered_tool_names()
        unaccounted = registered - set(_PROVENANCE) - _EXEMPT_TOOLS
        assert not unaccounted, (
            f"tool(s) {unaccounted} have no CLI/SDK provenance entry and aren't the "
            "documented set_config exemption -- add a _PROVENANCE mapping"
        )

        stale = (set(_PROVENANCE) | _EXEMPT_TOOLS) - registered
        assert not stale, f"provenance entry/exemption for tool(s) no longer registered: {stale}"

    def test_exactly_one_named_exemption(self):
        assert _EXEMPT_TOOLS == {"set_config"}

    def test_every_cli_provenance_names_a_real_command(self):
        cli_commands = {c.name for c in ALL_COMMANDS}
        claimed = {v.removeprefix("cli:") for v in _PROVENANCE.values() if v.startswith("cli:")}
        assert claimed <= cli_commands, f"claimed CLI command(s) don't exist: {claimed - cli_commands}"

    def test_every_sdk_provenance_names_a_real_export_or_known_symbol(self):
        claimed = {v.removeprefix("sdk:") for v in _PROVENANCE.values() if v.startswith("sdk:")}
        known_non_sdk_symbols = {"build_registry", "ConfigLoader"}
        assert claimed <= set(_sdk_exports) | known_non_sdk_symbols, (
            f"claimed SDK/known symbol(s) don't exist: {claimed - set(_sdk_exports) - known_non_sdk_symbols}"
        )


class TestGenerationSurfaceFullyRemoved:
    """The template/generation surface was deleted wholesale and must not reappear."""

    def test_templates_package_does_not_exist(self):
        assert not (REPO_ROOT / "iam_validator" / "mcp" / "templates").exists()

    def test_generation_tools_module_does_not_exist(self):
        assert not (REPO_ROOT / "iam_validator" / "mcp" / "tools" / "generation.py").exists()

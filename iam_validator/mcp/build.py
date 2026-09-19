"""Builds a fresh ``FastMCP`` instance from resolved settings.

Tool modules are iterated in the fixed order below -- never a set or a dict
built from one -- so two ``build_server()`` calls with identical settings
produce an identical tool-name sequence (MCP 2026-07-28 requires this for
client-side list caching).
"""

from __future__ import annotations

from fastmcp import FastMCP

from iam_validator.mcp.component_spec import ComponentSpec
from iam_validator.mcp.instructions import BASE_INSTRUCTIONS
from iam_validator.mcp.prompts import PROMPTS
from iam_validator.mcp.resources import RESOURCES
from iam_validator.mcp.settings import ServerSettings
from iam_validator.mcp.tools import analyze, org_config_tools, query, validation

_TOOL_MODULES = (validation, query, org_config_tools, analyze)

# Every profile except "read-only" filters by ComponentSpec.tag; "read-only"
# filters by ComponentSpec.mutating instead (checked directly in spec_survives).
_PROFILE_TAGS: dict[str, frozenset[str]] = {
    "validate-only": frozenset({"validate"}),
    "validate-and-query": frozenset({"validate", "query"}),
}


def spec_survives(spec: ComponentSpec, settings: ServerSettings) -> bool:
    """True if ``spec`` should be registered under ``settings``."""
    if settings.mode not in spec.modes:
        return False
    if settings.transport not in spec.transports:
        return False
    if settings.profile == "read-only":
        return not spec.mutating
    allowed_tags = _PROFILE_TAGS.get(settings.profile)
    if allowed_tags is not None and spec.tag not in allowed_tags:
        return False
    return True


def build_server(settings: ServerSettings) -> FastMCP:
    """Construct a fresh ``FastMCP`` instance carrying only the specs ``settings`` allow.

    Never reuses a module-level singleton: each call returns its own instance.
    """
    from iam_validator.mcp.context import server_lifespan

    mcp = FastMCP(name="IAM Policy Validator", lifespan=server_lifespan, instructions=BASE_INSTRUCTIONS)

    for module in _TOOL_MODULES:
        for tool_spec in getattr(module, "TOOLS", ()):
            if not spec_survives(tool_spec, settings):
                continue
            mcp.tool(
                tool_spec.fn,
                name=tool_spec.name,
                tags={tool_spec.tag},
                annotations=tool_spec.annotations,
                output_schema=tool_spec.output_schema,
            )

    for resource_spec in RESOURCES:
        if not spec_survives(resource_spec, settings):
            continue
        mcp.resource(resource_spec.uri, name=resource_spec.name, tags={resource_spec.tag})(resource_spec.fn)

    for prompt_spec in PROMPTS:
        if not spec_survives(prompt_spec, settings):
            continue
        mcp.prompt(prompt_spec.fn, name=prompt_spec.name, tags={prompt_spec.tag})

    return mcp


__all__ = ["spec_survives", "build_server"]

"""Builds a fresh ``FastMCP`` instance from resolved settings.

Tool modules are iterated in the fixed order below -- never a set or a dict
built from one -- so two ``build_server()`` calls with identical settings
produce an identical tool-name sequence (MCP 2026-07-28 requires this for
client-side list caching).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastmcp import FastMCP
from fastmcp.server.auth import restrict_tag
from fastmcp.tools.function_tool import FunctionTool

from iam_validator.mcp.auth import SCOPE_TO_TAG, get_auth_provider
from iam_validator.mcp.component_spec import ComponentSpec
from iam_validator.mcp.instructions import BASE_INSTRUCTIONS
from iam_validator.mcp.prompts import PROMPTS
from iam_validator.mcp.resources import RESOURCES
from iam_validator.mcp.settings import ServerSettings
from iam_validator.mcp.tools import analyze, checks, config, query, validate

if TYPE_CHECKING:
    from fastmcp.server.auth import AuthCheck, AuthProvider

    from iam_validator.mcp.context import ServerContext

_TOOL_MODULES = (validate, query, checks, config, analyze)

# tag -> scopes, derived from auth.SCOPE_TO_TAG so the two never drift apart. A tag
# absent here (e.g. "fix") has no scope requirement and stays visible to any caller.
_TAG_TO_SCOPES: dict[str, list[str]] = {}
for _scope, _tag in SCOPE_TO_TAG.items():
    _TAG_TO_SCOPES.setdefault(_tag, []).append(_scope)

# Every profile except "read-only" filters by ComponentSpec.tag; "read-only"
# filters by ComponentSpec.mutating instead (checked directly in spec_survives).
_PROFILE_TAGS: dict[str, frozenset[str]] = {
    "validate-only": frozenset({"validate"}),
    "validate-and-query": frozenset({"validate", "query"}),
}

PROFILE_DESCRIPTIONS: dict[str, str] = {
    "full": "All tools (default).",
    "validate-only": "Validation tools only — smallest token footprint.",
    "validate-and-query": (
        "Validation + AWS service-reference query tools. Does NOT include the live "
        "AWS Access Analyzer (use 'full' for that)."
    ),
    "read-only": (
        "Excludes any tool tagged 'mutating' (set_/clear_/load_*). Tag-based, not "
        "annotation-based — destructiveHint=False is intentional for session-only "
        "mutators per MCP spec, but they're still hidden here via the mutating tag."
    ),
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


def _component_auth(spec: ComponentSpec, auth_provider: AuthProvider | None) -> AuthCheck | None:
    """Scope check for ``spec``, or ``None`` if it should stay ungated.

    Only attached when a real ``AuthProvider`` is configured: outside a live request
    (e.g. direct ``list_tools()`` in tests, or any ``auth="none"`` deployment) FastMCP
    has no token to check, and ``restrict_tag`` would hide every scoped component.
    """
    # MCP 2026-07-28 allows the tool set to vary per-request by presented authorization
    # (this), but never per-connection or as a side effect of another request (which
    # spec_survives's build-time profile filtering never does -- it's fixed per server).
    if auth_provider is None:
        return None
    scopes = spec.scopes or _TAG_TO_SCOPES.get(spec.tag)
    if not scopes:
        return None
    return restrict_tag(spec.tag, scopes=list(scopes))


def build_server(settings: ServerSettings) -> FastMCP:
    """Construct a fresh ``FastMCP`` instance carrying only the specs ``settings`` allow.

    Never reuses a module-level singleton: each call returns its own instance.
    """
    from iam_validator.mcp.context import server_lifespan

    @asynccontextmanager
    async def _lifespan(server: FastMCP) -> AsyncIterator[ServerContext]:
        async with server_lifespan(server, settings) as context:
            yield context

    auth_provider = get_auth_provider(settings)
    mcp = FastMCP(
        name="IAM Policy Validator",
        lifespan=_lifespan,
        instructions=BASE_INSTRUCTIONS,
        auth=auth_provider,
    )

    for module in _TOOL_MODULES:
        for tool_spec in getattr(module, "TOOLS", ()):
            if not spec_survives(tool_spec, settings):
                continue
            auth = _component_auth(tool_spec, auth_provider)
            if tool_spec.input_schema is not None:
                # from_function() can't infer a discriminated union and rejects a non-object output_schema.
                tool = FunctionTool.from_function(
                    tool_spec.fn,
                    name=tool_spec.name,
                    tags={tool_spec.tag},
                    annotations=tool_spec.annotations,
                    auth=auth,
                )
                tool.parameters = tool_spec.input_schema
                tool.output_schema = tool_spec.output_schema
                mcp.add_tool(tool)
            else:
                mcp.tool(
                    tool_spec.fn,
                    name=tool_spec.name,
                    tags={tool_spec.tag},
                    annotations=tool_spec.annotations,
                    output_schema=tool_spec.output_schema,
                    auth=auth,
                )

    for resource_spec in RESOURCES:
        if not spec_survives(resource_spec, settings):
            continue
        mcp.resource(
            resource_spec.uri,
            name=resource_spec.name,
            tags={resource_spec.tag},
            auth=_component_auth(resource_spec, auth_provider),
        )(resource_spec.fn)

    for prompt_spec in PROMPTS:
        if not spec_survives(prompt_spec, settings):
            continue
        mcp.prompt(
            prompt_spec.fn,
            name=prompt_spec.name,
            tags={prompt_spec.tag},
            auth=_component_auth(prompt_spec, auth_provider),
        )

    return mcp


__all__ = ["spec_survives", "build_server", "PROFILE_DESCRIPTIONS"]

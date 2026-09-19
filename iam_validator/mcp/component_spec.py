"""Declarative gating specs shared by tools, resources, and prompts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp.types import ToolAnnotations


@dataclass(frozen=True, kw_only=True)
class ComponentSpec:
    """Gating metadata shared by tools, resources, and prompts."""

    tag: str
    modes: frozenset[str] = field(default_factory=lambda: frozenset({"local", "hosted"}))
    transports: frozenset[str] = field(default_factory=lambda: frozenset({"stdio", "http"}))
    scopes: frozenset[str] = frozenset()
    mutating: bool = False


@dataclass(frozen=True, kw_only=True)
class ToolSpec(ComponentSpec):
    """A gated MCP tool: the callable plus its registration metadata."""

    name: str
    fn: Callable[..., Any]
    annotations: ToolAnnotations
    output_schema: dict[str, Any]


@dataclass(frozen=True, kw_only=True)
class ResourceSpec(ComponentSpec):
    """A gated MCP resource: the callable plus its URI template."""

    uri: str
    name: str
    fn: Callable[..., Any]


@dataclass(frozen=True, kw_only=True)
class PromptSpec(ComponentSpec):
    """A gated MCP prompt: the callable plus its registration name."""

    name: str
    fn: Callable[..., Any]


__all__ = ["ComponentSpec", "ToolSpec", "ResourceSpec", "PromptSpec"]

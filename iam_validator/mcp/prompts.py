"""Declarative MCP prompt specs, gated the same way tools are."""

from __future__ import annotations

from iam_validator.mcp.component_spec import PromptSpec

PROMPTS: list[PromptSpec] = []

__all__ = ["PROMPTS"]

"""Declarative ``iam://`` resource specs, gated the same way tools are."""

from __future__ import annotations

from iam_validator.mcp.component_spec import ResourceSpec

RESOURCES: list[ResourceSpec] = []

__all__ = ["RESOURCES"]

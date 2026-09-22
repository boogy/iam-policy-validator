"""Consolidated check-catalog tool for the MCP server.

Absorbs the former ``get_issue_guidance`` tool. Sensitive-action classification
was already absorbed into ``query``'s ``action_details`` kind; the
per-action condition-requirement lookup is superseded by each check's
resolved ``config`` field below (see ``describe_checks``), so no separate
``get_required_conditions``-style tool is needed.
"""

from __future__ import annotations

import inspect
import sys
from typing import Any

from fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from iam_validator.core.check_registry import create_default_registry
from iam_validator.mcp.component_spec import ToolSpec, infer_output_schema
from iam_validator.mcp.context import effective_check_settings, get_active_config, get_server_context

# -OO/PYTHONOPTIMIZE=2 strips class docstrings, which describe_checks below reads via
# inspect.getdoc(); that would silently return blank `docstring` fields instead of
# failing loudly. -O (level 1) only strips `assert` and is unaffected.
if sys.flags.optimize >= 2:
    raise RuntimeError(
        "iam-validator-mcp cannot run under -OO/PYTHONOPTIMIZE=2: check docstrings "
        "consumed by describe_checks would be silently stripped."
    )


class CheckDescription(BaseModel):
    """One check's static metadata plus what the active config resolves it to."""

    check_id: str
    description: str
    default_severity: str
    docstring: str | None = None
    applies_to_policy_types: list[str] | None = None
    supersedes: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool
    severity: str
    source: str


class DescribeChecksResponse(BaseModel):
    """Response of the consolidated ``describe_checks`` tool."""

    checks: list[CheckDescription]


async def describe_checks(check_ids: list[str] | None = None, ctx: Context = None) -> dict[str, Any]:
    """Describe validation checks: docs, metadata, and the active config's resolution.

    Consolidates the former get_issue_guidance tool. Each entry's `config`
    field carries the check's fully-resolved options from the active config
    (e.g. action_condition_enforcement's `requirements` list) minus
    enabled/severity, which are reported separately.

    Args:
        check_ids: Restrict the result to these check ids. None (default)
            returns every registered check.

    Returns:
        {"checks": [...]} — see each entry's fields above.
    """
    context = get_server_context(ctx)
    registry = context.registry if context is not None else create_default_registry()
    active_config = get_active_config(ctx)

    checks = registry.get_all_checks()
    if check_ids is not None:
        wanted = set(check_ids)
        checks = [c for c in checks if c.check_id in wanted]

    entries: list[CheckDescription] = []
    for check in sorted(checks, key=lambda c: c.check_id):
        enabled, severity = effective_check_settings(check.check_id, check.default_severity, ctx)
        resolved_config = active_config.get_check_config(check.check_id) if active_config is not None else {}
        entries.append(
            CheckDescription(
                check_id=check.check_id,
                description=check.description,
                default_severity=check.default_severity,
                docstring=inspect.getdoc(type(check)),
                applies_to_policy_types=(
                    sorted(check.applies_to_policy_types) if check.applies_to_policy_types is not None else None
                ),
                supersedes=sorted(check.supersedes),
                config={k: v for k, v in resolved_config.items() if k not in ("enabled", "severity")},
                enabled=enabled,
                severity=severity,
                source=registry.get_source(check.check_id) or "builtin",
            )
        )
    return DescribeChecksResponse(checks=entries).model_dump()


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        tag="validate",
        name="describe_checks",
        fn=describe_checks,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(describe_checks),
    ),
)

__all__ = ["describe_checks", "CheckDescription", "DescribeChecksResponse", "TOOLS"]

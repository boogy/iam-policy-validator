"""Validation tools for MCP server.

This module provides the consolidated ``validate_policies`` MCP tool, which
wraps the core validation SDK (``iam_validator.core.policy_checks``) without
reimplementing it.
"""

import asyncio
import json
from collections import Counter
from typing import Annotated, Any, Literal

import yaml
from fastmcp import Context
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field
from pydantic import ValidationError as PydanticValidationError

from iam_validator.core import constants
from iam_validator.core.formatters.base import get_global_registry
from iam_validator.core.models import IAMPolicy, PolicyType, PolicyValidationResult, ValidationIssue
from iam_validator.core.policy_checks import build_registry
from iam_validator.core.policy_checks import validate_policies as sdk_validate_policies
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.report import ReportGenerator
from iam_validator.mcp.component_spec import ToolSpec, infer_output_schema
from iam_validator.mcp.context import get_server_context
from iam_validator.mcp.settings import ServerSettings
from iam_validator.mcp.tools.query import get_policy_summary


def issue_to_dict(issue: ValidationIssue, *, verbose: bool = False) -> dict[str, Any]:
    """Map a ``ValidationIssue`` to the JSON shape MCP tools return.

    Single source of truth for the verbose-vs-lean projection so every
    validation tool reports identical fields.
    """
    if not verbose:
        return {
            "severity": issue.severity,
            "message": issue.message,
            "suggestion": issue.suggestion,
            "check_id": issue.check_id,
        }
    return {
        "severity": issue.severity,
        "message": issue.message,
        "suggestion": issue.suggestion,
        "example": issue.example,
        "check_id": issue.check_id,
        "statement_index": issue.statement_index,
        "action": issue.action,
        "resource": issue.resource,
        "field_name": issue.field_name,
        "risk_explanation": issue.risk_explanation,
        "documentation_url": issue.documentation_url,
        "remediation_steps": issue.remediation_steps,
    }


# Map canonical PolicyType literals to the short strings this MCP tool
# exposes to callers (kept for API stability).
_POLICY_TYPE_SHORT_FORM: dict[str, str] = {
    "IDENTITY_POLICY": "identity",
    "RESOURCE_POLICY": "resource",
    "TRUST_POLICY": "trust",
    "SERVICE_CONTROL_POLICY": "scp",
    "RESOURCE_CONTROL_POLICY": "rcp",
}
_POLICY_TYPE_LONG_FORM: dict[str, PolicyType] = {short: long for long, short in _POLICY_TYPE_SHORT_FORM.items()}


def _normalize_policy_type(value: str | None, *, label: str) -> PolicyType | None:
    if value is None:
        return None
    normalized = _POLICY_TYPE_LONG_FORM.get(value.lower())
    if normalized is None:
        raise ToolError(f"{label}: invalid policy_type {value!r}. Must be one of: identity, resource, trust, scp, rcp")
    return normalized


# Formatters must be registered on the global FormatterRegistry before the
# format enum below is computed (core/report.py's ReportGenerator does the
# registration as a side effect of construction).
_report_generator = ReportGenerator()
_TERMINAL_FORMATS = constants.TERMINAL_FORMATS
_ALLOWED_FORMATS: tuple[str, ...] = tuple(sorted(set(get_global_registry().list_formatters()) - _TERMINAL_FORMATS))
FormatChoice = Literal[_ALLOWED_FORMATS]  # type: ignore[valid-type]


class PolicyInputObject(BaseModel):
    """The object form of a ``PolicyInput`` batch entry."""

    policy: dict[str, Any] | str
    name: str | None = Field(default=None, description="Opaque label; used only for policy_types: glob matching")
    policy_type: str | None = Field(
        default=None, description="identity|resource|trust|scp|rcp, overrides the run-wide policy_type for this entry"
    )


PolicyInput = Annotated[
    PolicyInputObject | dict[str, Any] | str,
    Field(description="A policy as a dict, a JSON/YAML string, or {policy, name?, policy_type?}"),
]


class PolicyResultEntry(BaseModel):
    """Per-policy result inside a ``validate_policies`` response."""

    name: str | None = None
    is_valid: bool
    fails_policy: bool
    severity_counts: dict[str, int] = Field(default_factory=dict)
    policy_type: str
    policy_type_source: Literal["cli-flag", "config-glob", "auto-detect", "default"]
    issues: list[dict[str, Any]] | None = None
    summary: dict[str, Any] | None = None


class ValidatePoliciesResponse(BaseModel):
    """Response of the consolidated ``validate_policies`` tool."""

    results: list[PolicyResultEntry]
    config_digest: str | None = None
    report: str | None = None
    truncated: bool = False
    truncated_count: int = 0


def _parse_policy_text(text: str, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise ToolError(f"{label}: could not parse policy text as JSON or YAML: {e}") from e
    if not isinstance(parsed, dict):
        raise ToolError(f"{label}: parsed policy text is not a JSON/YAML object")
    return parsed


def _split_policy_input(entry: Any, label: str) -> tuple[dict[str, Any], str | None, str | None]:
    """Split one ``PolicyInput`` into (raw_policy_dict, name, per_entry_policy_type)."""
    name: str | None = None
    entry_policy_type: str | None = None
    raw_source: Any = entry

    if isinstance(entry, PolicyInputObject):
        raw_source = entry.policy
        name = entry.name
        entry_policy_type = entry.policy_type
    elif isinstance(entry, dict) and "policy" in entry:
        raw_source = entry["policy"]
        name = entry.get("name")
        entry_policy_type = entry.get("policy_type")

    if isinstance(raw_source, str):
        raw_dict = _parse_policy_text(raw_source, label)
    elif isinstance(raw_source, dict):
        raw_dict = raw_source
    else:
        raise ToolError(f"{label}: policy must be a dict, a JSON/YAML string, or an object with a 'policy' field")

    return raw_dict, name, entry_policy_type


def _resolve_entry_policy_type(
    iam_policy: IAMPolicy,
    name: str | None,
    entry_policy_type: str | None,
    run_policy_type: str | None,
    config: Any,
    label: str,
) -> tuple[PolicyType, str]:
    """Per-entry resolution: entry override > run-wide override > config-glob(name) > auto-detect > default."""
    normalized_entry = _normalize_policy_type(entry_policy_type, label=label)
    if normalized_entry is not None:
        return normalized_entry, "cli-flag"

    normalized_run = _normalize_policy_type(run_policy_type, label=label)
    if normalized_run is not None:
        return normalized_run, "cli-flag"

    if name:
        glob_type = config.get_policy_type_for_path(name)
        if glob_type is not None:
            return glob_type, "config-glob"

    from iam_validator.checks.policy_structure import detect_policy_type

    detected = detect_policy_type(iam_policy)
    if detected != "IDENTITY_POLICY":
        return detected, "auto-detect"
    return "IDENTITY_POLICY", "default"


def _parse_iam_policy(raw_dict: dict[str, Any], label: str) -> IAMPolicy:
    try:
        return IAMPolicy(**raw_dict)
    except PydanticValidationError as e:
        raise ToolError(
            f"{label}: Malformed IAM policy: {e.error_count()} validation error(s). "
            "First error: " + (e.errors()[0].get("msg", "unknown") if e.errors() else "unknown")
        ) from e
    except (TypeError, ValueError) as e:
        raise ToolError(f"{label}: Malformed IAM policy: {e}") from e


def _entry_byte_size(raw_dict: dict[str, Any]) -> int:
    return len(json.dumps(raw_dict, default=str).encode())


class _RunContext:
    __slots__ = ("config", "registry", "settings", "formatters", "config_digest")

    def __init__(
        self,
        config: Any,
        registry: Any,
        settings: ServerSettings,
        formatters: ReportGenerator,
        config_digest: str | None,
    ) -> None:
        self.config = config
        self.registry = registry
        self.settings = settings
        self.formatters = formatters
        self.config_digest = config_digest


def _resolve_run_context(ctx: Any) -> _RunContext:
    context = get_server_context(ctx)
    if context is not None:
        session_config = context.mutable.get_config() if context.mutable is not None else None
        if session_config is not None:
            from iam_validator.core.policy_checks import overlay_registry_config

            registry = overlay_registry_config(context.registry, session_config)
            return _RunContext(session_config, registry, context.settings, context.formatters, context.config_digest)
        return _RunContext(
            context.config, context.registry, context.settings, context.formatters, context.config_digest
        )

    from iam_validator.core.config.config_loader import ConfigLoader

    config = ConfigLoader.load_config(allow_missing=True)
    registry = build_registry(config)
    return _RunContext(config, registry, ServerSettings(), _report_generator, None)


def _build_entry_response(
    result: PolicyValidationResult,
    raw_dict: dict[str, Any],
    name: str | None,
    resolved_type: PolicyType,
    source: str,
    detail: str,
) -> PolicyResultEntry:
    severity_counts = dict(Counter(issue.severity for issue in result.issues))
    entry = PolicyResultEntry(
        name=name,
        is_valid=result.is_valid,
        fails_policy=not result.is_valid,
        severity_counts=severity_counts,
        policy_type=resolved_type,
        policy_type_source=source,  # type: ignore[arg-type]
    )
    if detail in ("findings", "full"):
        entry.issues = [issue_to_dict(i, verbose=(detail == "full")) for i in result.issues]
    return entry


async def _attach_summaries(entries: list[PolicyResultEntry], raw_dicts: list[dict[str, Any]], detail: str) -> None:
    if detail not in ("summary", "full"):
        return
    for entry, raw_dict in zip(entries, raw_dicts, strict=True):
        summary = await get_policy_summary(raw_dict)
        entry.summary = summary.model_dump()


def _load_path_glob_entries(path: str, glob: str | None) -> list[tuple[dict[str, Any], str, None]]:
    from pathlib import Path as _Path

    loader = PolicyLoader()
    base = _Path(path)
    if glob:
        file_paths: list[_Path] = sorted(p for p in base.glob(glob) if p.is_file())
    else:
        file_paths = sorted(loader._get_policy_files(path))

    entries: list[tuple[dict[str, Any], str, None]] = []
    for file_path in file_paths:
        loaded = loader.load_from_file(str(file_path), return_raw_dict=True, record_size_error=True)
        if loaded is None:
            continue
        _iam_policy, raw_dict = loaded
        entries.append((raw_dict, str(file_path), None))
    return entries


async def _validate_policies_impl(
    policies: list[Any] | None,
    policy_type: str | None,
    detail: str,
    format: str,
    ctx: Any,
    *,
    path: str | None = None,
    glob: str | None = None,
) -> dict[str, Any]:
    if format not in _ALLOWED_FORMATS:
        raise ToolError(f"format: invalid value {format!r}. Must be one of: {', '.join(_ALLOWED_FORMATS)}")
    if detail not in ("summary", "findings", "full"):
        raise ToolError(f"detail: invalid value {detail!r}. Must be one of: summary, findings, full")

    run = _resolve_run_context(ctx)

    raw_entries: list[tuple[dict[str, Any], str | None, str | None]] = []
    if policies:
        if len(policies) > run.settings.max_policies:
            raise ToolError(f"max_policies limit is {run.settings.max_policies}, got {len(policies)} policies")
        for idx, entry in enumerate(policies):
            raw_dict, name, entry_type = _split_policy_input(entry, label=f"policies[{idx}]")
            raw_entries.append((raw_dict, name, entry_type))
    if path is not None:
        raw_entries.extend(_load_path_glob_entries(path, glob))

    if not raw_entries:
        raise ToolError("policies: at least one policy is required (or path in local mode)")

    if len(raw_entries) > run.settings.max_policies:
        raise ToolError(f"max_policies limit is {run.settings.max_policies}, got {len(raw_entries)} policies")

    total_bytes = 0
    for idx, (raw_dict, _name, _etype) in enumerate(raw_entries):
        size = _entry_byte_size(raw_dict)
        if size > run.settings.max_policy_bytes:
            raise ToolError(f"max_policy_bytes limit is {run.settings.max_policy_bytes}, entry {idx} is {size} bytes")
        total_bytes += size
    if total_bytes > run.settings.max_request_bytes:
        raise ToolError(f"max_request_bytes limit is {run.settings.max_request_bytes}, got {total_bytes} bytes")

    async def _do_validate() -> dict[str, Any]:
        parsed: list[tuple[dict[str, Any], str | None, IAMPolicy]] = []
        for idx, (raw_dict, name, _etype) in enumerate(raw_entries):
            parsed.append((raw_dict, name, _parse_iam_policy(raw_dict, label=f"policies[{idx}]")))

        resolved: list[tuple[PolicyType, str]] = []
        for idx, (raw_dict, name, iam_policy) in enumerate(parsed):
            entry_type = raw_entries[idx][2]
            resolved.append(
                _resolve_entry_policy_type(
                    iam_policy, name, entry_type, policy_type, run.config, label=f"policies[{idx}]"
                )
            )

        groups: dict[PolicyType, list[int]] = {}
        for idx, (resolved_type, _source) in enumerate(resolved):
            groups.setdefault(resolved_type, []).append(idx)

        ordered_results: list[PolicyValidationResult | None] = [None] * len(parsed)
        for group_type, indices in groups.items():
            group_items = [(parsed[i][1] or f"policy-{i}", parsed[i][2], parsed[i][0]) for i in indices]
            group_results = await sdk_validate_policies(
                policies=group_items,
                config=run.config,
                registry=run.registry,
                policy_type=group_type,
            )
            for i, result in zip(indices, group_results, strict=True):
                ordered_results[i] = result

        sdk_results = [r for r in ordered_results if r is not None]

        entries = [
            _build_entry_response(result, parsed[i][0], parsed[i][1], resolved[i][0], resolved[i][1], detail)
            for i, result in enumerate(sdk_results)
        ]
        await _attach_summaries(entries, [parsed[i][0] for i in range(len(parsed))], detail)

        response: dict[str, Any] = {
            "results": [e.model_dump() for e in entries],
            "config_digest": run.config_digest,
            "truncated": False,
            "truncated_count": 0,
        }
        if format != "json":
            report = run.formatters.generate_report(results=sdk_results)
            response["report"] = run.formatters.format_report(report, format_id=format)
        return response

    try:
        response = await asyncio.wait_for(_do_validate(), timeout=run.settings.request_timeout_s)
    except TimeoutError as e:
        raise ToolError(
            f"request_timeout_s limit is {run.settings.request_timeout_s}s; validation did not complete in time"
        ) from e

    response = _degrade_if_oversized(response, run.settings.max_response_bytes, detail)
    return response


def _response_size(response: dict[str, Any]) -> int:
    return len(json.dumps(response, default=str).encode())


def _degrade_if_oversized(response: dict[str, Any], max_response_bytes: int, detail: str) -> dict[str, Any]:
    if _response_size(response) <= max_response_bytes:
        return response

    for degraded_detail in ("findings", "summary"):
        if detail == "full" and degraded_detail == "findings":
            for entry in response["results"]:
                entry.pop("summary", None)
        if degraded_detail == "summary":
            for entry in response["results"]:
                entry.pop("issues", None)
                entry.pop("summary", None)
        response["truncated"] = True
        if _response_size(response) <= max_response_bytes:
            return response
        detail = degraded_detail

    omitted = 0
    while response["results"] and _response_size(response) > max_response_bytes:
        response["results"].pop()
        omitted += 1
    response["truncated"] = True
    response["truncated_count"] = omitted
    return response


async def validate_policies(
    policies: list[PolicyInput] | None = None,
    policy_type: str | None = None,
    detail: Literal["summary", "findings", "full"] = "findings",
    format: FormatChoice = "json",  # type: ignore[assignment]
    path: str | None = None,
    glob: str | None = None,
    ctx: Context = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Validate one or more IAM policies (local-mode: also from disk via path/glob).

    Consolidates the former validate_policy, quick_validate, validate_policies_batch,
    validate_with_config, check_org_compliance, and get_policy_summary tools.

    Args:
        policies: Inline policies — each a dict, a JSON/YAML string, or
            {policy, name?, policy_type?}. name is an opaque label used only
            for policy_types: glob matching and echoed back in the result.
            policy_type on an entry overrides the run-wide policy_type below.
        policy_type: identity|resource|trust|scp|rcp applied to every policy
            that doesn't set its own. None resolves per policy via
            policy_types: glob -> content auto-detect -> default.
        detail: "summary" (structural stats, no findings), "findings"
            (default; lean issue list), or "full" (verbose issues + summary).
        format: Report format. "json" returns only structured results; any
            other value additionally renders a "report" string.
        path: Local mode only. Load policies from this file or directory
            instead of (or in addition to) `policies`.
        glob: Local mode only. Restrict `path` (a directory) to files
            matching this glob pattern.

    Returns:
        {results: [...], config_digest, report?, truncated, truncated_count}
    """
    return await _validate_policies_impl(policies, policy_type, detail, format, ctx, path=path, glob=glob)


async def _validate_policies_hosted(
    policies: list[PolicyInput],
    policy_type: str | None = None,
    detail: Literal["summary", "findings", "full"] = "findings",
    format: FormatChoice = "json",  # type: ignore[assignment]
    ctx: Context = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Validate one or more IAM policies. See validate_policies for full docs.

    Hosted mode has no filesystem access, so path/glob are not available here.
    """
    return await _validate_policies_impl(policies, policy_type, detail, format, ctx)


async def get_active_profile(ctx: Context) -> dict[str, Any]:
    """Return the active MCP profile and the tools it currently exposes.

    Useful when a tool you expect is missing — confirms the server profile.
    """
    context = get_server_context(ctx)
    profile = context.settings.profile if context is not None else "full"
    tools = await ctx.fastmcp.list_tools()
    return {
        "profile": profile,
        "tool_count": len(tools),
        "tool_names": sorted(t.name for t in tools),
    }


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        tag="validate",
        name="validate_policies",
        fn=validate_policies,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(validate_policies),
        modes=frozenset({"local"}),
    ),
    ToolSpec(
        tag="validate",
        name="validate_policies",
        fn=_validate_policies_hosted,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(_validate_policies_hosted),
        modes=frozenset({"hosted"}),
    ),
    ToolSpec(
        tag="validate",
        name="get_active_profile",
        fn=get_active_profile,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(get_active_profile),
    ),
)

"""Docs, prompts, and README must never reference a check/formatter/MCP tool id the build doesn't register."""

import re
from pathlib import Path

import pytest

from iam_validator.core.check_registry import create_default_registry
from iam_validator.core.formatters.base import get_global_registry
from iam_validator.sdk import __all__ as _sdk_exports

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

from iam_validator.mcp.build import build_server
from iam_validator.mcp.settings import ServerSettings

REPO_ROOT = Path(__file__).resolve().parents[2]

# Retired MCP tool names with no direct successor of the same name (see iam_validator/mcp/CLAUDE.md's tool table).
_RETIRED_TOOL_NAMES = frozenset(
    {
        "list_templates",
        "generate_policy_from_template",
        "build_minimal_policy",
        "suggest_actions",
        "fix_policy_issues",
        "validate_policy",
        "quick_validate",
        "validate_policies_batch",
        "build_arn",
        "get_required_conditions",
        "check_sensitive_actions",
        "explain_policy",
        "compare_policies",
        "query_actions_batch",
        "check_actions_batch",
        "get_condition_requirements_for_action",
        "get_issue_guidance",
        "set_organization_config",
        "get_organization_config",
        "clear_organization_config",
        "load_organization_config_from_yaml",
        "check_org_compliance",
        "validate_with_config",
        "set_custom_instructions",
        "get_custom_instructions",
        "clear_custom_instructions",
        "list_checks",
        "list_sensitive_actions",
        "get_check_details",
        "query_service_actions",
    }
)

# Only these two mcp/ files are LLM-facing prose; other .py files reuse retired names as internal helpers.
_MCP_PROSE_FILES = (
    REPO_ROOT / "iam_validator" / "mcp" / "prompts.py",
    REPO_ROOT / "iam_validator" / "mcp" / "instructions.py",
)

# These document the same functions as SDK exports (test_tool_provenance.py), distinct from the MCP tool surface.
_EXCLUDED_DOC_DIRS = (
    REPO_ROOT / "docs" / "api-reference",
    REPO_ROOT / "docs" / "developer-guide" / "sdk",
)

_FORMAT_FLAG_RE = re.compile(r"iam-validator (?:validate|analyze)\b[^\n`]*--format\s+([a-z][a-z0-9_]*)")
_YAML_CHECK_STANZA_RE = re.compile(
    r"^([a-z][a-z0-9_]+):\s*$\n(?:^\s+#.*$\n)*^\s+(?:enabled|severity|message|suggestion):",
    re.MULTILINE,
)


def _doc_files() -> list[Path]:
    files = [
        p for p in sorted((REPO_ROOT / "docs").rglob("*.md")) if not any(_is_within(p, d) for d in _EXCLUDED_DOC_DIRS)
    ]
    files.append(REPO_ROOT / "README.md")
    return files


def _is_within(path: Path, directory: Path) -> bool:
    return directory in path.parents


def _word_boundary_hits(text: str, names: frozenset[str]) -> set[str]:
    pattern = re.compile(r"\b(" + "|".join(re.escape(n) for n in sorted(names)) + r")\b")
    return set(pattern.findall(text))


async def _registered_tool_names() -> set[str]:
    names: set[str] = set()
    for mode, transport in (("local", "stdio"), ("hosted", "http")):
        settings = ServerSettings(mode=mode, transport=transport, auth="none", auth_explicitly_set=(mode == "hosted"))
        mcp = build_server(settings)
        names |= {t.name for t in await mcp.list_tools()}
    return names


class TestNoRetiredToolNameLiterals:
    async def test_no_prompt_or_doc_references_a_retired_tool_name(self):
        live_names = await _registered_tool_names() | set(_sdk_exports)
        dead_names = _RETIRED_TOOL_NAMES - live_names
        assert dead_names, "fixture sanity: expected at least one genuinely retired name"

        hits: dict[str, set[str]] = {}
        for path in (*_MCP_PROSE_FILES, *_doc_files()):
            found = _word_boundary_hits(path.read_text(), dead_names)
            if found:
                hits[str(path.relative_to(REPO_ROOT))] = found

        assert not hits, f"retired MCP tool name(s) referenced as if still callable: {hits}"


class TestNoOrphanedRegistryDrivenLiterals:
    """A documented `--format`/YAML check stanza must name something the current build registers."""

    def test_every_documented_format_flag_names_a_live_formatter(self):
        live_formatters = set(get_global_registry().list_formatters())
        assert live_formatters, "fixture sanity: expected at least one registered formatter"

        hits: dict[str, set[str]] = {}
        for path in _doc_files():
            found = {fmt for fmt in _FORMAT_FLAG_RE.findall(path.read_text()) if fmt not in live_formatters}
            if found:
                hits[str(path.relative_to(REPO_ROOT))] = found

        assert not hits, f"`--format` example names a formatter the build doesn't register: {hits}"

    def test_every_documented_check_config_stanza_names_a_live_check(self):
        live_check_ids = {check.check_id for check in create_default_registry().get_all_checks()}
        assert live_check_ids, "fixture sanity: expected at least one registered check"

        hits: dict[str, set[str]] = {}
        for path in _doc_files():
            found = {cid for cid in _YAML_CHECK_STANZA_RE.findall(path.read_text()) if cid not in live_check_ids}
            if found:
                hits[str(path.relative_to(REPO_ROOT))] = found

        assert not hits, f"documented check config stanza names a check the build doesn't register: {hits}"

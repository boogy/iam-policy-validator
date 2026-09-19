"""Profile-gating tests: server.py's live tool catalog + spec_survives() semantics."""

import pytest
from mcp.types import ToolAnnotations
from pydantic import ValidationError

from iam_validator.mcp.build import spec_survives
from iam_validator.mcp.component_spec import ToolSpec
from iam_validator.mcp.server import get_active_profile, mcp, set_active_profile
from iam_validator.mcp.settings import ServerSettings


def _tool_spec(tag: str, mutating: bool = False) -> ToolSpec:
    return ToolSpec(
        tag=tag,
        name=f"fixture_{tag}",
        fn=lambda: None,
        annotations=ToolAnnotations(readOnlyHint=not mutating),
        output_schema={"type": "object"},
        mutating=mutating,
    )


async def test_list_checks_demoted_to_resource_not_tool():
    """list_checks must not appear as a tool — only as iam://checks resource."""
    enabled = await mcp.list_tools()
    names = {t.name for t in enabled}
    assert "list_checks" not in names
    assert "list_sensitive_actions" not in names
    assert "get_check_details" not in names


async def test_get_active_profile_reflects_state():
    set_active_profile("validate-only")
    result = await get_active_profile()
    assert result["profile"] == "validate-only"
    assert "validate_policy" in result["tool_names"]
    set_active_profile("full")


def test_unknown_profile_rejected_by_settings():
    with pytest.raises(ValidationError):
        ServerSettings(profile="bogus")


class TestSpecSurvivesProfileSemantics:
    """Profile filtering, re-expressed against spec_survives() with fixture specs
    now that the old decorator-driven gating mechanism is gone.
    """

    def test_validate_and_query_profile_includes_only_those_tags(self):
        settings = ServerSettings(profile="validate-and-query")
        assert spec_survives(_tool_spec("validate"), settings) is True
        assert spec_survives(_tool_spec("query"), settings) is True
        assert spec_survives(_tool_spec("fix"), settings) is False
        assert spec_survives(_tool_spec("analyze"), settings) is False

    def test_validate_only_profile_includes_only_validate_tag(self):
        settings = ServerSettings(profile="validate-only")
        assert spec_survives(_tool_spec("validate"), settings) is True
        assert spec_survives(_tool_spec("query"), settings) is False
        assert spec_survives(_tool_spec("fix"), settings) is False
        assert spec_survives(_tool_spec("orgconfig"), settings) is False
        assert spec_survives(_tool_spec("analyze"), settings) is False

    def test_read_only_profile_excludes_mutating_regardless_of_tag(self):
        settings = ServerSettings(profile="read-only")
        assert spec_survives(_tool_spec("orgconfig", mutating=True), settings) is False
        assert spec_survives(_tool_spec("orgconfig", mutating=False), settings) is True
        assert spec_survives(_tool_spec("validate"), settings) is True

    def test_full_profile_includes_every_tag_and_mutating_specs(self):
        settings = ServerSettings(profile="full")
        for tag in ("validate", "query", "fix", "orgconfig", "analyze"):
            assert spec_survives(_tool_spec(tag), settings) is True
        assert spec_survives(_tool_spec("orgconfig", mutating=True), settings) is True

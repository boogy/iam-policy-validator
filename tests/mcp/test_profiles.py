"""Tag-based ``--profile`` gating tests for the MCP server."""

import pytest

from iam_validator.mcp.server import (
    apply_profile,
    get_active_profile,
    mcp,
    set_active_profile,
)


@pytest.fixture(autouse=True)
def _reset_profile():
    """Each test starts and ends with the full profile so state never leaks."""
    apply_profile("full")
    set_active_profile("full")
    yield
    apply_profile("full")
    set_active_profile("full")


async def test_validate_only_profile_hides_generation_tools():
    apply_profile("validate-only")
    enabled = await mcp.list_tools()
    names = {t.name for t in enabled}
    assert "validate_policy" in names
    assert "generate_policy_from_template" not in names
    assert "build_minimal_policy" not in names


async def test_validate_and_query_profile_includes_query_tools():
    apply_profile("validate-and-query")
    enabled = await mcp.list_tools()
    names = {t.name for t in enabled}
    assert "validate_policy" in names
    assert "query_action_details" in names
    assert "generate_policy_from_template" not in names
    # analyze tag is separate
    assert "aws_access_analyzer_validate" not in names


async def test_no_generation_profile():
    apply_profile("no-generation")
    enabled = await mcp.list_tools()
    names = {t.name for t in enabled}
    assert "validate_policy" in names
    assert "generate_policy_from_template" not in names
    assert "fix_policy_issues" in names  # `fix` tag preserved


async def test_read_only_profile_hides_destructive_tools():
    apply_profile("read-only")
    enabled = await mcp.list_tools()
    names = {t.name for t in enabled}
    # Mutating tools must be gone
    assert "set_organization_config" not in names
    assert "set_custom_instructions" not in names
    assert "clear_organization_config" not in names
    assert "load_organization_config_from_yaml" not in names
    # Read tools must still be available
    assert "validate_policy" in names
    assert "get_organization_config" in names


async def test_full_profile_restores_everything_after_validate_only():
    apply_profile("validate-only")
    apply_profile("full")
    enabled = await mcp.list_tools()
    names = {t.name for t in enabled}
    assert "generate_policy_from_template" in names
    assert "build_minimal_policy" in names
    assert "set_organization_config" in names


async def test_apply_profile_is_not_an_mcp_tool():
    """Internal helper must not leak into the tool catalog."""
    enabled = await mcp.list_tools()
    names = {t.name for t in enabled}
    assert "apply_profile" not in names
    assert "set_active_profile" not in names


async def test_get_active_profile_reflects_state():
    apply_profile("validate-only")
    set_active_profile("validate-only")
    result = await get_active_profile()
    assert result["profile"] == "validate-only"
    assert "validate_policy" in result["tool_names"]


def test_unknown_profile_raises():
    with pytest.raises(ValueError, match="Unknown profile"):
        apply_profile("bogus")


async def test_list_checks_demoted_to_resource_not_tool():
    """list_checks must not appear as a tool — only as iam://checks resource."""
    enabled = await mcp.list_tools()
    names = {t.name for t in enabled}
    assert "list_checks" not in names
    assert "list_templates" not in names
    assert "list_sensitive_actions" not in names
    assert "get_check_details" not in names

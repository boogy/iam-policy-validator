"""Ensure every registered check has a useful get_issue_guidance response."""

import pytest

from iam_validator.core.check_registry import create_default_registry
from iam_validator.mcp.server import get_check_details, get_issue_guidance


async def test_every_registered_check_has_complete_guidance():
    """get_issue_guidance must return non-empty fields for every registered check."""
    registry = create_default_registry()
    incomplete: dict[str, list[str]] = {}
    for check in registry.get_all_checks():
        result = await get_issue_guidance(check.check_id)
        missing: list[str] = []
        if not result.get("description"):
            missing.append("description")
        if result.get("default_severity") is None:
            missing.append("default_severity")
        if not result.get("fix_steps"):
            missing.append("fix_steps")
        if not result.get("related"):
            missing.append("related")
        if missing:
            incomplete[check.check_id] = missing
    assert not incomplete, f"Incomplete guidance: {incomplete}"


async def test_unknown_check_returns_fallback():
    """The check_id-not-registered path must emit the catalogue pointer."""
    result = await get_issue_guidance("nonexistent_check_xyz")
    assert result["description"].startswith("Unknown check")
    assert "iam://checks" in result["related"]


async def test_curated_examples_use_correct_key():
    """Regression: ensure 'related' key is read (not 'related_tools')."""
    result = await get_issue_guidance("wildcard_action")
    assert result["related"] == [
        "suggest_actions",
        "query_service_actions",
        "iam://templates",
    ]


async def test_get_check_details_for_registered_check():
    """get_check_details returns description and severity from the registry."""
    result = await get_check_details("wildcard_action")
    assert result["check_id"] == "wildcard_action"
    assert result["description"]
    assert result["default_severity"] is not None
    assert result["example_violation"] == {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*",
    }


async def test_get_check_details_for_unknown_check():
    """Unknown check returns shape-stable response with description='Check not found'."""
    result = await get_check_details("nonexistent_check_xyz")
    assert result["description"] == "Check not found"
    assert result["default_severity"] is None
    assert result["example_violation"] is None


@pytest.mark.parametrize(
    "check_id",
    [
        "wildcard_action",
        "wildcard_resource",
        "full_wildcard",
        "service_wildcard",
        "sensitive_action",
        "action_validation",
        "policy_structure",
        "action_condition_enforcement",
        "not_action_not_resource",
        "sid_uniqueness",
        "principal_validation",
        "trust_policy_validation",
    ],
)
async def test_curated_entry_returns_example_pair(check_id: str):
    """All 12 curated entries must surface example_before AND example_after."""
    result = await get_issue_guidance(check_id)
    assert result["example_before"] is not None, f"missing example_before for {check_id}"
    assert result["example_after"] is not None, f"missing example_after for {check_id}"

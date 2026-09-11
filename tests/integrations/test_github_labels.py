"""Tests for the GitHub label endpoints.

Label removal puts the label name in the URL path. httpx only escapes
spaces, so an unencoded name containing "/", "#", "%" or "+" produced a
wrong path and the delete silently 404'd — while ``add_labels`` (a JSON
body) kept working, so labels could be added but never removed.
"""

from unittest.mock import AsyncMock, patch

import pytest

from iam_validator.integrations.github_integration import GitHubIntegration


@pytest.fixture
def github():
    with patch.dict(
        "os.environ",
        {
            "GITHUB_TOKEN": "ghp_" + "x" * 36,
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_PR_NUMBER": "42",
        },
        clear=False,
    ):
        integration = GitHubIntegration()
    assert integration.is_configured()
    return integration


@pytest.mark.parametrize(
    ("label", "expected_segment"),
    [
        ("iam-validity-error", "iam-validity-error"),
        ("needs review", "needs%20review"),
        ("iam/critical", "iam%2Fcritical"),
        ("bug#1", "bug%231"),
        ("100% done", "100%25%20done"),
        ("c++", "c%2B%2B"),
        ("security: critical", "security%3A%20critical"),
    ],
)
@pytest.mark.asyncio
async def test_remove_label_percent_encodes_name(github, label, expected_segment):
    """Every character that is unsafe in a path segment must be encoded."""
    with patch.object(github, "_make_request", new=AsyncMock(return_value={})) as request:
        assert await github.remove_label(label) is True

    request.assert_awaited_once_with("DELETE", f"issues/42/labels/{expected_segment}")


@pytest.mark.asyncio
async def test_remove_label_reports_failure(github):
    """A failed delete must not be reported as a successful removal."""
    with patch.object(github, "_make_request", new=AsyncMock(return_value=None)):
        assert await github.remove_label("iam/critical") is False


@pytest.mark.asyncio
async def test_get_labels_is_paginated(github):
    """Labels must be read through pagination, not a single 30-item page."""
    page = [{"name": f"label-{i}"} for i in range(45)]
    with patch.object(github, "_make_paginated_request", new=AsyncMock(return_value=page)) as request:
        labels = await github.get_labels()

    request.assert_awaited_once_with("issues/42/labels")
    assert len(labels) == 45
    assert labels[-1] == "label-44"


@pytest.mark.asyncio
async def test_get_labels_skips_malformed_entries(github):
    """Entries without a string name are ignored rather than crashing."""
    with patch.object(
        github,
        "_make_paginated_request",
        new=AsyncMock(return_value=[{"name": "ok"}, {"color": "red"}, {"name": 5}, "junk"]),
    ):
        assert await github.get_labels() == ["ok"]

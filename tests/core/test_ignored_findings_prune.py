"""Tests for pruning ignore records whose findings are no longer reported.

Ignore records used to outlive the findings they silenced: nothing removed
them when the policy was fixed, so the PR summary kept reporting an
"Ignored Findings" count and table for issues that no longer existed.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.constants import IGNORED_FINDINGS_IDENTIFIER
from iam_validator.core.ignored_findings import IgnoredFindingsStore


def storage_comment(*findings: dict) -> list[dict]:
    """Build a PR comment list containing the ignore storage comment."""
    payload = json.dumps({"version": 1, "ignored_findings": list(findings)})
    return [
        {
            "id": 999,
            "body": f"{IGNORED_FINDINGS_IDENTIFIER}\n\n```json\n{payload}\n```\n",
        }
    ]


def record(finding_id: str, file_path: str) -> dict:
    return {
        "finding_id": finding_id,
        "file_path": file_path,
        "check_id": "sensitive_action",
        "issue_type": "sensitive_action",
        "ignored_by": "owner",
        "ignored_at": "2024-01-15T10:30:00Z",
        "reason": "approved",
    }


@pytest.fixture
def mock_github():
    github = MagicMock()
    github.post_comment = AsyncMock(return_value=True)
    github._update_comment = AsyncMock(return_value=True)
    github.get_issue_comments = AsyncMock(return_value=[])
    return github


@pytest.mark.asyncio
async def test_prunes_record_for_resolved_finding(mock_github):
    """A record for a validated file with no matching finding is dropped."""
    mock_github.get_issue_comments = AsyncMock(return_value=storage_comment(record("a1b2c3d4e5f60718", "policy.json")))
    store = IgnoredFindingsStore(mock_github)

    pruned = await store.prune_resolved(frozenset(), {"policy.json"})

    assert pruned == 1
    assert await store.load() == {}
    mock_github._update_comment.assert_awaited_once()


@pytest.mark.asyncio
async def test_keeps_record_while_finding_is_still_reported(mock_github):
    """An ignored finding that is still reported keeps its record."""
    mock_github.get_issue_comments = AsyncMock(return_value=storage_comment(record("a1b2c3d4e5f60718", "policy.json")))
    store = IgnoredFindingsStore(mock_github)

    pruned = await store.prune_resolved(frozenset({"a1b2c3d4e5f60718"}), {"policy.json"})

    assert pruned == 0
    assert "a1b2c3d4e5f60718" in await store.load()
    mock_github._update_comment.assert_not_awaited()


@pytest.mark.asyncio
async def test_keeps_records_for_files_this_run_did_not_validate(mock_github):
    """A partial run must not discard ignores it has no evidence about."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=storage_comment(
            record("a1b2c3d4e5f60718", "validated.json"),
            record("0918273645aabbcc", "untouched.json"),
        )
    )
    store = IgnoredFindingsStore(mock_github)

    pruned = await store.prune_resolved(frozenset(), {"validated.json"})

    assert pruned == 1
    remaining = await store.load()
    assert "0918273645aabbcc" in remaining
    assert "a1b2c3d4e5f60718" not in remaining


@pytest.mark.asyncio
async def test_no_validated_files_is_a_noop(mock_github):
    """With nothing validated there is no evidence to prune on."""
    mock_github.get_issue_comments = AsyncMock(return_value=storage_comment(record("a1b2c3d4e5f60718", "policy.json")))
    store = IgnoredFindingsStore(mock_github)

    pruned = await store.prune_resolved(frozenset(), set())

    assert pruned == 0
    mock_github._update_comment.assert_not_awaited()


@pytest.mark.asyncio
async def test_failed_save_reports_nothing_pruned(mock_github):
    """A failed storage update must not be reported as a successful prune."""
    mock_github.get_issue_comments = AsyncMock(return_value=storage_comment(record("a1b2c3d4e5f60718", "policy.json")))
    mock_github._update_comment = AsyncMock(return_value=False)
    store = IgnoredFindingsStore(mock_github)

    pruned = await store.prune_resolved(frozenset(), {"policy.json"})

    assert pruned == 0
    # The record is still in GitHub, so it must still be in the store.
    assert "a1b2c3d4e5f60718" in await store.load()


@pytest.mark.asyncio
async def test_empty_store_never_creates_a_storage_comment(mock_github):
    """Pruning an empty store must not post a new storage comment."""
    store = IgnoredFindingsStore(mock_github)

    pruned = await store.prune_resolved(frozenset(), {"policy.json"})

    assert pruned == 0
    mock_github.post_comment.assert_not_awaited()
    mock_github._update_comment.assert_not_awaited()

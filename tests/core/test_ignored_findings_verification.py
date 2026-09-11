"""Tests for tamper verification of ignore records.

An ignore is trusted because an authorized user asked for it in a specific
reply comment. Verification re-checks that the reply still exists and is
still theirs, so a hand-edited storage comment cannot silence findings on
someone else's authority.

The two hazards this pins down: verification must cost no per-record API
calls, and an unavailable comment listing must never be read as "every
reply was deleted".
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.constants import IGNORED_FINDINGS_IDENTIFIER
from iam_validator.core.ignored_findings import IgnoredFindingsStore

OWNER = "code-owner"


def storage_comment(*findings: dict) -> list[dict]:
    payload = json.dumps({"version": 1, "ignored_findings": list(findings)})
    return [
        {
            "id": 999,
            "body": f"{IGNORED_FINDINGS_IDENTIFIER}\n\n```json\n{payload}\n```\n",
        }
    ]


def record(finding_id: str, *, reply_comment_id: int | None, ignored_by: str = OWNER) -> dict:
    return {
        "finding_id": finding_id,
        "file_path": "policy.json",
        "check_id": "sensitive_action",
        "issue_type": "sensitive_action",
        "ignored_by": ignored_by,
        "ignored_at": "2024-01-15T10:30:00Z",
        "reason": "approved",
        "reply_comment_id": reply_comment_id,
    }


@pytest.fixture
def mock_github():
    github = MagicMock()
    github.post_comment = AsyncMock(return_value=True)
    github._update_comment = AsyncMock(return_value=True)
    github.get_issue_comments = AsyncMock(return_value=[])
    return github


@pytest.mark.asyncio
async def test_keeps_record_whose_reply_still_matches(mock_github):
    mock_github.get_issue_comments = AsyncMock(
        return_value=storage_comment(record("a1b2c3d4e5f60718", reply_comment_id=555))
    )
    store = IgnoredFindingsStore(mock_github)

    removed = await store.remove_invalid_findings({555: OWNER})

    assert removed == 0
    assert "a1b2c3d4e5f60718" in await store.load()
    mock_github._update_comment.assert_not_awaited()


@pytest.mark.asyncio
async def test_author_match_is_case_insensitive(mock_github):
    mock_github.get_issue_comments = AsyncMock(
        return_value=storage_comment(record("a1b2c3d4e5f60718", reply_comment_id=555, ignored_by="Code-Owner"))
    )
    store = IgnoredFindingsStore(mock_github)

    assert await store.remove_invalid_findings({555: "code-owner"}) == 0


@pytest.mark.asyncio
async def test_removes_record_whose_reply_was_deleted(mock_github):
    """Deleting the "ignore" reply revokes the ignore."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=storage_comment(record("a1b2c3d4e5f60718", reply_comment_id=555))
    )
    store = IgnoredFindingsStore(mock_github)

    removed = await store.remove_invalid_findings({777: OWNER})

    assert removed == 1
    assert await store.load() == {}


@pytest.mark.asyncio
async def test_removes_forged_author(mock_github):
    """A hand-edited ignored_by no longer buys anything."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=storage_comment(record("a1b2c3d4e5f60718", reply_comment_id=555, ignored_by="attacker"))
    )
    store = IgnoredFindingsStore(mock_github)

    removed = await store.remove_invalid_findings({555: OWNER})

    assert removed == 1
    assert await store.load() == {}


@pytest.mark.asyncio
async def test_legacy_record_without_reply_id_is_left_alone(mock_github):
    """Records predating reply tracking have nothing to verify against."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=storage_comment(record("a1b2c3d4e5f60718", reply_comment_id=None))
    )
    store = IgnoredFindingsStore(mock_github)

    assert await store.remove_invalid_findings({}) == 0
    assert "a1b2c3d4e5f60718" in await store.load()


@pytest.mark.asyncio
async def test_unavailable_listing_never_revokes_anything(mock_github):
    """None means "unknown", not "every reply was deleted"."""
    mock_github.get_issue_comments = AsyncMock(
        return_value=storage_comment(
            record("a1b2c3d4e5f60718", reply_comment_id=555),
            record("0918273645aabbcc", reply_comment_id=556),
        )
    )
    store = IgnoredFindingsStore(mock_github)

    removed = await store.remove_invalid_findings(None)

    assert removed == 0
    assert len(await store.load()) == 2
    mock_github._update_comment.assert_not_awaited()


@pytest.mark.asyncio
async def test_verification_costs_no_per_record_api_calls(mock_github):
    """Whatever the record count, verification must not fetch comments."""
    mock_github.get_comment_by_id = AsyncMock(return_value=None)
    mock_github.get_issue_comments = AsyncMock(
        return_value=storage_comment(*[record(f"{i:016x}", reply_comment_id=500 + i) for i in range(50)])
    )
    store = IgnoredFindingsStore(mock_github)

    await store.remove_invalid_findings({500 + i: OWNER for i in range(50)})

    mock_github.get_comment_by_id.assert_not_awaited()


@pytest.mark.asyncio
async def test_failed_save_keeps_records(mock_github):
    mock_github.get_issue_comments = AsyncMock(
        return_value=storage_comment(record("a1b2c3d4e5f60718", reply_comment_id=555))
    )
    mock_github._update_comment = AsyncMock(return_value=False)
    store = IgnoredFindingsStore(mock_github)

    removed = await store.remove_invalid_findings({})

    assert removed == 0
    # Still present in GitHub, so still present in the store.
    assert "a1b2c3d4e5f60718" in await store.load()


@pytest.mark.asyncio
async def test_empty_store_is_a_noop(mock_github):
    store = IgnoredFindingsStore(mock_github)

    assert await store.remove_invalid_findings({}) == 0
    mock_github.post_comment.assert_not_awaited()
    mock_github._update_comment.assert_not_awaited()

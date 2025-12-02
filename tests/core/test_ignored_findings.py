"""Tests for ignored findings storage."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.ignored_findings import (
    STORAGE_VERSION,
    IgnoredFinding,
    IgnoredFindingsStore,
)


class TestIgnoredFinding:
    """Tests for IgnoredFinding dataclass."""

    def test_create_ignored_finding(self):
        """Test creating an ignored finding."""
        finding = IgnoredFinding(
            finding_id="abc123def456",
            file_path="policies/admin.json",
            check_id="sensitive_action",
            issue_type="sensitive_action",
            ignored_by="admin-user",
            ignored_at="2024-01-15T10:30:00Z",
            reason="Approved by security team",
        )

        assert finding.finding_id == "abc123def456"
        assert finding.file_path == "policies/admin.json"
        assert finding.check_id == "sensitive_action"
        assert finding.ignored_by == "admin-user"
        assert finding.reason == "Approved by security team"

    def test_create_finding_without_reason(self):
        """Test creating finding without reason."""
        finding = IgnoredFinding(
            finding_id="abc123",
            file_path="policy.json",
            check_id="test",
            issue_type="test",
            ignored_by="user",
            ignored_at="2024-01-15T10:30:00Z",
        )

        assert finding.reason is None

    def test_from_dict(self):
        """Test creating finding from dictionary."""
        data = {
            "finding_id": "abc123",
            "file_path": "policy.json",
            "check_id": "test",
            "issue_type": "test",
            "ignored_by": "user",
            "ignored_at": "2024-01-15T10:30:00Z",
            "reason": "Test reason",
        }

        finding = IgnoredFinding.from_dict(data)

        assert finding.finding_id == "abc123"
        assert finding.reason == "Test reason"

    def test_from_dict_missing_reason(self):
        """Test creating finding from dict without reason."""
        data = {
            "finding_id": "abc123",
            "file_path": "policy.json",
            "check_id": "test",
            "issue_type": "test",
            "ignored_by": "user",
            "ignored_at": "2024-01-15T10:30:00Z",
        }

        finding = IgnoredFinding.from_dict(data)

        assert finding.reason is None

    def test_to_dict(self):
        """Test converting finding to dictionary."""
        finding = IgnoredFinding(
            finding_id="abc123",
            file_path="policy.json",
            check_id="test",
            issue_type="test",
            ignored_by="user",
            ignored_at="2024-01-15T10:30:00Z",
            reason="Test",
        )

        data = finding.to_dict()

        assert data["finding_id"] == "abc123"
        assert data["file_path"] == "policy.json"
        assert data["reason"] == "Test"


class TestIgnoredFindingsStoreFormat:
    """Tests for storage format methods."""

    @pytest.fixture
    def mock_github(self):
        """Create mock GitHub integration."""
        github = MagicMock()
        github.get_issue_comments = AsyncMock(return_value=[])
        github.post_comment = AsyncMock(return_value=True)
        github._update_comment = AsyncMock(return_value=True)
        return github

    def test_format_comment_empty(self, mock_github):
        """Test formatting empty findings."""
        store = IgnoredFindingsStore(mock_github)
        body = store._format_comment({})

        assert "<!-- iam-policy-validator-ignored-findings -->" in body
        assert "Ignored Findings (0)" in body
        assert '"ignored_findings": []' in body

    def test_format_comment_with_findings(self, mock_github):
        """Test formatting with findings."""
        store = IgnoredFindingsStore(mock_github)
        findings = {
            "abc123": IgnoredFinding(
                finding_id="abc123",
                file_path="policy.json",
                check_id="test",
                issue_type="test",
                ignored_by="user",
                ignored_at="2024-01-15T10:30:00Z",
                reason="Test",
            )
        }

        body = store._format_comment(findings)

        assert "Ignored Findings (1)" in body
        assert '"abc123"' in body
        assert '"ignored_by": "user"' in body

    def test_parse_comment_valid(self, mock_github):
        """Test parsing valid comment."""
        store = IgnoredFindingsStore(mock_github)
        body = """<!-- iam-policy-validator-ignored-findings -->
```json
{
  "version": 1,
  "ignored_findings": [
    {"finding_id": "abc123", "file_path": "p.json", "check_id": "t", "issue_type": "t", "ignored_by": "u", "ignored_at": "2024-01-15T10:30:00Z"}
  ]
}
```
"""
        data = store._parse_comment(body)

        assert data["version"] == 1
        assert len(data["ignored_findings"]) == 1
        assert data["ignored_findings"][0]["finding_id"] == "abc123"

    def test_parse_comment_invalid_json(self, mock_github):
        """Test parsing invalid JSON returns empty structure."""
        store = IgnoredFindingsStore(mock_github)
        body = """<!-- iam-policy-validator-ignored-findings -->
```json
{invalid json}
```
"""
        data = store._parse_comment(body)

        assert data["version"] == STORAGE_VERSION
        assert data["ignored_findings"] == []

    def test_parse_comment_no_json_block(self, mock_github):
        """Test parsing comment without JSON block."""
        store = IgnoredFindingsStore(mock_github)
        body = "<!-- iam-policy-validator-ignored-findings -->"

        data = store._parse_comment(body)

        assert data["version"] == STORAGE_VERSION
        assert data["ignored_findings"] == []


class TestIgnoredFindingsStoreOperations:
    """Tests for store operations."""

    @pytest.fixture
    def mock_github(self):
        """Create mock GitHub integration."""
        github = MagicMock()
        github.get_issue_comments = AsyncMock(return_value=[])
        github.post_comment = AsyncMock(return_value=True)
        github._update_comment = AsyncMock(return_value=True)
        return github

    @pytest.mark.asyncio
    async def test_load_empty(self, mock_github):
        """Test loading when no storage comment exists."""
        store = IgnoredFindingsStore(mock_github)

        findings = await store.load()

        assert findings == {}

    @pytest.mark.asyncio
    async def test_load_with_existing_comment(self, mock_github):
        """Test loading from existing storage comment."""
        mock_github.get_issue_comments = AsyncMock(return_value=[
            {
                "id": 12345,
                "body": """<!-- iam-policy-validator-ignored-findings -->
```json
{
  "version": 1,
  "ignored_findings": [
    {"finding_id": "abc123", "file_path": "p.json", "check_id": "t", "issue_type": "t", "ignored_by": "u", "ignored_at": "2024-01-15T10:30:00Z"}
  ]
}
```
"""
            }
        ])

        store = IgnoredFindingsStore(mock_github)
        findings = await store.load()

        assert "abc123" in findings
        assert findings["abc123"].file_path == "p.json"
        assert store._comment_id == 12345

    @pytest.mark.asyncio
    async def test_is_ignored(self, mock_github):
        """Test checking if finding is ignored."""
        mock_github.get_issue_comments = AsyncMock(return_value=[
            {
                "id": 1,
                "body": """<!-- iam-policy-validator-ignored-findings -->
```json
{
  "version": 1,
  "ignored_findings": [
    {"finding_id": "abc123", "file_path": "p.json", "check_id": "t", "issue_type": "t", "ignored_by": "u", "ignored_at": "2024-01-15T10:30:00Z"}
  ]
}
```
"""
            }
        ])

        store = IgnoredFindingsStore(mock_github)

        assert await store.is_ignored("abc123")
        assert not await store.is_ignored("xyz789")

    @pytest.mark.asyncio
    async def test_get_ignored_ids(self, mock_github):
        """Test getting all ignored IDs as frozenset."""
        mock_github.get_issue_comments = AsyncMock(return_value=[
            {
                "id": 1,
                "body": """<!-- iam-policy-validator-ignored-findings -->
```json
{
  "version": 1,
  "ignored_findings": [
    {"finding_id": "abc", "file_path": "p.json", "check_id": "t", "issue_type": "t", "ignored_by": "u", "ignored_at": "2024-01-15T10:30:00Z"},
    {"finding_id": "def", "file_path": "p.json", "check_id": "t", "issue_type": "t", "ignored_by": "u", "ignored_at": "2024-01-15T10:30:00Z"}
  ]
}
```
"""
            }
        ])

        store = IgnoredFindingsStore(mock_github)
        ignored_ids = await store.get_ignored_ids()

        assert isinstance(ignored_ids, frozenset)
        assert "abc" in ignored_ids
        assert "def" in ignored_ids
        assert len(ignored_ids) == 2

    @pytest.mark.asyncio
    async def test_add_ignored_creates_comment(self, mock_github):
        """Test adding ignored finding creates new comment."""
        store = IgnoredFindingsStore(mock_github)

        finding = IgnoredFinding(
            finding_id="new123",
            file_path="policy.json",
            check_id="test",
            issue_type="test",
            ignored_by="user",
            ignored_at="2024-01-15T10:30:00Z",
        )

        result = await store.add_ignored(finding)

        assert result is True
        mock_github.post_comment.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_ignored_updates_existing(self, mock_github):
        """Test adding to existing findings updates comment."""
        mock_github.get_issue_comments = AsyncMock(return_value=[
            {
                "id": 12345,
                "body": """<!-- iam-policy-validator-ignored-findings -->
```json
{
  "version": 1,
  "ignored_findings": [
    {"finding_id": "existing", "file_path": "p.json", "check_id": "t", "issue_type": "t", "ignored_by": "u", "ignored_at": "2024-01-15T10:30:00Z"}
  ]
}
```
"""
            }
        ])

        store = IgnoredFindingsStore(mock_github)
        await store.load()  # Load existing

        finding = IgnoredFinding(
            finding_id="new123",
            file_path="policy.json",
            check_id="test",
            issue_type="test",
            ignored_by="user",
            ignored_at="2024-01-15T10:30:00Z",
        )

        result = await store.add_ignored(finding)

        assert result is True
        mock_github._update_comment.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_invalidation(self, mock_github):
        """Test cache invalidation."""
        store = IgnoredFindingsStore(mock_github)
        store._cache = {"abc": MagicMock()}
        store._comment_id = 123

        store.invalidate_cache()

        assert store._cache is None
        assert store._comment_id is None

    @pytest.mark.asyncio
    async def test_remove_ignored(self, mock_github):
        """Test removing an ignored finding."""
        mock_github.get_issue_comments = AsyncMock(return_value=[
            {
                "id": 12345,
                "body": """<!-- iam-policy-validator-ignored-findings -->
```json
{
  "version": 1,
  "ignored_findings": [
    {"finding_id": "to_remove", "file_path": "p.json", "check_id": "t", "issue_type": "t", "ignored_by": "u", "ignored_at": "2024-01-15T10:30:00Z"},
    {"finding_id": "keep", "file_path": "p.json", "check_id": "t", "issue_type": "t", "ignored_by": "u", "ignored_at": "2024-01-15T10:30:00Z"}
  ]
}
```
"""
            }
        ])

        store = IgnoredFindingsStore(mock_github)
        result = await store.remove_ignored("to_remove")

        assert result is True
        mock_github._update_comment.assert_called_once()
        assert store._cache is not None
        assert "to_remove" not in store._cache
        assert "keep" in store._cache

    @pytest.mark.asyncio
    async def test_remove_nonexistent(self, mock_github):
        """Test removing non-existent finding returns False."""
        store = IgnoredFindingsStore(mock_github)

        result = await store.remove_ignored("nonexistent")

        assert result is False

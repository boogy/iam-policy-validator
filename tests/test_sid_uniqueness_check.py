"""Tests for SID uniqueness check."""

import pytest

from iam_validator.checks.sid_uniqueness import SidUniquenessCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement


class TestSidUniquenessCheck:
    """Test suite for SidUniquenessCheck."""

    @pytest.fixture
    def check(self):
        """Create a SidUniquenessCheck instance."""
        return SidUniquenessCheck()

    @pytest.fixture
    def fetcher(self):
        """Create a mock AWSServiceFetcher instance."""
        return AWSServiceFetcher()

    @pytest.fixture
    def config(self):
        """Create a default CheckConfig."""
        return CheckConfig(check_id="sid_uniqueness")

    def test_check_id(self, check):
        """Test check_id property."""
        assert check.check_id == "sid_uniqueness"

    def test_description(self, check):
        """Test description property."""
        assert "unique" in check.description.lower()

    def test_default_severity(self, check):
        """Test default_severity property."""
        assert check.default_severity == "warning"

    @pytest.mark.asyncio
    async def test_execute_returns_empty(self, check, fetcher, config):
        """Test that statement-level execute returns empty list."""
        statement = Statement(
            Sid="TestSid", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_unique_sids(self, check, fetcher, config):
        """Test policy with all unique SIDs."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Sid="First", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(
                    Sid="Second",
                    Effect="Allow",
                    Action=["s3:PutObject"],
                    Resource=["*"],
                ),
                Statement(
                    Sid="Third",
                    Effect="Allow",
                    Action=["s3:DeleteObject"],
                    Resource=["*"],
                ),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_duplicate_sid_two_occurrences(self, check, fetcher, config):
        """Test duplicate SID with two occurrences."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="DuplicateSid",
                    Effect="Allow",
                    Action=["s3:GetObject"],
                    Resource=["*"],
                ),
                Statement(
                    Sid="DuplicateSid",
                    Effect="Allow",
                    Action=["s3:PutObject"],
                    Resource=["*"],
                ),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "warning"
        assert issues[0].issue_type == "duplicate_sid"
        assert issues[0].statement_sid == "DuplicateSid"
        assert issues[0].statement_index == 1  # Second occurrence flagged
        assert "2 times" in issues[0].message

    @pytest.mark.asyncio
    async def test_duplicate_sid_three_occurrences(self, check, fetcher, config):
        """Test duplicate SID with three occurrences."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="TripleSid",
                    Effect="Allow",
                    Action=["s3:GetObject"],
                    Resource=["*"],
                ),
                Statement(
                    Sid="TripleSid",
                    Effect="Allow",
                    Action=["s3:PutObject"],
                    Resource=["*"],
                ),
                Statement(
                    Sid="TripleSid",
                    Effect="Allow",
                    Action=["s3:DeleteObject"],
                    Resource=["*"],
                ),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Should report 2 issues (for the 2nd and 3rd occurrences)
        assert len(issues) == 2
        assert all(issue.statement_sid == "TripleSid" for issue in issues)
        assert issues[0].statement_index == 1
        assert issues[1].statement_index == 2
        assert all("3 times" in issue.message for issue in issues)

    @pytest.mark.asyncio
    async def test_multiple_duplicate_sids(self, check, fetcher, config):
        """Test multiple different duplicate SIDs."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Sid="DupA", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(Sid="DupA", Effect="Allow", Action=["s3:PutObject"], Resource=["*"]),
                Statement(
                    Sid="DupB",
                    Effect="Allow",
                    Action=["s3:DeleteObject"],
                    Resource=["*"],
                ),
                Statement(Sid="DupB", Effect="Allow", Action=["s3:ListBucket"], Resource=["*"]),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Should report 2 issues (one for each duplicate)
        assert len(issues) == 2
        duplicate_sids = {issue.statement_sid for issue in issues}
        assert duplicate_sids == {"DupA", "DupB"}

    @pytest.mark.asyncio
    async def test_none_sids_ignored(self, check, fetcher, config):
        """Test that statements without SIDs are ignored."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(Effect="Allow", Action=["s3:PutObject"], Resource=["*"]),
                Statement(
                    Sid="UniqueSid",
                    Effect="Allow",
                    Action=["s3:DeleteObject"],
                    Resource=["*"],
                ),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_mixed_duplicate_and_none_sids(self, check, fetcher, config):
        """Test mix of duplicate SIDs and None SIDs."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="Duplicate",
                    Effect="Allow",
                    Action=["s3:GetObject"],
                    Resource=["*"],
                ),
                Statement(Effect="Allow", Action=["s3:PutObject"], Resource=["*"]),  # No SID
                Statement(
                    Sid="Duplicate",
                    Effect="Allow",
                    Action=["s3:DeleteObject"],
                    Resource=["*"],
                ),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_sid == "Duplicate"

    @pytest.mark.asyncio
    async def test_line_numbers_captured(self, check, fetcher, config):
        """Test that line numbers are captured."""
        stmt1 = Statement(Sid="Dup", Effect="Allow", Action=["s3:GetObject"], Resource=["*"])
        stmt1.line_number = 10

        stmt2 = Statement(Sid="Dup", Effect="Allow", Action=["s3:PutObject"], Resource=["*"])
        stmt2.line_number = 20

        policy = IAMPolicy(Version="2012-10-17", Statement=[stmt1, stmt2])
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        assert len(issues) == 1
        assert issues[0].line_number == 20  # Second occurrence

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity from config."""
        config = CheckConfig(check_id="sid_uniqueness", severity="error")
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Sid="Dup", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(Sid="Dup", Effect="Allow", Action=["s3:PutObject"], Resource=["*"]),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_suggestion_included(self, check, fetcher, config):
        """Test that suggestion is included."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Sid="Dup", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(Sid="Dup", Effect="Allow", Action=["s3:PutObject"], Resource=["*"]),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        assert issues[0].suggestion is not None
        assert "unique" in issues[0].suggestion.lower()

    @pytest.mark.asyncio
    async def test_message_includes_all_indices(self, check, fetcher, config):
        """Test that error message includes all statement indices."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Sid="Dup", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(
                    Sid="Unique",
                    Effect="Allow",
                    Action=["s3:ListBucket"],
                    Resource=["*"],
                ),
                Statement(Sid="Dup", Effect="Allow", Action=["s3:PutObject"], Resource=["*"]),
                Statement(
                    Sid="Dup",
                    Effect="Allow",
                    Action=["s3:DeleteObject"],
                    Resource=["*"],
                ),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Should have 2 issues (for indices 2 and 3)
        assert len(issues) == 2
        # Both should mention all three statement numbers #1, #3, #4 (1-indexed)
        assert all("#1" in issue.message for issue in issues)
        assert all("#3" in issue.message for issue in issues)
        assert all("#4" in issue.message for issue in issues)

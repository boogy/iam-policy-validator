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
        return SidUniquenessCheck()

    @pytest.fixture
    def fetcher(self):
        return AWSServiceFetcher()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="sid_uniqueness")

    @pytest.mark.asyncio
    async def test_unique_sids(self, check, fetcher, config):
        """Test policy with all unique SIDs."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Sid="First", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(Sid="Second", Effect="Allow", Action=["s3:PutObject"], Resource=["*"]),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_duplicate_sid(self, check, fetcher, config):
        """Test duplicate SID detection."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Sid="DuplicateSid", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(Sid="DuplicateSid", Effect="Allow", Action=["s3:PutObject"], Resource=["*"]),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "duplicate_sid"
        assert issues[0].statement_sid == "DuplicateSid"

    @pytest.mark.asyncio
    async def test_multiple_duplicates(self, check, fetcher, config):
        """Test multiple occurrences of the same SID."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Sid="Dup", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(Sid="Dup", Effect="Allow", Action=["s3:PutObject"], Resource=["*"]),
                Statement(Sid="Dup", Effect="Allow", Action=["s3:DeleteObject"], Resource=["*"]),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        # Should report 2 issues (for the 2nd and 3rd occurrences)
        assert len(issues) == 2

    @pytest.mark.asyncio
    async def test_none_sids_ignored(self, check, fetcher, config):
        """Test that statements without SIDs are ignored."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(Effect="Allow", Action=["s3:PutObject"], Resource=["*"]),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 0

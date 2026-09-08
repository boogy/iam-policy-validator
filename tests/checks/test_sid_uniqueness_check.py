"""Tests for SID uniqueness check."""

from pathlib import Path

import pytest

from iam_validator.checks.sid_uniqueness import SidUniquenessCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement
from iam_validator.core.policy_checks import validate_policies


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

    @pytest.mark.asyncio
    async def test_invalid_sid_format_honors_configured_severity(self, check, fetcher):
        """A configured severity override applies to the Sid-format finding, not just duplicates."""
        config = CheckConfig(check_id="sid_uniqueness", severity="warning")
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Sid="bad-sid", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_sid_format"
        assert issues[0].severity == "warning"

    @pytest.mark.asyncio
    async def test_empty_sid_is_reported_as_invalid_format(self, check, fetcher, config):
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Sid="", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_sid_format"
        assert "empty" in issues[0].message

    @pytest.mark.asyncio
    async def test_empty_sids_are_not_counted_as_duplicates(self, check, fetcher, config):
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Sid="", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(Sid="", Effect="Allow", Action=["s3:PutObject"], Resource=["*"]),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        issue_types = [i.issue_type for i in issues]
        assert issue_types.count("invalid_sid_format") == 2
        assert issue_types.count("duplicate_sid") == 0


async def test_malformed_sid_reported_exactly_once():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "my-invalid-sid",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*",
            }
        ],
    }
    results = await validate_policies([("inline.json", IAMPolicy.model_validate(policy), policy)])
    sid_issues = [i for r in results for i in r.issues if i.issue_type == "invalid_sid_format"]

    assert len(sid_issues) == 1
    assert sid_issues[0].severity == "error"


def test_sid_pattern_is_defined_only_in_constants():
    literal = r're.compile(r"^[a-zA-Z0-9]+$")'
    defining = [p for p in Path("iam_validator").rglob("*.py") if literal in p.read_text(encoding="utf-8")]
    assert [p.name for p in defining] == ["constants.py"]

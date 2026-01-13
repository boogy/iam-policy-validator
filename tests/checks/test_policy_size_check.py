"""Tests for policy size check."""

import pytest

from iam_validator.checks.policy_size import PolicySizeCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement


class TestPolicySizeCheck:
    """Test suite for PolicySizeCheck."""

    @pytest.fixture
    def check(self):
        return PolicySizeCheck()

    @pytest.fixture
    def fetcher(self):
        return AWSServiceFetcher()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="policy_size")

    @pytest.mark.asyncio
    async def test_small_policy_passes(self, check, fetcher, config):
        """Test that small policies pass validation."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="ReadOnly",
                    Effect="Allow",
                    Action=["s3:GetObject"],
                    Resource=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_managed_policy_exceeds_limit(self, check, fetcher):
        """Test that managed policy exceeding 6144 chars is flagged."""
        actions = [f"s3:GetObject{i:04d}" for i in range(450)]
        config = CheckConfig(check_id="policy_size", config={"policy_type": "managed"})
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="ManyActions",
                    Effect="Allow",
                    Action=actions,
                    Resource=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "policy_size_exceeded"
        assert "6,144" in issues[0].message

    @pytest.mark.asyncio
    async def test_inline_user_policy_exceeds_limit(self, check, fetcher):
        """Test that inline user policy exceeding 2048 chars is flagged."""
        actions = [f"s3:GetObject{i:04d}" for i in range(150)]
        config = CheckConfig(check_id="policy_size", config={"policy_type": "inline_user"})
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Effect="Allow", Action=actions, Resource=["arn:aws:s3:::my-bucket/*"])
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 1
        assert "2,048" in issues[0].message

    @pytest.mark.asyncio
    async def test_custom_size_limits(self, check, fetcher):
        """Test using custom size limits."""
        config = CheckConfig(
            check_id="policy_size",
            config={"policy_type": "managed", "size_limits": {"managed": 500}},
        )
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Action=[f"s3:GetObject{i:02d}" for i in range(30)],
                    Resource=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 1
        assert "500" in issues[0].message

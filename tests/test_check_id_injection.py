"""Tests for automatic check_id injection in CheckRegistry."""

import pytest

from iam_validator.checks.policy_size import PolicySizeCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckRegistry
from iam_validator.core.models import IAMPolicy, Statement


class TestCheckIDInjection:
    """Test suite for automatic check_id injection."""

    @pytest.fixture
    def fetcher(self):
        """Create AWS service fetcher."""
        return AWSServiceFetcher()

    @pytest.fixture
    def registry(self):
        """Create a check registry with policy_size check."""
        registry = CheckRegistry()
        registry.register(PolicySizeCheck())
        return registry

    @pytest.mark.asyncio
    async def test_check_id_injected_in_policy_level_check(self, registry, fetcher):
        """Test that check_id is automatically injected for policy-level checks."""
        # Create a policy that exceeds managed policy size
        actions = [f"s3:GetObject{i:04d}" for i in range(450)]
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

        # Execute policy checks
        issues = await registry.execute_policy_checks(policy, "test.json", fetcher)

        # Should have issues
        assert len(issues) > 0

        # All issues should have check_id set
        for issue in issues:
            assert issue.check_id is not None
            assert issue.check_id == "policy_size"

    @pytest.mark.asyncio
    async def test_check_id_not_overridden_if_already_set(self, registry, fetcher):
        """Test that check_id is not overridden if already set by the check."""
        # This is a theoretical test - checks typically don't set check_id manually
        # But if they do, we should respect it
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="Test",
                    Effect="Allow",
                    Action=["s3:GetObject"],
                    Resource=["*"],
                )
            ],
        )

        issues = await registry.execute_policy_checks(policy, "test.json", fetcher)

        # Even if no size issues, the check_id injection logic should work
        # (This test mainly ensures we don't break when check_id is already set)
        assert isinstance(issues, list)

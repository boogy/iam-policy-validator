"""Tests for policy size check."""

import pytest

from iam_validator.checks.policy_size import PolicySizeCheck
from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement


class TestPolicySizeCheck:
    """Test suite for PolicySizeCheck."""

    @pytest.fixture
    def check(self):
        """Create a PolicySizeCheck instance."""
        return PolicySizeCheck()

    @pytest.fixture
    def fetcher(self):
        """Create a mock AWSServiceFetcher instance."""
        return AWSServiceFetcher()

    @pytest.fixture
    def config(self):
        """Create a default CheckConfig."""
        return CheckConfig(check_id="policy_size")

    def test_check_id(self, check):
        """Test check_id property."""
        assert check.check_id == "policy_size"

    def test_description(self, check):
        """Test description property."""
        assert "size" in check.description.lower()
        assert "limit" in check.description.lower()

    def test_default_severity(self, check):
        """Test default_severity property."""
        assert check.default_severity == "error"

    @pytest.mark.asyncio
    async def test_execute_returns_empty(self, check, fetcher, config):
        """Test that statement-level execute returns empty list."""
        statement = Statement(
            Sid="TestSid", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

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
        # Create a policy with many actions to exceed the limit
        # Each action is around 15 chars, so we need ~410 actions
        actions = [f"s3:GetObject{i:04d}" for i in range(450)]

        config = CheckConfig(
            check_id="policy_size", config={"policy_type": "managed"}
        )

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
        assert issues[0].severity == "error"
        assert issues[0].issue_type == "policy_size_exceeded"
        assert issues[0].statement_index == -1  # Policy-level issue
        assert "6,144" in issues[0].message
        assert "managed policy" in issues[0].message

    @pytest.mark.asyncio
    async def test_inline_user_policy_exceeds_limit(self, check, fetcher):
        """Test that inline user policy exceeding 2048 chars is flagged."""
        # Create a policy that exceeds inline_user limit (2048)
        actions = [f"s3:GetObject{i:04d}" for i in range(150)]

        config = CheckConfig(
            check_id="policy_size", config={"policy_type": "inline_user"}
        )

        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="UserActions",
                    Effect="Allow",
                    Action=actions,
                    Resource=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        assert len(issues) == 1
        assert "2,048" in issues[0].message
        assert "inline policy for users" in issues[0].message

    @pytest.mark.asyncio
    async def test_inline_group_policy_exceeds_limit(self, check, fetcher):
        """Test that inline group policy exceeding 5120 chars is flagged."""
        # Create a policy that exceeds inline_group limit (5120)
        actions = [f"s3:GetObject{i:04d}" for i in range(350)]

        config = CheckConfig(
            check_id="policy_size", config={"policy_type": "inline_group"}
        )

        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="GroupActions",
                    Effect="Allow",
                    Action=actions,
                    Resource=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        assert len(issues) == 1
        assert "5,120" in issues[0].message
        assert "inline policy for groups" in issues[0].message

    @pytest.mark.asyncio
    async def test_inline_role_policy_exceeds_limit(self, check, fetcher):
        """Test that inline role policy exceeding 10240 chars is flagged."""
        # Create a policy that exceeds inline_role limit (10240)
        actions = [f"s3:GetObject{i:04d}" for i in range(700)]

        config = CheckConfig(
            check_id="policy_size", config={"policy_type": "inline_role"}
        )

        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="RoleActions",
                    Effect="Allow",
                    Action=actions,
                    Resource=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        assert len(issues) == 1
        assert "10,240" in issues[0].message
        assert "inline policy for roles" in issues[0].message

    @pytest.mark.asyncio
    async def test_custom_size_limits(self, check, fetcher):
        """Test using custom size limits."""
        config = CheckConfig(
            check_id="policy_size",
            config={
                "policy_type": "managed",
                "size_limits": {"managed": 500},  # Very small custom limit
            },
        )

        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="TestActions",
                    Effect="Allow",
                    Action=[f"s3:GetObject{i:02d}" for i in range(30)],
                    Resource=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Should fail because policy will be larger than 500 chars
        assert len(issues) == 1
        assert "500" in issues[0].message

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity from config."""
        actions = [f"s3:GetObject{i:04d}" for i in range(450)]

        config = CheckConfig(
            check_id="policy_size",
            severity="warning",
            config={"policy_type": "managed"},
        )

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
        assert issues[0].severity == "warning"

    @pytest.mark.asyncio
    async def test_suggestion_included(self, check, fetcher):
        """Test that suggestion is included."""
        actions = [f"s3:GetObject{i:04d}" for i in range(450)]

        config = CheckConfig(
            check_id="policy_size", config={"policy_type": "managed"}
        )

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

        assert issues[0].suggestion is not None
        assert "splitting" in issues[0].suggestion.lower()
        assert "whitespace" in issues[0].suggestion.lower()

    @pytest.mark.asyncio
    async def test_whitespace_not_counted(self, check, fetcher, config):
        """Test that whitespace is not counted in policy size."""
        # Create a small policy
        policy_small = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="Test", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]
                )
            ],
        )

        # The policy should have the same effective size regardless of whitespace
        # since we remove all whitespace before measuring
        issues = await check.execute_policy(
            policy_small, "test.json", fetcher, config
        )
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_multiple_statements_combined_size(self, check, fetcher):
        """Test that multiple statements are counted together."""
        # Create a policy with multiple statements that together exceed the limit
        actions1 = [f"s3:GetObject{i:04d}" for i in range(250)]
        actions2 = [f"s3:PutObject{i:04d}" for i in range(250)]

        config = CheckConfig(
            check_id="policy_size", config={"policy_type": "managed"}
        )

        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="Statement1",
                    Effect="Allow",
                    Action=actions1,
                    Resource=["arn:aws:s3:::bucket1/*"],
                ),
                Statement(
                    Sid="Statement2",
                    Effect="Allow",
                    Action=actions2,
                    Resource=["arn:aws:s3:::bucket2/*"],
                ),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Should exceed limit when combined
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_default_policy_type(self, check, fetcher):
        """Test that default policy type is 'managed'."""
        # Large policy without specifying policy_type
        actions = [f"s3:GetObject{i:04d}" for i in range(450)]

        config = CheckConfig(check_id="policy_size")  # No policy_type specified

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

        # Should use managed policy limit (6144)
        assert len(issues) == 1
        assert "managed policy" in issues[0].message

    @pytest.mark.asyncio
    async def test_percentage_calculation(self, check, fetcher):
        """Test that percentage over limit is calculated."""
        actions = [f"s3:GetObject{i:04d}" for i in range(450)]

        config = CheckConfig(
            check_id="policy_size", config={"policy_type": "managed"}
        )

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

        # Should include percentage in suggestion
        assert "%" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_unknown_policy_type_defaults_to_managed(self, check, fetcher):
        """Test that unknown policy type defaults to managed."""
        actions = [f"s3:GetObject{i:04d}" for i in range(450)]

        config = CheckConfig(
            check_id="policy_size",
            config={"policy_type": "unknown_type"},  # Invalid type
        )

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

        # Should still work, defaulting to managed policy
        assert len(issues) == 1

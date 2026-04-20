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
            Statement=[Statement(Effect="Allow", Action=actions, Resource=["arn:aws:s3:::my-bucket/*"])],
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

    @pytest.mark.asyncio
    async def test_trust_policy_limit_triggered_via_runtime_kwarg(self, check, fetcher, config):
        """Runtime policy_type=TRUST_POLICY maps to 2048-byte limit automatically."""
        # A trust policy just above 2048 bytes. Stuff Condition values (AWS
        # counts those) rather than actions so the payload looks trust-shaped.
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"Service": "lambda.amazonaws.com"},
                    Action="sts:AssumeRole",
                    Condition={"StringEquals": {"aws:SourceAccount": "x" * 2200}},
                )
            ],
        )
        issues = await check.execute_policy(
            policy, "trust.json", fetcher, config, policy_type="TRUST_POLICY"
        )
        assert len(issues) == 1
        assert "2,048" in issues[0].message
        assert "trust policy" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_scp_limit_triggered_via_runtime_kwarg(self, check, fetcher, config):
        """Runtime policy_type=SERVICE_CONTROL_POLICY maps to 5120-byte limit."""
        actions = [f"s3:GetObject{i:04d}" for i in range(380)]
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Deny", Action=actions, Resource="*")],
        )
        issues = await check.execute_policy(
            policy, "scp.json", fetcher, config, policy_type="SERVICE_CONTROL_POLICY"
        )
        assert len(issues) == 1
        assert "5,120" in issues[0].message
        assert "Service Control Policy" in issues[0].message

    @pytest.mark.asyncio
    async def test_rcp_limit_triggered_via_runtime_kwarg(self, check, fetcher, config):
        """Runtime policy_type=RESOURCE_CONTROL_POLICY maps to 5120-byte limit."""
        actions = [f"s3:PutObject{i:04d}" for i in range(380)]
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Deny", Action=actions, Resource="*")],
        )
        issues = await check.execute_policy(
            policy, "rcp.json", fetcher, config, policy_type="RESOURCE_CONTROL_POLICY"
        )
        assert len(issues) == 1
        assert "5,120" in issues[0].message
        assert "Resource Control Policy" in issues[0].message

    @pytest.mark.asyncio
    async def test_yaml_policy_type_overrides_runtime_kwarg(self, check, fetcher):
        """Explicit policy_type in YAML config takes priority over runtime kwarg."""
        # Build a policy around 3 KB — under managed (6144) but over inline_user (2048).
        actions = [f"s3:GetObject{i:04d}" for i in range(200)]
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Allow", Action=actions, Resource="*")],
        )
        # Runtime says IDENTITY_POLICY (which would resolve to managed/6144 -> no issue)
        # but YAML pins inline_user (2048 -> flagged).
        config = CheckConfig(check_id="policy_size", config={"policy_type": "inline_user"})
        issues = await check.execute_policy(
            policy, "p.json", fetcher, config, policy_type="IDENTITY_POLICY"
        )
        assert len(issues) == 1
        assert "2,048" in issues[0].message

    @pytest.mark.asyncio
    async def test_size_uses_raw_policy_dict_when_available(self, check, fetcher, config):
        """When raw_policy_dict is supplied, it's measured (not the Pydantic view)."""
        # A small policy, but raw_policy_dict padded with extra keys AWS would see.
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Allow", Action="s3:GetObject", Resource="*")],
        )
        raw = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "x" * 3000,  # blow up the raw size
                }
            ],
        }
        cfg = CheckConfig(check_id="policy_size", config={"policy_type": "inline_user"})
        issues = await check.execute_policy(
            policy, "p.json", fetcher, cfg, raw_policy_dict=raw
        )
        assert len(issues) == 1
        assert "bytes" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_size_counts_utf8_bytes_not_codepoints(self, check, fetcher):
        """Non-ASCII characters count as multiple UTF-8 bytes, matching AWS."""
        # A single non-ASCII codepoint stuffed into a SID repeatedly.
        # 'é' is 2 bytes in UTF-8; '𝓐' (math script A) is 4 bytes.
        # Use tight limit so only the byte-counted size triggers the issue.
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="A" * 50,  # harmless ascii SID kept short
                    Effect="Allow",
                    Action="s3:GetObject",
                    Resource="*",
                    Condition={"StringEquals": {"aws:PrincipalTag/owner": "𝓐" * 30}},
                )
            ],
        )
        cfg = CheckConfig(
            check_id="policy_size",
            config={"policy_type": "managed", "size_limits": {"managed": 200}},
        )
        issues = await check.execute_policy(policy, "p.json", fetcher, cfg)
        assert len(issues) == 1
        # 30 × 4 bytes for the math 'A' alone = 120 extra bytes beyond the
        # codepoint count, so the reported size must reflect UTF-8 byte length.
        reported = int(issues[0].message.split(" bytes")[0].split("(")[1].replace(",", ""))
        assert reported > 200

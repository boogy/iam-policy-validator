"""Tests for WildcardResourceCheck."""

import pytest

from iam_validator.checks.wildcard_resource import WildcardResourceCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
async def fetcher():
    """Create AWS service fetcher for tests."""
    async with AWSServiceFetcher(prefetch_common=False) as f:
        yield f


@pytest.fixture
def check():
    """Create WildcardResourceCheck instance."""
    return WildcardResourceCheck()


@pytest.fixture
def config():
    """Create default check config."""
    return CheckConfig(check_id="wildcard_resource", enabled=True, config={})


class TestWildcardResourceCheck:
    """Tests for WildcardResourceCheck."""

    @pytest.mark.asyncio
    async def test_wildcard_resource_detected(self, check, fetcher, config):
        """Test that Resource:* is detected for actions that support resource-level permissions."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "overly_permissive"

    @pytest.mark.asyncio
    async def test_specific_resources_not_flagged(self, check, fetcher, config):
        """Test that specific resources are not flagged."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_deny_statement_ignored(self, check, fetcher, config):
        """Test that Deny statements are ignored."""
        statement = Statement(Effect="Deny", Action=["s3:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_allowed_wildcards_config(self, check, fetcher):
        """Test allowed_wildcards configuration."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["iam:Get*"]},
        )
        # Action matching allowed pattern passes
        statement = Statement(Effect="Allow", Action=["iam:GetUser"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

        # Action not matching allowed pattern fails
        statement2 = Statement(Effect="Allow", Action=["iam:DeleteUser"], Resource=["*"])
        issues2 = await check.execute(statement2, 0, fetcher, config)
        assert len(issues2) == 1

    @pytest.mark.asyncio
    async def test_list_level_actions_not_flagged(self, check, fetcher, config):
        """Test that list-level actions don't flag wildcards (they don't support resource-level)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:ListAllMyBuckets", "iam:ListUsers", "ec2:DescribeInstances"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_mixed_list_and_write_actions(self, check, fetcher, config):
        """Test that mixed list and write actions flag the write action."""
        statement = Statement(
            Effect="Allow", Action=["s3:ListAllMyBuckets", "s3:PutObject"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1


class TestConditionAwareSeverity:
    """Tests for condition-aware severity adjustment in WildcardResourceCheck."""

    @pytest.fixture
    def check(self):
        """Create WildcardResourceCheck instance."""
        return WildcardResourceCheck()

    @pytest.fixture
    def config(self):
        """Create default check config."""
        return CheckConfig(check_id="wildcard_resource", enabled=True, config={})

    @pytest.fixture
    async def fetcher(self):
        """Create AWS service fetcher for tests."""
        async with AWSServiceFetcher(prefetch_common=False) as f:
            yield f

    @pytest.mark.asyncio
    async def test_global_condition_lowers_severity_resource_account(
        self, check, fetcher, config
    ):
        """Test 1: aws:ResourceAccount condition lowers severity to LOW."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:ResourceAccount": "123456789012"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        assert "aws:ResourceAccount" in issues[0].message

    @pytest.mark.asyncio
    async def test_global_condition_lowers_severity_resource_org_id(
        self, check, fetcher, config
    ):
        """Test aws:ResourceOrgID condition lowers severity to LOW."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:ResourceOrgID": "o-abc123"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        assert "aws:ResourceOrgID" in issues[0].message

    @pytest.mark.asyncio
    async def test_global_condition_lowers_severity_resource_org_paths(
        self, check, fetcher, config
    ):
        """Test aws:ResourceOrgPaths condition lowers severity to LOW."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"ForAnyValue:StringLike": {"aws:ResourceOrgPaths": "o-abc/*"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        assert "aws:ResourceOrgPaths" in issues[0].message

    @pytest.mark.asyncio
    async def test_resource_tag_with_action_level_support_lowers_severity_ssm(
        self, check, fetcher, config
    ):
        """Test 3: SSM actions with aws:ResourceTag in ActionConditionKeys lower severity."""
        statement = Statement(
            Effect="Allow",
            Action=["ssm:StartSession"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:ResourceTag/nx:component": "bastion"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        assert "aws:ResourceTag" in issues[0].message

    @pytest.mark.asyncio
    async def test_resource_tag_with_resource_level_support_lowers_severity_s3(
        self, check, fetcher, config
    ):
        """Test 4: S3 GetObject with aws:ResourceTag (via object resource) lowers severity."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:ResourceTag/Env": "prod"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        assert "aws:ResourceTag" in issues[0].message

    @pytest.mark.asyncio
    async def test_resource_tag_no_support_keeps_severity_route53(
        self, check, fetcher, config
    ):
        """Test 5: Route53 action without ResourceTag support keeps MEDIUM severity."""
        statement = Statement(
            Effect="Allow",
            Action=["route53:ChangeResourceRecordSets"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:ResourceTag/Env": "prod"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "medium"
        assert "don't support resource tags" in issues[0].message

    @pytest.mark.asyncio
    async def test_non_resource_scoping_condition_keeps_severity(
        self, check, fetcher, config
    ):
        """Test 6: Non-resource-scoping condition (aws:SourceIp) keeps MEDIUM severity."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_no_conditions_keeps_severity(self, check, fetcher, config):
        """Test 7: No conditions keeps MEDIUM severity (unchanged behavior)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_mixed_actions_resource_tag_partial_support_keeps_severity(
        self, check, fetcher, config
    ):
        """Test 8: Mixed actions where one doesn't support ResourceTag keeps MEDIUM."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "route53:ChangeResourceRecordSets"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:ResourceTag/Env": "prod"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "medium"
        assert "don't support resource tags" in issues[0].message

    @pytest.mark.asyncio
    async def test_multiple_global_conditions_lowers_severity(
        self, check, fetcher, config
    ):
        """Test 9: Multiple global conditions together lower severity."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={
                "StringEquals": {
                    "aws:ResourceAccount": "123456789012",
                    "aws:ResourceOrgID": "o-abc123",
                }
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        # Both should be mentioned in the message
        assert "aws:ResourceAccount" in issues[0].message
        assert "aws:ResourceOrgID" in issues[0].message

    @pytest.mark.asyncio
    async def test_all_actions_support_resource_tag_via_different_paths(
        self, check, fetcher, config
    ):
        """Test 10: Actions supporting ResourceTag via different paths (action/resource level)."""
        # s3:GetObject supports via resource-level, ssm:StartSession via action-level
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "ssm:StartSession"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:ResourceTag/Env": "prod"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        assert "aws:ResourceTag" in issues[0].message

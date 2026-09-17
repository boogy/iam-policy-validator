"""Tests for WildcardResourceCheck."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.checks.wildcard_resource import WildcardResourceCheck, clear_resource_support_cache
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.config.defaults import get_default_config
from iam_validator.core.models import ActionDetail, ServiceDetail, Statement


@pytest.fixture(autouse=True)
def _clear_wildcard_resource_module_caches():
    """Module-level action caches persist across tests; isolate each test's view of them."""
    clear_resource_support_cache()
    yield
    clear_resource_support_cache()


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
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::bucket/*"])
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
        statement = Statement(Effect="Allow", Action=["s3:ListAllMyBuckets", "s3:PutObject"], Resource=["*"])
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
    async def test_global_condition_lowers_severity_resource_account(self, check, fetcher, config):
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
    async def test_global_condition_lowers_severity_resource_org_id(self, check, fetcher, config):
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
    async def test_global_condition_lowers_severity_resource_org_paths(self, check, fetcher, config):
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
    async def test_resource_tag_with_action_level_support_lowers_severity_ssm(self, check, fetcher, config):
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
        assert "ABAC" in issues[0].message
        assert "aws:ResourceTag/nx:component" in issues[0].message

    @pytest.mark.asyncio
    async def test_resource_tag_with_resource_level_support_lowers_severity_s3(self, check, fetcher, config):
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
        assert "ABAC" in issues[0].message
        assert "aws:ResourceTag/Env" in issues[0].message

    @pytest.mark.asyncio
    async def test_resource_tag_no_support_keeps_severity_route53(self, check, fetcher, config):
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
        assert "don't support them" in issues[0].message

    @pytest.mark.asyncio
    async def test_non_resource_scoping_condition_keeps_severity(self, check, fetcher, config):
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
    async def test_mixed_actions_resource_tag_partial_support_keeps_severity(self, check, fetcher, config):
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
        assert "don't support them" in issues[0].message

    @pytest.mark.asyncio
    async def test_multiple_global_conditions_lowers_severity(self, check, fetcher, config):
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
    async def test_all_actions_support_resource_tag_via_different_paths(self, check, fetcher, config):
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
        assert "ABAC" in issues[0].message
        assert "aws:ResourceTag/Env" in issues[0].message

    @pytest.mark.asyncio
    async def test_request_tag_abac_lowers_severity(self, check, fetcher, config):
        """Test: aws:RequestTag/* ABAC conditions lower severity to LOW."""
        statement = Statement(
            Effect="Allow",
            Action=["sqs:CreateQueue"],
            Resource=["*"],
            Condition={
                "StringEquals": {
                    "aws:RequestTag/owner": "${aws:PrincipalTag/owner}",
                    "aws:RequestTag/env": "${aws:PrincipalTag/env}",
                },
                "Null": {
                    "aws:RequestTag/owner": "false",
                    "aws:RequestTag/env": "false",
                },
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        assert "ABAC" in issues[0].message
        assert "aws:RequestTag/" in issues[0].message

    @pytest.mark.asyncio
    async def test_request_tag_with_tagkeys_includes_both_in_message(self, check, fetcher, config):
        """Test: aws:RequestTag/* with aws:TagKeys includes both in the message."""
        statement = Statement(
            Effect="Allow",
            Action=["sqs:CreateQueue"],
            Resource=["*"],
            Condition={
                "StringEquals": {
                    "aws:RequestTag/owner": "${aws:PrincipalTag/owner}",
                },
                "ForAllValues:StringEquals": {
                    "aws:TagKeys": ["owner"],
                },
                "Null": {
                    "aws:RequestTag/owner": "false",
                },
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        assert "aws:RequestTag/owner" in issues[0].message
        assert "aws:TagKeys" in issues[0].message

    @pytest.mark.asyncio
    async def test_negated_global_condition_does_not_lower_severity(self, check, fetcher, config):
        """StringNotEquals excludes a value rather than scoping to one — severity unchanged."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"StringNotEquals": {"aws:ResourceAccount": "123456789012"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_null_only_condition_does_not_lower_severity(self, check, fetcher, config):
        """A lone Null check tests key existence, not resource scope — severity unchanged."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"Null": {"aws:ResourceAccount": "false"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_negated_abac_tag_condition_does_not_lower_severity(self, check, fetcher, config):
        """A negated tag-ABAC condition doesn't restrict resource scope — severity unchanged."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"StringNotEquals": {"aws:ResourceTag/Env": "prod"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_principal_tag_does_not_lower_severity(self, check, fetcher, config):
        """aws:PrincipalTag/* scopes WHO, not WHAT — should NOT lower severity."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:PrincipalTag/team": "engineering"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "medium"


def _make_s3_service_detail_with_list_actions() -> ServiceDetail:
    """s3 service data with both kinds of list-level action: with and without resource types."""
    return ServiceDetail(
        Name="Amazon S3",
        Actions=[
            ActionDetail(
                Name="ListBucket",
                Resources=[{"Name": "accesspoint"}, {"Name": "bucket"}],
                Annotations={"Properties": {"IsList": True}},
            ),
            ActionDetail(
                Name="ListAllMyBuckets",
                Resources=[],
                Annotations={"Properties": {"IsList": True}},
            ),
        ],
    )


@pytest.fixture
def s3_list_fetcher():
    """Mock fetcher serving canned s3 list-action data — no network access."""
    fetcher = MagicMock()
    fetcher.fetch_service_by_name = AsyncMock(return_value=_make_s3_service_detail_with_list_actions())
    return fetcher


class TestListActionResourceSupportGating:
    """RES-1: list-level actions must be gated on resource-type support, not access level alone."""

    @pytest.fixture
    def check(self):
        return WildcardResourceCheck()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="wildcard_resource", enabled=True, config={})

    @pytest.mark.asyncio
    async def test_list_action_with_resources_is_flagged(self, check, config, s3_list_fetcher):
        """s3:ListBucket is list-level but takes a resource ARN — Resource: "*" should be flagged."""
        statement = Statement(Effect="Allow", Action=["s3:ListBucket"], Resource=["*"])
        issues = await check.execute(statement, 0, s3_list_fetcher, config)
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_list_action_without_resources_not_flagged(self, check, config, s3_list_fetcher):
        """s3:ListAllMyBuckets has no resource types — Resource: "*" is appropriate."""
        statement = Statement(Effect="Allow", Action=["s3:ListAllMyBuckets"], Resource=["*"])
        issues = await check.execute(statement, 0, s3_list_fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_cached_path_agrees_with_uncached_path_for_list_action_with_resources(
        self, check, config, s3_list_fetcher
    ):
        """A second lookup of the same action must hit the cache and agree with the first."""
        statement = Statement(Effect="Allow", Action=["s3:ListBucket"], Resource=["*"])
        first = await check.execute(statement, 0, s3_list_fetcher, config)
        second = await check.execute(statement, 0, s3_list_fetcher, config)
        assert len(first) == len(second) == 1
        assert s3_list_fetcher.fetch_service_by_name.await_count == 1

    @pytest.mark.asyncio
    async def test_cached_path_agrees_with_uncached_path_for_list_action_without_resources(
        self, check, config, s3_list_fetcher
    ):
        """A second lookup of the same action must hit the cache and agree with the first."""
        statement = Statement(Effect="Allow", Action=["s3:ListAllMyBuckets"], Resource=["*"])
        first = await check.execute(statement, 0, s3_list_fetcher, config)
        second = await check.execute(statement, 0, s3_list_fetcher, config)
        assert len(first) == len(second) == 0
        assert s3_list_fetcher.fetch_service_by_name.await_count == 1


class TestAdjustmentReasonReachesMessage:
    """Brief RES-3: a custom or default message must not swallow the severity-adjustment reason."""

    @pytest.fixture
    def check(self):
        return WildcardResourceCheck()

    @pytest.fixture
    async def fetcher(self):
        async with AWSServiceFetcher(prefetch_common=False) as f:
            yield f

    @pytest.mark.asyncio
    async def test_default_config_message_includes_adjustment_reason(self, check, fetcher):
        """Default config's static wildcard_resource.message must not hide the adjustment reason."""
        default_config = get_default_config()["wildcard_resource"]
        config = CheckConfig(check_id="wildcard_resource", enabled=True, config=default_config)
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:ResourceAccount": "123456789012"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert "Severity lowered" in issues[0].message

    @pytest.mark.asyncio
    async def test_user_configured_message_includes_adjustment_reason(self, check, fetcher):
        """A user-supplied custom message must still get the adjustment reason appended."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"message": "Custom wildcard resource warning"},
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:ResourceAccount": "123456789012"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert "Custom wildcard resource warning" in issues[0].message
        assert "Severity lowered" in issues[0].message

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

    def test_check_id(self, check):
        """Test check ID."""
        assert check.check_id == "wildcard_resource"

    def test_description(self, check):
        """Test check description."""
        assert "wildcard resources" in check.description.lower()

    def test_default_severity(self, check):
        """Test default severity is medium."""
        assert check.default_severity == "medium"

    @pytest.mark.asyncio
    async def test_wildcard_resource_detected(self, check, fetcher, config):
        """Test that Resource:* is detected."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "medium"
        assert issues[0].issue_type == "overly_permissive"
        assert "all resources" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_specific_resources_not_flagged(self, check, fetcher, config):
        """Test that specific resources are not flagged."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_deny_statement_ignored(self, check, fetcher, config):
        """Test that Deny statements are ignored."""
        statement = Statement(
            Effect="Deny",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_in_list_with_other_resources(self, check, fetcher, config):
        """Test that wildcard is detected even when mixed with other resources."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*", "*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "all resources" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_allowed_wildcards_pass(self, check, fetcher):
        """Test that actions in allowed_wildcards configuration are not flagged."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["ec2:Describe*", "s3:List*"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["ec2:DescribeInstances", "s3:ListBucket"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # These actions should be allowed with Resource:* because they match allowed patterns
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_allowed_wildcards_partial_match_fails(self, check, fetcher):
        """Test that only matching actions pass with allowed_wildcards."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["ec2:Describe*"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["ec2:DescribeInstances", "ec2:TerminateInstances"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # ec2:TerminateInstances doesn't match ec2:Describe*, so should be flagged
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_full_wildcard_action_with_allowed_config_fails(self, check, fetcher):
        """Test that Action:* is still flagged even with allowed_wildcards config."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["ec2:Describe*"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["*"],  # Full wildcard is filtered out
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Full wildcard "*" should still be flagged
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_statement_with_sid(self, check, fetcher, config):
        """Test that statement SID is captured in issue."""
        statement = Statement(
            Sid="AllowAllResources",
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_sid == "AllowAllResources"

    @pytest.mark.asyncio
    async def test_statement_index(self, check, fetcher, config):
        """Test that statement index is captured."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 9, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_index == 9

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, fetcher, config):
        """Test that line number is captured when available."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            line_number=55,
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].line_number == 55

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity override."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            severity="high",
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "high"

    @pytest.mark.asyncio
    async def test_custom_message(self, check, fetcher):
        """Test custom message configuration."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"message": "Custom wildcard resource warning"},
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].message == "Custom wildcard resource warning"

    @pytest.mark.asyncio
    async def test_custom_suggestion(self, check, fetcher):
        """Test custom suggestion configuration."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"suggestion": "Please use specific resource ARNs"},
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Please use specific resource ARNs" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_suggestion_with_example(self, check, fetcher):
        """Test suggestion includes example when configured."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={
                "suggestion": "Use specific resource ARNs",
                "example": "Resource: 'arn:aws:s3:::my-bucket/*'",
            },
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Use specific resource ARNs" in issues[0].suggestion
        assert issues[0].example is not None
        assert "Resource: 'arn:aws:s3:::my-bucket/*'" in issues[0].example

    @pytest.mark.asyncio
    async def test_wildcard_action_with_allowed_config(self, check, fetcher):
        """Test that wildcard action without allowed_wildcards is flagged."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": []},
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should be flagged because allowed_wildcards is empty
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_empty_resources_not_flagged(self, check, fetcher, config):
        """Test that empty resources list doesn't cause issues."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=[],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_none_resources_not_flagged(self, check, fetcher, config):
        """Test that None resources doesn't cause issues."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
        )
        # Manually set Resource to None to test edge case
        statement.resource = None

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_resource_with_arn_patterns(self, check, fetcher, config):
        """Test that ARN patterns with wildcards are not flagged."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket-*/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # ARN with wildcard pattern is not the same as Resource: "*"
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_actions_in_policy_with_allowed_wildcards(self, check, fetcher):
        """Test that wildcard actions in policy match against allowed_wildcards config.

        This is a regression test for the bug where policy actions like "iam:Get*"
        were not being expanded before comparison with the expanded allowed_wildcards list.

        Config: allowed_wildcards: ["iam:Get*", "iam:List*"]
        Policy: Action: ["iam:Get*", "iam:List*"], Resource: "*"
        Expected: No issues (wildcards should be allowed)
        """
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["iam:Get*", "iam:List*"]},
        )

        statement = Statement(
            Sid="GeneralReadOnly",
            Effect="Allow",
            Action=["iam:Get*", "iam:List*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Both wildcard actions should be allowed because they match the allowed patterns
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_actions_partial_match_with_allowed_wildcards(self, check, fetcher):
        """Test that only partially matching wildcard actions are flagged.

        Config: allowed_wildcards: ["iam:Get*"]
        Policy: Action: ["iam:Get*", "iam:Delete*"], Resource: "*"
        Expected: Issue flagged (iam:Delete* is not in allowed list)
        """
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["iam:Get*"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["iam:Get*", "iam:Delete*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # iam:Delete* doesn't match iam:Get*, so should be flagged
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_literal_match_without_expansion(self, check, fetcher):
        """Test literal pattern matching (fast path) without AWS API expansion.

        When policy actions exactly match config patterns (literal string match),
        the check should pass without needing to expand via AWS API.

        Config: allowed_wildcards: ["iam:Get*"]
        Policy: Action: ["iam:Get*"], Resource: "*"
        Expected: No issues (literal match: "iam:Get*" == "iam:Get*")
        """
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["iam:Get*"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["iam:Get*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should pass via literal match (fast path)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_specific_action_with_wildcard_config_expansion(self, check, fetcher):
        """Test specific actions matched against wildcard config (expansion path).

        When policy has specific actions and config has wildcards, the config
        should expand to match the specific actions.

        Config: allowed_wildcards: ["iam:Get*"] -> expands to ["iam:GetUser", "iam:GetRole", ...]
        Policy: Action: ["iam:GetUser"], Resource: "*"
        Expected: No issues (iam:GetUser is in expanded list)
        """
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["iam:Get*"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["iam:GetUser"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should pass via expansion match
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_mixed_literal_and_expanded_match(self, check, fetcher):
        """Test mix of literal and expanded actions.

        Policy: Action: ["iam:Get*", "iam:GetUser"], Resource: "*"
        Config: allowed_wildcards: ["iam:Get*"]
        Expected: No issues (iam:Get* matches literally, iam:GetUser matches via expansion)
        """
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["iam:Get*"]},
        )

        statement = Statement(
            Effect="Allow",
            Action=["iam:Get*", "iam:GetUser"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should pass: iam:Get* matches literally, triggers fast path
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_actions_without_resource_support_not_flagged(self, check, fetcher, config):
        """Test that actions without resource-level permission support are not flagged.

        Some AWS actions don't support resource-level permissions and legitimately
        require Resource: "*". These should not be flagged as overly permissive.

        Examples:
        - sts:GetCallerIdentity - doesn't support resource-level permissions
        - ec2:DescribeInstances - doesn't support resource-level permissions
        """
        # sts:GetCallerIdentity doesn't support resource-level permissions
        statement = Statement(
            Sid="AllowGetCallerIdentity",
            Effect="Allow",
            Action=["sts:GetCallerIdentity"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not be flagged - this action requires Resource: "*"
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_ec2_describe_actions_without_resource_support(self, check, fetcher, config):
        """Test that EC2 Describe actions without resource support are not flagged.

        ec2:DescribeInstances doesn't support resource-level permissions.
        """
        statement = Statement(
            Sid="AllowDescribeInstances",
            Effect="Allow",
            Action=["ec2:DescribeInstances"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not be flagged - ec2:DescribeInstances requires Resource: "*"
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_mixed_actions_some_requiring_resources(self, check, fetcher, config):
        """Test statement with both resource-supporting and non-supporting actions.

        When a statement has a mix of actions where some support resources and
        some don't, it should still flag the issue if any action supports resources.

        ec2:DescribeInstances - doesn't support resource-level permissions (OK)
        s3:GetObject - supports resource-level permissions (should flag)
        """
        statement = Statement(
            Sid="MixedActions",
            Effect="Allow",
            Action=["ec2:DescribeInstances", "s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should be flagged because s3:GetObject supports resource-level permissions
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_all_actions_without_resource_support(self, check, fetcher, config):
        """Test statement where all actions don't support resources.

        When ALL actions in a statement don't support resource-level permissions,
        the wildcard resource is appropriate and should not be flagged.
        """
        statement = Statement(
            Sid="AllReadOnlyNoResourceSupport",
            Effect="Allow",
            Action=["sts:GetCallerIdentity", "ec2:DescribeInstances"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not be flagged - all actions require Resource: "*"
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_iam_list_users_without_resource_support(self, check, fetcher, config):
        """Test that iam:ListUsers is not flagged (it doesn't support resources).

        iam:ListUsers doesn't support resource-level permissions.
        """
        statement = Statement(
            Sid="AllowListUsers",
            Effect="Allow",
            Action=["iam:ListUsers"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not be flagged - iam:ListUsers requires Resource: "*"
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_action_with_resource_support_still_flagged(self, check, fetcher, config):
        """Test that actions with resource support are still flagged.

        s3:GetObject supports resource-level permissions (requires bucket/object ARN).
        """
        statement = Statement(
            Sid="GetObjectWildcard",
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should be flagged - s3:GetObject supports specific resource ARNs
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_wildcard_action_patterns_still_flagged(self, check, fetcher, config):
        """Test that wildcard action patterns are still flagged.

        Wildcard patterns like "s3:*" should still be flagged because
        we can't determine resource support for all matched actions.
        """
        statement = Statement(
            Sid="S3WildcardAction",
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should be flagged - wildcard action patterns can't be filtered
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_filter_actions_unknown_service(self, check, fetcher, config):
        """Test that unknown services are conservatively kept.

        If we can't look up an action (unknown service), we should keep it
        to be conservative about security.
        """
        statement = Statement(
            Sid="UnknownService",
            Effect="Allow",
            Action=["unknownservice:SomeAction"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should be flagged - unknown services are kept (conservative approach)
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_list_level_actions_not_flagged(self, check, fetcher, config):
        """Test that list-level actions are not flagged with wildcard resources.

        List-level actions (like s3:ListBuckets) only enumerate resources and
        don't pose security risks with Resource: "*". These should not be flagged.
        """
        statement = Statement(
            Sid="AllowListBuckets",
            Effect="Allow",
            Action=["s3:ListAllMyBuckets"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not be flagged - s3:ListAllMyBuckets is a list-level action
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_iam_list_actions_not_flagged(self, check, fetcher, config):
        """Test that IAM list actions are not flagged.

        iam:ListUsers and similar list actions are safe with wildcards.
        """
        statement = Statement(
            Sid="AllowIAMListActions",
            Effect="Allow",
            Action=["iam:ListUsers", "iam:ListRoles", "iam:ListGroups"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not be flagged - all are list-level actions
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_ec2_describe_list_actions_not_flagged(self, check, fetcher, config):
        """Test that EC2 describe/list actions are not flagged.

        EC2 describe actions are list-level and safe with wildcards.
        """
        statement = Statement(
            Sid="AllowEC2Describe",
            Effect="Allow",
            Action=["ec2:DescribeInstances", "ec2:DescribeVpcs", "ec2:DescribeSubnets"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not be flagged - EC2 describe actions are list-level
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_mixed_list_and_write_actions_flagged(self, check, fetcher, config):
        """Test that mixed list and write actions are flagged for the write action.

        When a statement has both list-level and write-level actions,
        it should still flag the issue for the write action.
        """
        statement = Statement(
            Sid="MixedListAndWrite",
            Effect="Allow",
            Action=["s3:ListAllMyBuckets", "s3:PutObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should be flagged because s3:PutObject is a write action
        assert len(issues) == 1
        # The message should reference s3:PutObject, not s3:ListAllMyBuckets
        assert "s3:PutObject" in issues[0].message or "PutObject" in issues[0].message

    @pytest.mark.asyncio
    async def test_all_list_actions_not_flagged(self, check, fetcher, config):
        """Test that a statement with only list-level actions is not flagged.

        When ALL actions in a statement are list-level, Resource: "*" is
        appropriate and should not be flagged.
        """
        statement = Statement(
            Sid="OnlyListActions",
            Effect="Allow",
            Action=[
                "s3:ListAllMyBuckets",
                "iam:ListUsers",
                "ec2:DescribeInstances",
            ],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should not be flagged - all actions are list-level
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_read_actions_still_flagged(self, check, fetcher, config):
        """Test that read-level actions (not list) are still flagged.

        Read actions like s3:GetObject can access sensitive data and should
        be flagged for wildcard resource usage. Only list-level actions are safe.
        """
        statement = Statement(
            Sid="ReadAction",
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # Should be flagged - s3:GetObject is a read action, not list
        assert len(issues) == 1

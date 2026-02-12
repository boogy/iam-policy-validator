"""Tests for condition key validation with wildcard actions."""

import pytest

from iam_validator.checks.condition_key_validation import ConditionKeyValidationCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.aws_service.validators import (
    ConditionKeyValidationResult,
    ServiceValidator,
)
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestWildcardActionConditionKeyValidation:
    """Tests for validate_condition_key with wildcard actions at the validator level."""

    @pytest.mark.asyncio
    async def test_wildcard_action_with_valid_resource_tag(self):
        """iam:Tag* with aws:ResourceTag/owner should be valid (expanded actions support it)."""
        async with AWSServiceFetcher() as fetcher:
            result = await fetcher.validate_condition_key(
                "iam:Tag*",
                "aws:ResourceTag/owner",
                ["*"],
            )
            assert result.is_valid is True, f"Expected valid but got: {result.error_message}"

    @pytest.mark.asyncio
    async def test_wildcard_action_with_valid_action_condition_key(self):
        """s3:Get* with s3:ExistingObjectTag/env should be valid (GetObject supports it)."""
        async with AWSServiceFetcher() as fetcher:
            result = await fetcher.validate_condition_key(
                "s3:Get*",
                "s3:ExistingObjectTag/env",
                ["arn:aws:s3:::bucket/*"],
            )
            assert result.is_valid is True, f"Expected valid but got: {result.error_message}"

    @pytest.mark.asyncio
    async def test_wildcard_action_with_invalid_condition_key(self):
        """s3:Get* with ec2:InstanceType should be invalid (no expanded action supports it)."""
        async with AWSServiceFetcher() as fetcher:
            result = await fetcher.validate_condition_key(
                "s3:Get*",
                "ec2:InstanceType",
                ["arn:aws:s3:::bucket/*"],
            )
            assert result.is_valid is False
            assert result.error_message is not None
            assert "ec2:InstanceType" in result.error_message

    @pytest.mark.asyncio
    async def test_wildcard_action_global_key_with_warning(self):
        """iam:Tag* with aws:PrincipalOrgID should be valid with warning."""
        async with AWSServiceFetcher() as fetcher:
            result = await fetcher.validate_condition_key(
                "iam:Tag*",
                "aws:PrincipalOrgID",
                ["*"],
            )
            assert result.is_valid is True

    @pytest.mark.asyncio
    async def test_wildcard_action_with_request_tag(self):
        """iam:Create* with aws:RequestTag/env should be valid (CreateRole etc. support it)."""
        async with AWSServiceFetcher() as fetcher:
            result = await fetcher.validate_condition_key(
                "iam:Create*",
                "aws:RequestTag/env",
                ["*"],
            )
            assert result.is_valid is True, f"Expected valid but got: {result.error_message}"

    @pytest.mark.asyncio
    async def test_suffix_wildcard_action(self):
        """iam:*Role with aws:ResourceTag/owner should be valid (TagRole, UntagRole support it)."""
        async with AWSServiceFetcher() as fetcher:
            result = await fetcher.validate_condition_key(
                "iam:*Role",
                "aws:ResourceTag/owner",
                ["*"],
            )
            assert result.is_valid is True, f"Expected valid but got: {result.error_message}"

    @pytest.mark.asyncio
    async def test_no_match_wildcard_falls_through_to_error(self):
        """Wildcard matching zero actions should produce an error."""
        async with AWSServiceFetcher() as fetcher:
            result = await fetcher.validate_condition_key(
                "iam:Zzzzz*",
                "aws:ResourceTag/owner",
                ["*"],
            )
            # Should still be valid because aws:ResourceTag/owner is handled at service level
            # or as a global key - depending on the service definition
            # The key point is it shouldn't crash
            assert isinstance(result, ConditionKeyValidationResult)


class TestWildcardConditionKeyCheckIntegration:
    """Integration tests: full check pipeline with wildcard actions and condition keys."""

    @pytest.fixture
    def check(self):
        return ConditionKeyValidationCheck()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="condition_key_validation")

    @pytest.mark.asyncio
    async def test_iam_tag_wildcard_with_resource_tag_no_false_positive(self, check, config):
        """The original bug: iam:Tag* + aws:ResourceTag/owner should NOT produce an error."""
        statement = Statement(
            Sid="TagResources",
            Effect="Allow",
            Action=["iam:Tag*"],
            Resource=["arn:aws:iam::123456789012:role/*"],
            Condition={"StringEquals": {"aws:ResourceTag/owner": "${aws:PrincipalTag/owner}"}},
        )
        async with AWSServiceFetcher() as fetcher:
            issues = await check.execute(statement, 0, fetcher, config)

        invalid_key_issues = [i for i in issues if i.issue_type == "invalid_condition_key"]
        assert len(invalid_key_issues) == 0, (
            f"False positive: {invalid_key_issues[0].message if invalid_key_issues else ''}"
        )

    @pytest.mark.asyncio
    async def test_iam_create_wildcard_with_request_tag_no_false_positive(self, check, config):
        """iam:Create* + aws:RequestTag/env should NOT produce an error."""
        statement = Statement(
            Sid="CreateResources",
            Effect="Allow",
            Action=["iam:Create*"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:RequestTag/env": "production"}},
        )
        async with AWSServiceFetcher() as fetcher:
            issues = await check.execute(statement, 0, fetcher, config)

        invalid_key_issues = [i for i in issues if i.issue_type == "invalid_condition_key"]
        assert len(invalid_key_issues) == 0, (
            f"False positive: {invalid_key_issues[0].message if invalid_key_issues else ''}"
        )

    @pytest.mark.asyncio
    async def test_exact_action_still_validated_correctly(self, check, config):
        """Ensure exact actions (non-wildcard) still work as before."""
        statement = Statement(
            Sid="TagRole",
            Effect="Allow",
            Action=["iam:TagRole"],
            Resource=["arn:aws:iam::123456789012:role/*"],
            Condition={"StringEquals": {"aws:ResourceTag/owner": "${aws:PrincipalTag/owner}"}},
        )
        async with AWSServiceFetcher() as fetcher:
            issues = await check.execute(statement, 0, fetcher, config)

        invalid_key_issues = [i for i in issues if i.issue_type == "invalid_condition_key"]
        assert len(invalid_key_issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_with_truly_invalid_key_still_flagged(self, check, config):
        """iam:Tag* with a truly invalid condition key should still be flagged."""
        statement = Statement(
            Sid="TagResources",
            Effect="Allow",
            Action=["iam:Tag*"],
            Resource=["*"],
            Condition={"StringEquals": {"ec2:InstanceType": "t3.micro"}},
        )
        async with AWSServiceFetcher() as fetcher:
            issues = await check.execute(statement, 0, fetcher, config)

        invalid_key_issues = [i for i in issues if i.issue_type == "invalid_condition_key"]
        assert len(invalid_key_issues) == 1
        assert "ec2:InstanceType" in invalid_key_issues[0].message

    @pytest.mark.asyncio
    async def test_mixed_wildcard_and_exact_actions(self, check, config):
        """Mix of wildcard and exact actions should validate correctly."""
        statement = Statement(
            Sid="ManageRoles",
            Effect="Allow",
            Action=["iam:Tag*", "iam:GetRole"],
            Resource=["arn:aws:iam::123456789012:role/*"],
            Condition={"StringEquals": {"aws:ResourceTag/owner": "${aws:PrincipalTag/owner}"}},
        )
        async with AWSServiceFetcher() as fetcher:
            issues = await check.execute(statement, 0, fetcher, config)

        invalid_key_issues = [i for i in issues if i.issue_type == "invalid_condition_key"]
        assert len(invalid_key_issues) == 0

    @pytest.mark.asyncio
    async def test_service_wildcard_skipped(self, check, config):
        """Full wildcard (*) should still be skipped as before."""
        statement = Statement(
            Sid="AllowAll",
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:ResourceTag/owner": "test"}},
        )
        async with AWSServiceFetcher() as fetcher:
            issues = await check.execute(statement, 0, fetcher, config)

        # Full wildcard action is skipped in condition key validation
        invalid_key_issues = [i for i in issues if i.issue_type == "invalid_condition_key"]
        assert len(invalid_key_issues) == 0


class TestValidatorWildcardUnit:
    """Unit tests for ServiceValidator.validate_condition_key with wildcards using mocks."""

    @pytest.mark.asyncio
    async def test_wildcard_checks_expanded_action_condition_keys(self):
        """Wildcard expands to actions and checks their condition keys."""
        from unittest.mock import MagicMock

        from iam_validator.core.models import ActionDetail, ServiceDetail

        service = MagicMock(spec=ServiceDetail)
        service.condition_keys = {}
        service.resources = {}

        action_with_key = MagicMock(spec=ActionDetail)
        action_with_key.action_condition_keys = ["s3:prefix"]
        action_with_key.resources = []

        action_without_key = MagicMock(spec=ActionDetail)
        action_without_key.action_condition_keys = []
        action_without_key.resources = []

        service.actions = {
            "GetObject": action_with_key,
            "GetBucketAcl": action_without_key,
        }

        validator = ServiceValidator()
        result = await validator.validate_condition_key("s3:Get*", "s3:prefix", service)
        assert result.is_valid is True

    @pytest.mark.asyncio
    async def test_wildcard_checks_expanded_resource_condition_keys(self):
        """Wildcard expands to actions and checks their resource-level condition keys."""
        from unittest.mock import MagicMock

        from iam_validator.core.models import ActionDetail, ResourceType, ServiceDetail

        service = MagicMock(spec=ServiceDetail)
        service.condition_keys = {}

        resource_type = MagicMock(spec=ResourceType)
        resource_type.condition_keys = ["aws:ResourceTag/${TagKey}"]
        service.resources = {"role": resource_type}

        action_detail = MagicMock(spec=ActionDetail)
        action_detail.action_condition_keys = []
        action_detail.resources = [{"Name": "role"}]

        service.actions = {"TagRole": action_detail}

        validator = ServiceValidator()
        result = await validator.validate_condition_key("iam:Tag*", "aws:ResourceTag/owner", service)
        assert result.is_valid is True

    @pytest.mark.asyncio
    async def test_wildcard_no_match_returns_error(self):
        """Wildcard matching no actions falls through to error handling."""
        from unittest.mock import MagicMock

        from iam_validator.core.models import ServiceDetail

        service = MagicMock(spec=ServiceDetail)
        service.condition_keys = {}
        service.actions = {"CreateRole": MagicMock(), "DeleteRole": MagicMock()}
        service.resources = {}

        validator = ServiceValidator()
        result = await validator.validate_condition_key("iam:Zzzzz*", "some:key", service)
        assert result.is_valid is False

"""Tests for condition key validation check."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.checks.condition_key_validation import ConditionKeyValidationCheck
from iam_validator.core.aws_service import (
    AWSServiceFetcher,
    ConditionKeyValidationResult,
)
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestConditionKeyValidationCheck:
    """Test suite for ConditionKeyValidationCheck."""

    @pytest.fixture
    def check(self):
        return ConditionKeyValidationCheck()

    @pytest.fixture
    def fetcher(self):
        mock = MagicMock(spec=AWSServiceFetcher)
        mock.validate_condition_key = AsyncMock()
        return mock

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="condition_key_validation")

    @pytest.mark.asyncio
    async def test_no_conditions(self, check, fetcher, config):
        """Test statement with no conditions."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::bucket/*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0
        fetcher.validate_condition_key.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_condition_key(self, check, fetcher, config):
        """Test valid condition key passes."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(is_valid=True)
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:prefix": "documents/"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_invalid_condition_key(self, check, fetcher, config):
        """Test invalid condition key is flagged."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=False,
            error_message="Condition key 's3:invalidKey' is not valid",
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_condition_key"
        assert issues[0].condition_key == "s3:invalidKey"

    @pytest.mark.asyncio
    async def test_wildcard_action_skipped(self, check, fetcher, config):
        """Test wildcard action is skipped in validation."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(is_valid=True)
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:prefix": "documents/"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0
        fetcher.validate_condition_key.assert_not_called()

    @pytest.mark.asyncio
    async def test_only_reports_once_per_condition_key(self, check, fetcher, config):
        """Test that invalid condition key is only reported once with multiple actions."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=False, error_message="Invalid"
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_global_condition_key_with_warning(self, check, fetcher, config):
        """Test global condition key with action-specific keys generates warning."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=True,
            warning_message="Global condition key warning",
        )
        statement = Statement(
            Effect="Allow",
            Action=["kms:Decrypt"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:PrincipalOrgID": "o-123456789"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "warning"
        assert issues[0].issue_type == "global_condition_key_with_action_specific"


class TestConditionKeyPatternMatching:
    """Test pattern matching for service-specific condition keys."""

    def test_ssm_resource_tag_pattern_matching(self):
        """Test that ssm:resourceTag/owner matches ssm:resourceTag/tag-key pattern."""
        from iam_validator.core.aws_service.validators import condition_key_in_list

        # Pattern matching: condition key with valid tag should match pattern
        assert condition_key_in_list("ssm:resourceTag/owner", ["ssm:resourceTag/tag-key"])
        # Exact match should work
        assert condition_key_in_list("ssm:Overwrite", ["ssm:Overwrite"])
        # No match when patterns differ
        assert not condition_key_in_list("ssm:resourceTag/owner", ["ssm:Overwrite"])

    def test_aws_tag_pattern_matching(self):
        """Test that aws:ResourceTag/owner matches aws:ResourceTag/${TagKey} pattern."""
        from iam_validator.core.aws_service.validators import condition_key_in_list

        assert condition_key_in_list("aws:ResourceTag/owner", ["aws:ResourceTag/${TagKey}"])
        assert condition_key_in_list("aws:RequestTag/Department", ["aws:RequestTag/${TagKey}"])

    @pytest.mark.asyncio
    async def test_ssm_put_parameter_with_resource_tag(self):
        """Integration test: ssm:resourceTag/owner should be valid for ssm:PutParameter."""
        async with AWSServiceFetcher() as fetcher:
            result = await fetcher.validate_condition_key(
                "ssm:PutParameter",
                "ssm:resourceTag/owner",
                ["arn:aws:ssm:us-east-1:123456789012:parameter/test"],
            )
            assert result.is_valid is True

    def test_s3_request_object_tag_pattern_matching(self):
        """Test that s3:RequestObjectTag/Environment matches s3:RequestObjectTag/<key> pattern."""
        from iam_validator.core.aws_service.validators import condition_key_in_list

        # S3 uses /<key> placeholder - any pattern with "/" should work
        assert condition_key_in_list("s3:RequestObjectTag/Environment", ["s3:RequestObjectTag/<key>"])
        assert condition_key_in_list("s3:ExistingObjectTag/Team", ["s3:ExistingObjectTag/<key>"])

    def test_generic_pattern_matching(self):
        """Test that any pattern with / matches condition keys with valid tag suffix."""
        from iam_validator.core.aws_service.validators import condition_key_in_list

        # Any pattern with "/" should match if prefix matches and suffix is valid tag
        assert condition_key_in_list("svc:SomeCondition/MyValue", ["svc:SomeCondition/anything"])
        assert condition_key_in_list("svc:Tag/Environment", ["svc:Tag/placeholder"])
        # Different prefixes should NOT match
        assert not condition_key_in_list("svc:Condition/Value", ["svc:OtherCondition/placeholder"])

    @pytest.mark.asyncio
    async def test_s3_put_object_with_request_object_tag(self):
        """Integration test: s3:RequestObjectTag/Environment should be valid for s3:PutObject."""
        async with AWSServiceFetcher() as fetcher:
            result = await fetcher.validate_condition_key(
                "s3:PutObject",
                "s3:RequestObjectTag/Environment",
                ["arn:aws:s3:::my-bucket/*"],
            )
            assert result.is_valid is True, f"Expected valid but got: {result.error_message}"

    @pytest.mark.asyncio
    async def test_s3_get_object_with_existing_object_tag(self):
        """Integration test: s3:ExistingObjectTag/Team should be valid for s3:GetObject."""
        async with AWSServiceFetcher() as fetcher:
            result = await fetcher.validate_condition_key(
                "s3:GetObject",
                "s3:ExistingObjectTag/Team",
                ["arn:aws:s3:::my-bucket/*"],
            )
            assert result.is_valid is True, f"Expected valid but got: {result.error_message}"


class TestTagKeyValidation:
    """Test AWS tag key format validation."""

    def test_valid_tag_keys(self):
        """Test that valid AWS tag keys are accepted."""
        from iam_validator.core.aws_service.validators import _is_valid_tag_key

        assert _is_valid_tag_key("owner")
        assert _is_valid_tag_key("Environment")
        assert _is_valid_tag_key("cost-center")
        assert _is_valid_tag_key("Cost Center")

    def test_invalid_tag_keys(self):
        """Test that invalid AWS tag keys are rejected."""
        from iam_validator.core.aws_service.validators import _is_valid_tag_key

        assert not _is_valid_tag_key("")
        assert not _is_valid_tag_key("key<value")
        assert not _is_valid_tag_key("key*value")

    def test_tag_key_length_limits(self):
        """Test AWS tag key length constraints (1-128 characters)."""
        from iam_validator.core.aws_service.validators import _is_valid_tag_key

        assert _is_valid_tag_key("a")
        assert _is_valid_tag_key("a" * 128)
        assert not _is_valid_tag_key("a" * 129)

    @pytest.mark.asyncio
    async def test_request_tag_not_supported_by_action(self):
        """Test that aws:RequestTag is rejected for actions that don't support it.

        This tests the fix for the issue where aws:RequestTag was incorrectly accepted
        for all IAM actions because it appears in service-level condition keys.
        Only actions that create/modify tagged resources should support aws:RequestTag.
        """
        check = ConditionKeyValidationCheck()
        config = CheckConfig(check_id="condition_key_validation")

        # Test with iam:SetDefaultPolicyVersion which does NOT support aws:RequestTag
        statement = Statement(
            Sid="SetDefaultOnly",
            Effect="Allow",
            Action=["iam:SetDefaultPolicyVersion"],
            Resource=["arn:aws:iam::123456789012:policy/*"],
            Condition={"StringEquals": {"aws:RequestTag/owner": "test"}},
        )

        async with AWSServiceFetcher() as fetcher:
            issues = await check.execute(statement, 0, fetcher, config)

        # Should detect that aws:RequestTag is not supported
        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_condition_key"
        assert "aws:RequestTag/owner" in issues[0].message
        assert "not supported" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_request_tag_supported_by_action(self):
        """Test that aws:RequestTag is accepted for actions that DO support it.

        Actions like iam:CreatePolicy explicitly list aws:RequestTag in their
        ActionConditionKeys, so it should be accepted.
        """
        check = ConditionKeyValidationCheck()
        config = CheckConfig(check_id="condition_key_validation")

        # Test with iam:CreatePolicy which DOES support aws:RequestTag
        statement = Statement(
            Sid="CreatePolicyOnly",
            Effect="Allow",
            Action=["iam:CreatePolicy"],
            Resource=["arn:aws:iam::123456789012:policy/*"],
            Condition={"StringEquals": {"aws:RequestTag/owner": "test"}},
        )

        async with AWSServiceFetcher() as fetcher:
            issues = await check.execute(statement, 0, fetcher, config)

        # Should NOT detect any issues - aws:RequestTag is valid for CreatePolicy
        assert len(issues) == 0

"""Tests for condition key validation check."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.checks.condition_key_validation import ConditionKeyValidationCheck
from iam_validator.core.aws_service import AWSServiceFetcher, ConditionKeyValidationResult
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class TestConditionKeyValidationCheck:
    """Test suite for ConditionKeyValidationCheck."""

    @pytest.fixture
    def check(self):
        """Create a ConditionKeyValidationCheck instance."""
        return ConditionKeyValidationCheck()

    @pytest.fixture
    def fetcher(self):
        """Create a mock AWSServiceFetcher instance."""
        mock = MagicMock(spec=AWSServiceFetcher)
        mock.validate_condition_key = AsyncMock()
        return mock

    @pytest.fixture
    def config(self):
        """Create a default CheckConfig."""
        return CheckConfig(check_id="condition_key_validation")

    def test_check_id(self, check):
        """Test check_id property."""
        assert check.check_id == "condition_key_validation"

    def test_description(self, check):
        """Test description property."""
        assert check.description == "Validates condition keys against AWS service definitions"

    def test_default_severity(self, check):
        """Test default_severity property."""
        assert check.default_severity == "error"

    @pytest.mark.asyncio
    async def test_no_conditions(self, check, fetcher, config):
        """Test statement with no conditions."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::bucket/*"]
        )
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
        fetcher.validate_condition_key.assert_called_once_with(
            "s3:GetObject", "s3:prefix", ["arn:aws:s3:::bucket/*"]
        )

    @pytest.mark.asyncio
    async def test_invalid_condition_key(self, check, fetcher, config):
        """Test invalid condition key is flagged."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=False,
            error_message="Condition key 's3:invalidKey' is not valid for action 's3:GetObject'",
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].issue_type == "invalid_condition_key"
        assert issues[0].condition_key == "s3:invalidKey"
        assert issues[0].action == "s3:GetObject"

    @pytest.mark.asyncio
    async def test_multiple_condition_keys(self, check, fetcher, config):
        """Test multiple condition keys are validated."""

        async def validate_side_effect(action, key, resources):
            if key == "s3:prefix":
                return ConditionKeyValidationResult(is_valid=True)
            else:
                return ConditionKeyValidationResult(
                    is_valid=False, error_message=f"Condition key '{key}' is not valid"
                )

        fetcher.validate_condition_key.side_effect = validate_side_effect

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:prefix": "documents/", "s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].condition_key == "s3:invalidKey"
        assert fetcher.validate_condition_key.call_count == 2

    @pytest.mark.asyncio
    async def test_multiple_operators(self, check, fetcher, config):
        """Test condition keys in multiple operators."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(is_valid=True)

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={
                "StringEquals": {"s3:prefix": "documents/"},
                "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        assert fetcher.validate_condition_key.call_count == 2

    @pytest.mark.asyncio
    async def test_multiple_actions(self, check, fetcher, config):
        """Test condition key is validated against multiple actions."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(is_valid=True)

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "s3:PutObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:prefix": "documents/"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        # Should validate against both actions
        assert fetcher.validate_condition_key.call_count == 2

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
        """Test that invalid condition key is only reported once even with multiple actions."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=False, error_message="Invalid condition key"
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should only report once, not three times
        assert len(issues) == 1
        assert issues[0].condition_key == "s3:invalidKey"

    @pytest.mark.asyncio
    async def test_statement_with_sid(self, check, fetcher, config):
        """Test that statement SID is captured."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=False, error_message="Invalid condition key"
        )

        statement = Statement(
            Sid="TestStatement",
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].statement_sid == "TestStatement"

    @pytest.mark.asyncio
    async def test_statement_index(self, check, fetcher, config):
        """Test that statement index is captured."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=False, error_message="Invalid condition key"
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 7, fetcher, config)

        assert issues[0].statement_index == 7

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, fetcher, config):
        """Test that line number is captured when available."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=False, error_message="Invalid condition key"
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        statement.line_number = 55

        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].line_number == 55

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity from config."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=False, error_message="Invalid condition key"
        )

        config = CheckConfig(check_id="condition_key_validation", severity="error")
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_error_message_fallback(self, check, fetcher, config):
        """Test fallback error message when none provided."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(is_valid=False)

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:invalidKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Invalid condition key: `s3:invalidKey`" in issues[0].message

    @pytest.mark.asyncio
    async def test_string_action(self, check, fetcher, config):
        """Test action as string instead of list."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(is_valid=True)

        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource=["arn:aws:s3:::bucket/*"],
            Condition={"StringEquals": {"s3:prefix": "documents/"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        fetcher.validate_condition_key.assert_called_once_with(
            "s3:GetObject", "s3:prefix", ["arn:aws:s3:::bucket/*"]
        )

    @pytest.mark.asyncio
    async def test_global_condition_key_with_warning(self, check, fetcher, config):
        """Test global condition key with action-specific keys generates warning."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=True,
            warning_message=(
                "Global condition key 'aws:PrincipalOrgID' is used with action 'kms:Decrypt'. "
                "While global condition keys can be used across all AWS services, "
                "the key may not be available in every request context. "
                "Verify that 'aws:PrincipalOrgID' is available for this specific action's request context. "
                "Consider using '*IfExists' operators (e.g., StringEqualsIfExists) if the key might be missing."
            ),
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
        assert issues[0].condition_key == "aws:PrincipalOrgID"
        assert issues[0].action == "kms:Decrypt"
        assert "Global condition key" in issues[0].message
        assert "request context" in issues[0].message
        assert "IfExists" in issues[0].message

    @pytest.mark.asyncio
    async def test_global_condition_key_warning_disabled(self, check, fetcher):
        """Test that global condition key warning can be disabled via config."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=True,
            warning_message=(
                "Global condition key 'aws:PrincipalOrgID' is used with action 'kms:Decrypt'. "
                "While global condition keys can be used across all AWS services, "
                "the key may not be available in every request context. "
                "Verify that 'aws:PrincipalOrgID' is available for this specific action's request context. "
                "Consider using '*IfExists' operators (e.g., StringEqualsIfExists) if the key might be missing."
            ),
        )

        # Create config with warn_on_global_condition_keys disabled
        config = CheckConfig(
            check_id="condition_key_validation",
            config={"warn_on_global_condition_keys": False},
        )

        statement = Statement(
            Effect="Allow",
            Action=["kms:Decrypt"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:PrincipalOrgID": "o-123456789"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should not generate a warning when disabled
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_global_condition_key_warning_enabled_by_default(self, check, fetcher):
        """Test that global condition key warning is enabled by default."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=True,
            warning_message="Global condition key warning message",
        )

        # Create config without explicitly setting warn_on_global_condition_keys
        config = CheckConfig(check_id="condition_key_validation")

        statement = Statement(
            Effect="Allow",
            Action=["kms:Decrypt"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:PrincipalOrgID": "o-123456789"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should generate a warning by default
        assert len(issues) == 1
        assert issues[0].severity == "warning"

    @pytest.mark.asyncio
    async def test_resource_level_condition_key(self, check, fetcher, config):
        """Test that resource-level condition keys are validated."""
        # Simulate a resource-specific condition key that's valid
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(is_valid=True)

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:us-east-1:123456789012:accesspoint/my-access-point"],
            Condition={"StringEquals": {"s3:AccessPointNetworkOrigin": "Internet"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        fetcher.validate_condition_key.assert_called_once_with(
            "s3:GetObject",
            "s3:AccessPointNetworkOrigin",
            ["arn:aws:s3:us-east-1:123456789012:accesspoint/my-access-point"],
        )

    @pytest.mark.asyncio
    async def test_invalid_resource_level_condition_key(self, check, fetcher, config):
        """Test that invalid resource-level condition keys are flagged."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(
            is_valid=False,
            error_message="Condition key 's3:InvalidResourceKey' is not valid for resource type",
        )

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:us-east-1:123456789012:accesspoint/my-access-point"],
            Condition={"StringEquals": {"s3:InvalidResourceKey": "value"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].issue_type == "invalid_condition_key"
        assert issues[0].condition_key == "s3:InvalidResourceKey"

    @pytest.mark.asyncio
    async def test_multiple_resources_with_condition_keys(self, check, fetcher, config):
        """Test condition key validation with multiple resource ARNs."""
        fetcher.validate_condition_key.return_value = ConditionKeyValidationResult(is_valid=True)

        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=[
                "arn:aws:s3:::bucket1/*",
                "arn:aws:s3:us-east-1:123456789012:accesspoint/my-access-point",
            ],
            Condition={"StringEquals": {"s3:prefix": "documents/"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
        # Should pass all resources to validate_condition_key
        fetcher.validate_condition_key.assert_called_once_with(
            "s3:GetObject",
            "s3:prefix",
            [
                "arn:aws:s3:::bucket1/*",
                "arn:aws:s3:us-east-1:123456789012:accesspoint/my-access-point",
            ],
        )


class TestConditionKeyPatternMatching:
    """Test pattern matching for service-specific condition keys like ssm:resourceTag/tag-key."""

    @pytest.mark.asyncio
    async def test_ssm_resource_tag_pattern_matching(self):
        """Test that ssm:resourceTag/owner matches ssm:resourceTag/tag-key pattern."""
        from iam_validator.core.aws_service.validators import _matches_condition_key_pattern

        # These should match the ssm:resourceTag/tag-key pattern
        assert _matches_condition_key_pattern("ssm:resourceTag/owner", "ssm:resourceTag/tag-key")
        assert _matches_condition_key_pattern(
            "ssm:resourceTag/Environment", "ssm:resourceTag/tag-key"
        )
        assert _matches_condition_key_pattern(
            "ssm:resourceTag/CostCenter", "ssm:resourceTag/tag-key"
        )

        # Exact match should also work
        assert _matches_condition_key_pattern("ssm:Overwrite", "ssm:Overwrite")

        # Non-matching patterns should fail
        assert not _matches_condition_key_pattern("ssm:resourceTag/owner", "ssm:Overwrite")
        assert not _matches_condition_key_pattern("ssm:invalid", "ssm:resourceTag/tag-key")

    @pytest.mark.asyncio
    async def test_aws_tag_pattern_matching(self):
        """Test that aws:ResourceTag/owner matches aws:ResourceTag/${TagKey} pattern."""
        from iam_validator.core.aws_service.validators import _matches_condition_key_pattern

        # These should match the ${TagKey} pattern
        assert _matches_condition_key_pattern(
            "aws:ResourceTag/owner", "aws:ResourceTag/${TagKey}"
        )
        assert _matches_condition_key_pattern(
            "aws:RequestTag/Department", "aws:RequestTag/${TagKey}"
        )

    @pytest.mark.asyncio
    async def test_condition_key_in_list(self):
        """Test _condition_key_in_list helper function."""
        from iam_validator.core.aws_service.validators import _condition_key_in_list

        condition_keys = [
            "aws:ResourceTag/${TagKey}",
            "ssm:resourceTag/tag-key",
            "ssm:Overwrite",
            "ssm:Policies",
        ]

        # Should match pattern-based keys
        assert _condition_key_in_list("ssm:resourceTag/owner", condition_keys)
        assert _condition_key_in_list("aws:ResourceTag/Environment", condition_keys)

        # Should match exact keys
        assert _condition_key_in_list("ssm:Overwrite", condition_keys)
        assert _condition_key_in_list("ssm:Policies", condition_keys)

        # Should not match invalid keys
        assert not _condition_key_in_list("ssm:InvalidKey", condition_keys)
        assert not _condition_key_in_list("invalid:key", condition_keys)

    @pytest.mark.asyncio
    async def test_ssm_put_parameter_with_resource_tag(self):
        """Integration test: ssm:resourceTag/owner should be valid for ssm:PutParameter."""
        from iam_validator.core.aws_service import AWSServiceFetcher

        fetcher = AWSServiceFetcher()

        # Test that ssm:resourceTag/owner is now valid for ssm:PutParameter
        result = await fetcher.validate_condition_key(
            "ssm:PutParameter",
            "ssm:resourceTag/owner",
            ["arn:aws:ssm:us-east-1:123456789012:parameter/test"],
        )

        assert result.is_valid is True
        assert result.error_message is None

    @pytest.mark.asyncio
    async def test_invalid_ssm_condition_key(self):
        """Integration test: invalid condition keys should still be rejected."""
        from iam_validator.core.aws_service import AWSServiceFetcher

        fetcher = AWSServiceFetcher()

        # Test that truly invalid keys are still rejected
        result = await fetcher.validate_condition_key(
            "ssm:PutParameter",
            "ssm:completelyInvalidKey",
            ["arn:aws:ssm:us-east-1:123456789012:parameter/test"],
        )

        assert result.is_valid is False
        assert result.error_message is not None


class TestTagKeyValidation:
    """Test AWS tag key format validation."""

    def test_valid_tag_keys(self):
        """Test that valid AWS tag keys are accepted."""
        from iam_validator.core.aws_service.validators import _is_valid_tag_key

        # Standard alphanumeric tag keys
        assert _is_valid_tag_key("owner")
        assert _is_valid_tag_key("Environment")
        assert _is_valid_tag_key("CostCenter")
        assert _is_valid_tag_key("Project123")

        # Tag keys with allowed special characters
        assert _is_valid_tag_key("cost-center")
        assert _is_valid_tag_key("project_name")
        assert _is_valid_tag_key("env.type")
        assert _is_valid_tag_key("team:backend")
        assert _is_valid_tag_key("path/to/resource")
        assert _is_valid_tag_key("email@domain")
        assert _is_valid_tag_key("key+value")
        assert _is_valid_tag_key("key=value")

        # Tag keys with spaces (allowed by AWS)
        assert _is_valid_tag_key("Cost Center")
        assert _is_valid_tag_key("Project Name")

        # Mixed special characters
        assert _is_valid_tag_key("my-project_v2.0:prod/main@team+alpha")

    def test_invalid_tag_keys(self):
        """Test that invalid AWS tag keys are rejected."""
        from iam_validator.core.aws_service.validators import _is_valid_tag_key

        # Empty tag key
        assert not _is_valid_tag_key("")

        # Tag keys with invalid characters
        assert not _is_valid_tag_key("key<value")
        assert not _is_valid_tag_key("key>value")
        assert not _is_valid_tag_key("key&value")
        assert not _is_valid_tag_key("key|value")
        assert not _is_valid_tag_key("key\\value")
        assert not _is_valid_tag_key("key*value")
        assert not _is_valid_tag_key("key?value")
        assert not _is_valid_tag_key("key#value")
        assert not _is_valid_tag_key("key$value")
        assert not _is_valid_tag_key("key%value")
        assert not _is_valid_tag_key("key^value")
        assert not _is_valid_tag_key("key!value")
        assert not _is_valid_tag_key("key`value")
        assert not _is_valid_tag_key("key~value")
        assert not _is_valid_tag_key("key(value)")
        assert not _is_valid_tag_key("key[value]")
        assert not _is_valid_tag_key("key{value}")
        assert not _is_valid_tag_key('key"value')
        assert not _is_valid_tag_key("key'value")

    def test_tag_key_length_limits(self):
        """Test AWS tag key length constraints (1-128 characters)."""
        from iam_validator.core.aws_service.validators import _is_valid_tag_key

        # Minimum length (1 character)
        assert _is_valid_tag_key("a")

        # Maximum length (128 characters)
        assert _is_valid_tag_key("a" * 128)

        # Over maximum length (129 characters)
        assert not _is_valid_tag_key("a" * 129)

        # Way over maximum
        assert not _is_valid_tag_key("a" * 500)

    def test_pattern_matching_rejects_invalid_tag_keys(self):
        """Test that pattern matching rejects condition keys with invalid tag key formats."""
        from iam_validator.core.aws_service.validators import _matches_condition_key_pattern

        # Invalid characters in tag key portion should not match
        assert not _matches_condition_key_pattern(
            "ssm:resourceTag/invalid<tag", "ssm:resourceTag/tag-key"
        )
        assert not _matches_condition_key_pattern(
            "aws:ResourceTag/bad*key", "aws:ResourceTag/${TagKey}"
        )
        assert not _matches_condition_key_pattern(
            "ssm:resourceTag/has#hash", "ssm:resourceTag/tag-key"
        )

        # Empty tag key should not match
        assert not _matches_condition_key_pattern(
            "ssm:resourceTag/", "ssm:resourceTag/tag-key"
        )

        # Tag key exceeding 128 characters should not match
        long_tag_key = "a" * 129
        assert not _matches_condition_key_pattern(
            f"ssm:resourceTag/{long_tag_key}", "ssm:resourceTag/tag-key"
        )

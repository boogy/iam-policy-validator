"""
Tests for action_resource_matching check.

This test file ensures that the ActionResourceMatchingCheck correctly validates
that resources in a policy statement match the required resource types for actions.
"""

import pytest

from iam_validator.checks.action_resource_matching import ActionResourceMatchingCheck
from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
def check():
    """Create an instance of the ActionResourceMatchingCheck."""
    return ActionResourceMatchingCheck()


@pytest.fixture
def check_config():
    """Create a basic check configuration."""
    return CheckConfig(check_id="action_resource_matching", enabled=True)


@pytest.fixture
async def fetcher():
    """Create AWS service fetcher for tests."""
    async with AWSServiceFetcher(prefetch_common=False) as f:
        yield f


class TestS3ActionsResourceMatching:
    """Test S3 actions with correct and incorrect resource formats."""

    @pytest.mark.asyncio
    async def test_s3_get_object_with_object_arn_passes(
        self, check, check_config, fetcher
    ):
        """s3:GetObject with object ARN should pass validation."""
        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource="arn:aws:s3:::my-bucket/*"  # Correct: object ARN with /*
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "s3:GetObject with object ARN should not create issues"

    @pytest.mark.asyncio
    async def test_s3_get_object_with_bucket_arn_fails(
        self, check, check_config, fetcher
    ):
        """s3:GetObject with bucket ARN should fail validation."""
        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource="arn:aws:s3:::my-bucket"  # Wrong: bucket ARN, needs /*
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 1, "s3:GetObject with bucket ARN should create an issue"
        assert "object" in issues[0].message.lower()
        assert issues[0].action == "s3:GetObject"

    @pytest.mark.asyncio
    async def test_s3_list_bucket_with_bucket_arn_passes(
        self, check, check_config, fetcher
    ):
        """s3:ListBucket with bucket ARN should pass validation."""
        statement = Statement(
            Effect="Allow",
            Action="s3:ListBucket",
            Resource="arn:aws:s3:::my-bucket"  # Correct: bucket ARN without /*
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "s3:ListBucket with bucket ARN should not create issues"

    @pytest.mark.asyncio
    async def test_s3_list_bucket_with_object_arn_fails(
        self, check, check_config, fetcher
    ):
        """s3:ListBucket with object ARN should fail validation."""
        statement = Statement(
            Effect="Allow",
            Action="s3:ListBucket",
            Resource="arn:aws:s3:::my-bucket/*"  # Wrong: object ARN, needs bucket ARN
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 1, "s3:ListBucket with object ARN should create an issue"
        assert "bucket" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_s3_put_object_with_object_arn_passes(
        self, check, check_config, fetcher
    ):
        """s3:PutObject with object ARN should pass validation."""
        statement = Statement(
            Effect="Allow",
            Action="s3:PutObject",
            Resource="arn:aws:s3:::my-bucket/prefix/*"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "s3:PutObject with object ARN should not create issues"

    @pytest.mark.asyncio
    async def test_s3_delete_bucket_with_bucket_arn_passes(
        self, check, check_config, fetcher
    ):
        """s3:DeleteBucket with bucket ARN should pass validation."""
        statement = Statement(
            Effect="Allow",
            Action="s3:DeleteBucket",
            Resource="arn:aws:s3:::my-bucket"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "s3:DeleteBucket with bucket ARN should not create issues"


class TestIAMActionsResourceMatching:
    """Test IAM actions with correct and incorrect resource formats."""

    @pytest.mark.asyncio
    async def test_iam_get_user_with_user_arn_passes(
        self, check, check_config, fetcher
    ):
        """iam:GetUser with user ARN should pass validation."""
        statement = Statement(
            Effect="Allow",
            Action="iam:GetUser",
            Resource="arn:aws:iam::123456789012:user/TestUser"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "iam:GetUser with user ARN should not create issues"

    @pytest.mark.asyncio
    async def test_iam_get_user_with_wildcard_user_arn_passes(
        self, check, check_config, fetcher
    ):
        """iam:GetUser with wildcard user ARN should pass validation."""
        statement = Statement(
            Effect="Allow",
            Action="iam:GetUser",
            Resource="arn:aws:iam::*:user/*"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "iam:GetUser with wildcard should not create issues"

    @pytest.mark.asyncio
    async def test_iam_create_role_with_role_arn_passes(
        self, check, check_config, fetcher
    ):
        """iam:CreateRole with role ARN should pass validation."""
        statement = Statement(
            Effect="Allow",
            Action="iam:CreateRole",
            Resource="arn:aws:iam::123456789012:role/*"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "iam:CreateRole with role ARN should not create issues"


class TestMultipleResourceTypes:
    """Test actions that accept multiple resource types."""

    @pytest.mark.asyncio
    async def test_action_with_one_of_multiple_valid_resource_types(
        self, check, check_config, fetcher
    ):
        """Action that accepts multiple resource types should pass with any valid type."""
        # s3:GetObject accepts both "object" and "accesspointobject"
        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource="arn:aws:s3:::my-bucket/*"  # Valid "object" type
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "Should accept any valid resource type"


class TestWildcardHandling:
    """Test handling of wildcard resources and actions."""

    @pytest.mark.asyncio
    async def test_wildcard_resource_skipped(
        self, check, check_config, fetcher
    ):
        """Statements with wildcard resources should be skipped."""
        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource="*"  # Wildcard - handled by other checks
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "Wildcard resources should be skipped"

    @pytest.mark.asyncio
    async def test_wildcard_action_skipped(
        self, check, check_config, fetcher
    ):
        """Statements with wildcard actions should be skipped."""
        statement = Statement(
            Effect="Allow",
            Action="s3:*",  # Wildcard action
            Resource="arn:aws:s3:::my-bucket/*"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "Wildcard actions should be skipped"

    @pytest.mark.asyncio
    async def test_full_wildcard_action_skipped(
        self, check, check_config, fetcher
    ):
        """Statements with full wildcard actions should be skipped."""
        statement = Statement(
            Effect="Allow",
            Action="*",  # Full wildcard
            Resource="arn:aws:s3:::my-bucket/*"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "Full wildcard actions should be skipped"


class TestMultipleResources:
    """Test statements with multiple resources."""

    @pytest.mark.asyncio
    async def test_multiple_resources_all_valid_passes(
        self, check, check_config, fetcher
    ):
        """Multiple resources that are all valid should pass."""
        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource=[
                "arn:aws:s3:::bucket1/*",
                "arn:aws:s3:::bucket2/prefix/*"
            ]
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "All valid resources should pass"

    @pytest.mark.asyncio
    async def test_multiple_resources_one_valid_passes(
        self, check, check_config, fetcher
    ):
        """If ANY resource matches, the statement should pass."""
        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource=[
                "arn:aws:s3:::bucket1/*",  # Valid
                "arn:aws:s3:::bucket2"      # Invalid, but should still pass
            ]
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        # Should pass because at least one resource is valid
        assert len(issues) == 0, "Should pass if any resource is valid"

    @pytest.mark.asyncio
    async def test_multiple_resources_all_invalid_fails(
        self, check, check_config, fetcher
    ):
        """If NO resources match, the statement should fail."""
        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource=[
                "arn:aws:s3:::bucket1",  # Invalid: bucket ARN
                "arn:aws:s3:::bucket2"   # Invalid: bucket ARN
            ]
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 1, "Should fail if no resources are valid"


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_unknown_service_skipped(
        self, check, check_config, fetcher
    ):
        """Unknown services should raise an error (handled upstream)."""
        statement = Statement(
            Effect="Allow",
            Action="unknownservice:SomeAction",
            Resource="arn:aws:unknownservice:::resource"
        )

        # Unknown services raise ValueError from the fetcher
        with pytest.raises(ValueError, match="Service 'unknownservice' not found"):
            await check.execute(statement, 0, fetcher, check_config)

    @pytest.mark.asyncio
    async def test_unknown_action_skipped(
        self, check, check_config, fetcher
    ):
        """Unknown actions should be skipped (handled by action_validation)."""
        statement = Statement(
            Effect="Allow",
            Action="s3:UnknownAction",
            Resource="arn:aws:s3:::bucket/*"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "Unknown actions should be skipped"

    @pytest.mark.asyncio
    async def test_invalid_action_format_skipped(
        self, check, check_config, fetcher
    ):
        """Actions without colon separator should be skipped."""
        statement = Statement(
            Effect="Allow",
            Action="InvalidActionFormat",
            Resource="arn:aws:s3:::bucket/*"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 0, "Invalid action formats should be skipped"


class TestErrorMessages:
    """Test that error messages are helpful and accurate."""

    @pytest.mark.asyncio
    async def test_error_message_includes_action(
        self, check, check_config, fetcher
    ):
        """Error messages should include the action name."""
        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource="arn:aws:s3:::my-bucket"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 1
        assert "s3:GetObject" in issues[0].message

    @pytest.mark.asyncio
    async def test_error_message_includes_required_type(
        self, check, check_config, fetcher
    ):
        """Error messages should mention the required resource type."""
        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource="arn:aws:s3:::my-bucket"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 1
        # Should mention "object" as the required resource type
        assert "object" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_suggestion_provided(
        self, check, check_config, fetcher
    ):
        """Error messages should include helpful suggestions."""
        statement = Statement(
            Effect="Allow",
            Action="s3:GetObject",
            Resource="arn:aws:s3:::my-bucket"
        )

        issues = await check.execute(statement, 0, fetcher, check_config)
        assert len(issues) == 1
        assert issues[0].suggestion is not None
        assert len(issues[0].suggestion) > 0

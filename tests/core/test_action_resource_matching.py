"""Tests for action_resource_matching check."""

import pytest

from iam_validator.checks.action_resource_matching import ActionResourceMatchingCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
def check():
    return ActionResourceMatchingCheck()


@pytest.fixture
def check_config():
    return CheckConfig(check_id="action_resource_matching", enabled=True)


@pytest.fixture
async def fetcher():
    async with AWSServiceFetcher(prefetch_common=False) as f:
        yield f


# Consolidated: pass/fail validation tests
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action,resource,should_pass,desc",
    [
        # S3 object actions - need /* suffix
        ("s3:GetObject", "arn:aws:s3:::my-bucket/*", True, "object action with object ARN"),
        ("s3:GetObject", "arn:aws:s3:::my-bucket", False, "object action with bucket ARN"),
        ("s3:PutObject", "arn:aws:s3:::my-bucket/prefix/*", True, "put object with path"),
        # S3 bucket actions - no /* suffix
        ("s3:ListBucket", "arn:aws:s3:::my-bucket", True, "bucket action with bucket ARN"),
        ("s3:ListBucket", "arn:aws:s3:::my-bucket/*", False, "bucket action with object ARN"),
        ("s3:DeleteBucket", "arn:aws:s3:::my-bucket", True, "delete bucket"),
        # IAM actions
        ("iam:GetUser", "arn:aws:iam::123456789012:user/TestUser", True, "IAM user action"),
        ("iam:GetUser", "arn:aws:iam::*:user/*", True, "IAM with wildcards"),
        ("iam:CreateRole", "arn:aws:iam::123456789012:role/*", True, "IAM role action"),
    ],
)
async def test_action_resource_matching(
    check, check_config, fetcher, action, resource, should_pass, desc
):
    """Test action-resource matching for various combinations."""
    statement = Statement(Effect="Allow", Action=action, Resource=resource)
    issues = await check.execute(statement, 0, fetcher, check_config)
    if should_pass:
        assert len(issues) == 0, f"Should pass: {desc}"
    else:
        assert len(issues) >= 1, f"Should fail: {desc}"


# Consolidated: wildcard handling tests
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action,resource",
    [
        ("s3:GetObject", "*"),  # Wildcard resource
        ("s3:*", "arn:aws:s3:::my-bucket/*"),  # Wildcard action
        ("*", "arn:aws:s3:::my-bucket/*"),  # Full wildcard action
    ],
)
async def test_wildcard_handling_skipped(check, check_config, fetcher, action, resource):
    """Wildcard resources and actions should be skipped."""
    statement = Statement(Effect="Allow", Action=action, Resource=resource)
    issues = await check.execute(statement, 0, fetcher, check_config)
    assert len(issues) == 0


# Consolidated: multiple resources tests
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "resources,should_pass",
    [
        (["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2/prefix/*"], True),
        (["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2"], True),  # Any valid = pass
        (["arn:aws:s3:::bucket1", "arn:aws:s3:::bucket2"], False),  # All invalid = fail
    ],
)
async def test_multiple_resources(check, check_config, fetcher, resources, should_pass):
    """Test statements with multiple resources."""
    statement = Statement(Effect="Allow", Action="s3:GetObject", Resource=resources)
    issues = await check.execute(statement, 0, fetcher, check_config)
    if should_pass:
        assert len(issues) == 0
    else:
        assert len(issues) >= 1


# Consolidated: edge cases
@pytest.mark.asyncio
async def test_unknown_service_raises(check, check_config, fetcher):
    """Unknown services should raise ValueError."""
    statement = Statement(
        Effect="Allow",
        Action="unknownservice:SomeAction",
        Resource="arn:aws:unknownservice:::resource",
    )
    with pytest.raises(ValueError, match="Service `unknownservice` not found"):
        await check.execute(statement, 0, fetcher, check_config)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action",
    ["s3:UnknownAction", "InvalidActionFormat"],
)
async def test_invalid_actions_skipped(check, check_config, fetcher, action):
    """Unknown or invalid actions should be skipped."""
    statement = Statement(Effect="Allow", Action=action, Resource="arn:aws:s3:::bucket/*")
    issues = await check.execute(statement, 0, fetcher, check_config)
    assert len(issues) == 0


# Consolidated: error message quality
@pytest.mark.asyncio
async def test_error_message_quality(check, check_config, fetcher):
    """Error messages should include action, resource type, and suggestion."""
    statement = Statement(
        Effect="Allow", Action="s3:GetObject", Resource="arn:aws:s3:::my-bucket"
    )
    issues = await check.execute(statement, 0, fetcher, check_config)
    assert len(issues) == 1
    assert "s3:GetObject" in issues[0].message
    assert "object" in issues[0].message.lower()
    assert issues[0].suggestion


# Consolidated: template variable support
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action,resource",
    [
        ("iam:GetRole", "arn:aws:iam::${aws_account_id}:role/my-role"),
        ("iam:GetRole", "arn:aws:iam::${AWS::AccountId}:role/CloudFormationRole"),
        ("s3:GetObject", "arn:aws:s3:::${bucket_name}/*"),
        ("s3:GetObject", "arn:aws:s3:::my-bucket/${aws:username}/*"),
        ("secretsmanager:GetSecretValue", "arn:aws:secretsmanager:us-east-1:${aws_account_id}:secret:my-secret-*"),
        ("iam:GetRole", "arn:aws:iam::${aws_account_id}:role/${environment}-*"),
        ("iam:GetRole", "arn:aws:iam::${var.my_custom_account}:role/MyRole"),
        ("s3:GetObject", "arn:aws:s3:::${data.s3_bucket.name}/*"),
        ("s3:GetObject", "arn:${var.partition}:s3:::${var.bucket}/*"),
    ],
)
async def test_template_variables_supported(check, check_config, fetcher, action, resource):
    """Template variables in ARNs should be normalized and pass validation."""
    statement = Statement(Effect="Allow", Action=action, Resource=resource)
    issues = await check.execute(statement, 0, fetcher, check_config)
    assert len(issues) == 0


@pytest.mark.asyncio
async def test_template_variable_still_detects_mismatch(check, check_config, fetcher):
    """Template variables should normalize but still catch resource mismatches."""
    statement = Statement(
        Effect="Allow",
        Action="s3:GetObject",
        Resource="arn:aws:s3:::${bucket_name}",  # Missing /* - still wrong!
    )
    issues = await check.execute(statement, 0, fetcher, check_config)
    assert len(issues) == 1
    assert "object" in issues[0].message.lower()

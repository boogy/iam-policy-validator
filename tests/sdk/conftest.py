"""Shared fixtures for SDK tests."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import (
    ActionDetail,
    ConditionKey,
    IAMPolicy,
    ResourceType,
    ServiceDetail,
)

# ---------------------------------------------------------------------------
# Sample policies
# ---------------------------------------------------------------------------


@pytest.fixture
def valid_policy_dict():
    """Minimal valid identity policy as a dict."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ],
    }


@pytest.fixture
def valid_policy(valid_policy_dict):
    """Minimal valid IAMPolicy model."""
    return IAMPolicy(**valid_policy_dict)


@pytest.fixture
def wildcard_policy_dict():
    """Policy with wildcard Action and Resource."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }


@pytest.fixture
def multi_statement_policy_dict():
    """Policy with Allow + Deny statements."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRead",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
            },
            {
                "Sid": "DenyDelete",
                "Effect": "Deny",
                "Action": "s3:DeleteObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            },
        ],
    }


@pytest.fixture
def resource_policy_dict():
    """S3 bucket resource policy with Principal."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ],
    }


@pytest.fixture
def public_access_policy_dict():
    """Policy with Principal: '*' (public access)."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-bucket/*",
            }
        ],
    }


@pytest.fixture
def condition_policy_dict():
    """Policy with Condition block."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceVpc": "vpc-12345"},
                    "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
                },
            }
        ],
    }


@pytest.fixture
def not_action_policy_dict():
    """Policy using NotAction / NotResource."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "NotAction": ["iam:ChangePassword", "iam:GetUser"],
                "NotResource": "arn:aws:iam::123456789012:user/${aws:username}",
            }
        ],
    }


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_policy_file(valid_policy_dict, tmp_path):
    """Write a valid policy to a temp JSON file."""
    fp = tmp_path / "test_policy.json"
    fp.write_text(json.dumps(valid_policy_dict, indent=2))
    return fp


@pytest.fixture
def tmp_policy_dir(valid_policy_dict, wildcard_policy_dict, tmp_path):
    """Directory with two policy files."""
    (tmp_path / "policy1.json").write_text(json.dumps(valid_policy_dict, indent=2))
    (tmp_path / "policy2.json").write_text(json.dumps(wildcard_policy_dict, indent=2))
    return tmp_path


@pytest.fixture
def tmp_nested_policy_dir(valid_policy_dict, tmp_path):
    """Directory with a nested sub-directory containing a policy."""
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "nested_policy.json").write_text(json.dumps(valid_policy_dict, indent=2))
    return tmp_path


# ---------------------------------------------------------------------------
# Mock AWSServiceFetcher
# ---------------------------------------------------------------------------


def _make_service_detail():
    """Build a realistic mock ServiceDetail for 's3'."""
    return ServiceDetail(
        Name="Amazon S3",
        Actions=[
            ActionDetail(
                Name="GetObject",
                ActionConditionKeys=["s3:x-amz-acl"],
                Resources=[{"Name": "object"}],
                Annotations={
                    "Description": "Read an object",
                    "Properties": {"IsWrite": False},
                },
            ),
            ActionDetail(
                Name="PutObject",
                ActionConditionKeys=["s3:x-amz-acl"],
                Resources=[{"Name": "object"}],
                Annotations={
                    "Description": "Write an object",
                    "Properties": {"IsWrite": True},
                },
            ),
            ActionDetail(
                Name="ListBuckets",
                ActionConditionKeys=[],
                Resources=[],
                Annotations={
                    "Description": "List all buckets",
                    "Properties": {"IsList": True},
                },
            ),
            ActionDetail(
                Name="DeleteBucket",
                ActionConditionKeys=[],
                Resources=[{"Name": "bucket"}],
                Annotations={
                    "Description": "Delete a bucket",
                    "Properties": {"IsWrite": True},
                },
            ),
            ActionDetail(
                Name="PutBucketPolicy",
                ActionConditionKeys=[],
                Resources=[{"Name": "bucket"}],
                Annotations={
                    "Description": "Set bucket policy",
                    "Properties": {"IsPermissionManagement": True},
                },
            ),
        ],
        Resources=[
            ResourceType(
                Name="bucket",
                ARNFormats=["arn:${Partition}:s3:::${BucketName}"],
                ConditionKeys=["s3:ResourceAccount"],
            ),
            ResourceType(
                Name="object",
                ARNFormats=["arn:${Partition}:s3:::${BucketName}/${ObjectName}"],
                ConditionKeys=["s3:ResourceAccount"],
            ),
        ],
        ConditionKeys=[
            ConditionKey(
                Name="s3:x-amz-acl",
                Description="Filter by canned ACL",
                Types=["String"],
            ),
            ConditionKey(
                Name="s3:prefix",
                Description="Filter by key prefix",
                Types=["String"],
            ),
            ConditionKey(
                Name="s3:ResourceAccount",
                Description="Filter by resource account",
                Types=["String"],
            ),
        ],
    )


@pytest.fixture
def mock_service_detail():
    """A realistic ServiceDetail for testing query functions."""
    return _make_service_detail()


@pytest.fixture
def mock_fetcher(mock_service_detail):
    """Mock AWSServiceFetcher that returns realistic service data."""
    fetcher = MagicMock()
    fetcher.validate_action = AsyncMock(return_value=(True, None, False))
    fetcher.expand_wildcard_action = AsyncMock(return_value=["s3:GetObject", "s3:PutObject"])
    fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
    # Support async context manager
    fetcher.__aenter__ = AsyncMock(return_value=fetcher)
    fetcher.__aexit__ = AsyncMock(return_value=False)
    return fetcher


@pytest.fixture
def default_config():
    """Default check configuration."""
    return CheckConfig(check_id="test_check", enabled=True)

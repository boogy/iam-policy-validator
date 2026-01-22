"""Shared fixtures for MCP server tests.

This module provides common fixtures for testing the MCP server implementation,
including mock AWS service fetchers, sample policies, and test configurations.

Note: These tests require the optional 'mcp' extra (fastmcp package).
      Tests will be skipped if fastmcp is not installed.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement, ValidationIssue


@pytest.fixture
def mock_fetcher():
    """Mock AWSServiceFetcher for tests.

    Returns a MagicMock that simulates AWS service fetcher behavior without
    making real API calls. Configured with common return values.
    """
    fetcher = MagicMock()

    # Mock validate_action - returns (is_valid, error, is_wildcard)
    async def mock_validate_action(action: str):
        if action == "*":
            return True, None, True
        elif ":" not in action:
            return False, "Invalid action format", False
        elif action.startswith("invalid:"):
            return False, "Invalid service", False
        elif "*" in action:
            return True, None, True
        else:
            return True, None, False

    fetcher.validate_action = AsyncMock(side_effect=mock_validate_action)

    # Mock expand_wildcard_action
    async def mock_expand_wildcard(pattern: str):
        if pattern == "s3:Get*":
            return ["s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectVersion"]
        elif pattern == "s3:*":
            return ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
        elif pattern == "iam:*User*":
            return ["iam:CreateUser", "iam:DeleteUser", "iam:GetUser", "iam:UpdateUser"]
        else:
            raise ValueError(f"Cannot expand wildcard: {pattern}")

    fetcher.expand_wildcard_action = AsyncMock(side_effect=mock_expand_wildcard)

    # Mock fetch_service_by_name
    async def mock_fetch_service(service: str):
        if service == "s3":
            service_mock = MagicMock()
            service_mock.service_prefix = "s3"
            service_mock.actions = [
                {"name": "GetObject", "access_level": "Read"},
                {"name": "PutObject", "access_level": "Write"},
                {"name": "ListBucket", "access_level": "List"},
            ]
            service_mock.condition_keys = [
                "s3:prefix",
                "s3:x-amz-acl",
                "aws:SecureTransport",
            ]
            return service_mock
        elif service == "iam":
            service_mock = MagicMock()
            service_mock.service_prefix = "iam"
            service_mock.actions = [
                {"name": "CreateUser", "access_level": "Write"},
                {"name": "GetUser", "access_level": "Read"},
                {"name": "PassRole", "access_level": "Write"},
            ]
            service_mock.condition_keys = [
                "iam:PassedToService",
                "iam:PolicyARN",
            ]
            return service_mock
        else:
            raise ValueError(f"Service not found: {service}")

    fetcher.fetch_service_by_name = AsyncMock(side_effect=mock_fetch_service)

    return fetcher


@pytest.fixture
def default_config():
    """Default check configuration for tests."""
    return CheckConfig(
        check_id="test_check",
        enabled=True,
        config={},
    )


@pytest.fixture
def simple_policy_dict():
    """Simple valid policy as a dictionary.

    Returns:
        A basic S3 read policy suitable for testing validation.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::my-bucket/*"],
            }
        ],
    }


@pytest.fixture
def wildcard_policy_dict():
    """Policy with bare wildcard actions.

    Returns:
        A policy with Action: "*" that should be blocked by security enforcement.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["*"],
                "Resource": ["*"],
            }
        ],
    }


@pytest.fixture
def wildcard_resource_policy_dict():
    """Policy with wildcard resource and write actions.

    Returns:
        A policy with Resource: "*" and write actions (should be blocked).
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:DeleteObject"],
                "Resource": ["*"],
            }
        ],
    }


@pytest.fixture
def readonly_wildcard_policy_dict():
    """Policy with wildcard resource but only metadata-read actions.

    Returns:
        A policy with Resource: "*" but only metadata operations (should pass).
        Note: s3:GetObject is NOT included because it accesses data.
        Only metadata actions like s3:ListBucket, ec2:DescribeInstances are safe.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "ec2:DescribeInstances"],
                "Resource": ["*"],
            }
        ],
    }


@pytest.fixture
def passrole_policy_dict():
    """Policy with iam:PassRole action.

    Returns:
        A policy that requires iam:PassedToService condition.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": ["arn:aws:iam::123456789012:role/MyRole"],
            }
        ],
    }


@pytest.fixture
def s3_write_policy_dict():
    """Policy with S3 write actions.

    Returns:
        A policy that should have aws:SecureTransport condition auto-added.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject"],
                "Resource": ["arn:aws:s3:::my-bucket/*"],
            }
        ],
    }


@pytest.fixture
def policy_with_condition_dict():
    """Policy that already has a condition.

    Returns:
        A policy with existing conditions (should be preserved).
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["*"],
                "Condition": {
                    "StringEquals": {
                        "aws:SourceVpc": "vpc-12345",
                    }
                },
            }
        ],
    }


@pytest.fixture
def invalid_json_policy():
    """Invalid JSON string for testing error handling.

    Returns:
        A malformed JSON string.
    """
    return '{"Version": "2012-10-17", "Statement": [{'


@pytest.fixture
def simple_statement():
    """Simple Allow statement for testing.

    Returns:
        A basic S3 GetObject statement.
    """
    return Statement(
        effect="Allow",
        action=["s3:GetObject"],
        resource=["arn:aws:s3:::my-bucket/*"],
    )


@pytest.fixture
def wildcard_statement():
    """Statement with wildcard action.

    Returns:
        A statement with Action: "*".
    """
    return Statement(
        effect="Allow",
        action=["*"],
        resource=["*"],
    )


@pytest.fixture
def sensitive_action_statement():
    """Statement with sensitive action.

    Returns:
        A statement with iam:CreateAccessKey (credential exposure).
    """
    return Statement(
        effect="Allow",
        action=["iam:CreateAccessKey"],
        resource=["*"],
    )


@pytest.fixture
def simple_policy():
    """Simple IAMPolicy model for testing.

    Returns:
        A basic policy with one S3 read statement.
    """
    return IAMPolicy(
        version="2012-10-17",
        statement=[
            Statement(
                effect="Allow",
                action=["s3:GetObject"],
                resource=["arn:aws:s3:::my-bucket/*"],
            )
        ],
    )


@pytest.fixture
def validation_issue():
    """Sample validation issue for testing.

    Returns:
        A medium severity validation issue.
    """
    return ValidationIssue(
        severity="medium",
        statement_index=0,
        issue_type="overly_permissive",
        message="Action allows wildcard access",
        suggestion="Use specific actions instead",
        check_id="wildcard_action",
    )

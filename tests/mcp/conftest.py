"""Shared fixtures for MCP server tests.

This module provides common fixtures for testing the MCP server implementation,
including mock AWS service fetchers, sample policies, and test configurations.

Note: These tests require the optional 'mcp' extra (fastmcp package).
      Tests will be skipped if fastmcp is not installed.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import (
    ActionDetail,
    ConditionKey,
    IAMPolicy,
    ResourceType,
    ServiceDetail,
    Statement,
    ValidationIssue,
)


@contextmanager
def as_caller(*scopes: str, client_id: str = "test-caller") -> Iterator[None]:
    """Simulate an authenticated request carrying ``scopes``, for direct calls to
    ``list_tools()``/``get_tool()``/etc. that bypass FastMCP's real transport dispatch
    (which is the only place that would otherwise populate the access-token context).
    """
    from mcp.server.auth.middleware.auth_context import auth_context_var
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
    from mcp.server.auth.provider import AccessToken

    token = auth_context_var.set(
        AuthenticatedUser(AccessToken(token="test-token", client_id=client_id, scopes=list(scopes)))
    )
    try:
        yield
    finally:
        auth_context_var.reset(token)


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

    async def mock_validate_actions_batch(actions: list[str], allow_wildcards: bool = True):
        return {action: await mock_validate_action(action) for action in actions}

    fetcher.validate_actions_batch = AsyncMock(side_effect=mock_validate_actions_batch)

    # Mock expand_wildcard_action
    async def mock_expand_wildcard(pattern: str):
        if pattern == "s3:Get*":
            return ["s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectVersion"]
        elif pattern == "s3:*":
            return sorted(["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"])
        elif pattern == "iam:*User*":
            return ["iam:CreateUser", "iam:DeleteUser", "iam:GetUser", "iam:UpdateUser"]
        else:
            raise ValueError(f"Cannot expand wildcard: {pattern}")

    fetcher.expand_wildcard_action = AsyncMock(side_effect=mock_expand_wildcard)

    def _action(name: str, access_flag: str | None, resource_type: str | None = None) -> ActionDetail:
        """An ``ActionDetail`` carrying the ``Properties`` flag ``_get_access_level`` reads."""
        return ActionDetail(
            name=name,
            annotations={"Properties": {access_flag: True}} if access_flag else None,
            resources=[{"Name": resource_type}] if resource_type else [],
        )

    # Mock fetch_service_by_name -- returns real ServiceDetail/ActionDetail/ConditionKey
    # instances (not bare MagicMocks), so `.actions`/`.condition_keys` are the dicts
    # production code expects, not the list shape a hand-rolled mock could drift into.
    async def mock_fetch_service(service: str) -> ServiceDetail:
        if service == "s3":
            return ServiceDetail(
                name="Amazon S3",
                prefix="s3",
                actions_list=[
                    _action("GetObject", None, "object"),
                    _action("PutObject", "IsWrite", "object"),
                    _action("ListBucket", "IsList", "bucket"),
                ],
                resources_list=[
                    ResourceType(name="object", arn_formats=["arn:${Partition}:s3:::${BucketName}/${ObjectName}"]),
                    ResourceType(name="bucket", arn_formats=["arn:${Partition}:s3:::${BucketName}"]),
                ],
                condition_keys_list=[
                    ConditionKey(name="s3:prefix"),
                    ConditionKey(name="s3:x-amz-acl"),
                    ConditionKey(name="aws:SecureTransport"),
                ],
            )
        elif service == "iam":
            return ServiceDetail(
                name="AWS Identity and Access Management",
                prefix="iam",
                actions_list=[
                    _action("CreateUser", "IsWrite"),
                    _action("GetUser", None),
                    _action("PassRole", "IsWrite"),
                ],
                condition_keys_list=[
                    ConditionKey(name="iam:PassedToService"),
                    ConditionKey(name="iam:PolicyARN"),
                ],
            )
        else:
            raise ValueError(f"Service not found: {service}")

    fetcher.fetch_service_by_name = AsyncMock(side_effect=mock_fetch_service)

    return fetcher


@pytest.fixture(autouse=True)
def _no_real_aws_fetcher(monkeypatch: pytest.MonkeyPatch, mock_fetcher: MagicMock) -> None:
    """Redirect ``validate_policies``'s internal fetcher construction (which ignores ``ServerContext.fetcher``) to ``mock_fetcher``."""
    import iam_validator.core.policy_checks as policy_checks_module

    class _FakeFetcherContext:
        async def __aenter__(self) -> MagicMock:
            return mock_fetcher

        async def __aexit__(self, *exc: object) -> bool:
            return False

    monkeypatch.setattr(policy_checks_module, "AWSServiceFetcher", lambda *a, **k: _FakeFetcherContext())


@pytest.fixture(autouse=True)
def _no_real_aws_fetcher_in_context(monkeypatch: pytest.MonkeyPatch, mock_fetcher: MagicMock) -> None:
    """Redirect ``build_context()``'s fetcher construction, used by a real server lifespan's ``prewarm()``, to ``mock_fetcher``."""
    import iam_validator.mcp.context as context_module

    mock_fetcher.__aenter__ = AsyncMock(return_value=mock_fetcher)
    mock_fetcher.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(context_module, "AWSServiceFetcher", lambda *a, **k: mock_fetcher)


@pytest.fixture(autouse=True)
def _no_real_aws_cache_dir(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Structural backstop: any directly constructed AWSServiceFetcher (bypassing the two fixtures above) gets tmp_path as its cache dir, never ~/Library/Caches."""
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher

    original_init = AWSServiceFetcher.__init__

    def _init(self, *args, cache_dir=None, **kwargs):
        original_init(
            self, *args, cache_dir=tmp_path / "aws_services_cache" if cache_dir is None else cache_dir, **kwargs
        )

    monkeypatch.setattr(AWSServiceFetcher, "__init__", _init)


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

"""Shared fixtures for core module tests."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement


@pytest.fixture
def mock_fetcher():
    """Mock AWSServiceFetcher that doesn't hit the network."""
    fetcher = MagicMock()
    fetcher.validate_action = AsyncMock(return_value=(True, None, False))
    fetcher.expand_wildcard_action = AsyncMock(return_value=[])
    fetcher.fetch_service_by_name = AsyncMock(return_value=MagicMock())
    return fetcher


@pytest.fixture
def default_config():
    """Default check configuration."""
    return CheckConfig(check_id="test_check", enabled=True)


@pytest.fixture
def simple_policy():
    """Simple valid policy."""
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

"""Shared fixtures for check tests."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


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
def allow_all_statement():
    """Statement that allows everything."""
    return Statement(effect="Allow", action=["*"], resource=["*"])


@pytest.fixture
def readonly_statement():
    """Read-only S3 statement."""
    return Statement(
        effect="Allow",
        action=["s3:GetObject", "s3:ListBucket"],
        resource=["arn:aws:s3:::my-bucket/*"],
        sid="ReadOnlyAccess",
    )

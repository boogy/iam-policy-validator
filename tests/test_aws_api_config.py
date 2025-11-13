"""Tests for AWS API configuration."""

from iam_validator.core.config import AWS_SERVICE_REFERENCE_BASE_URL


def test_aws_fetcher_uses_centralized_config():
    """Test that AWSServiceFetcher uses the centralized BASE_URL config."""
    from iam_validator.core.aws_service import AWSServiceFetcher

    assert AWSServiceFetcher.BASE_URL == AWS_SERVICE_REFERENCE_BASE_URL

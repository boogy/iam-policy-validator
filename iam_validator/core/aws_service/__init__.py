"""AWS Service Fetcher - Public API.

This module provides functionality to fetch AWS service information from the AWS service
reference API with advanced caching and performance features.

Example usage:
    async with AWSServiceFetcher() as fetcher:
        services = await fetcher.fetch_services()
        service_detail = await fetcher.fetch_service_by_name("s3")
"""

# Re-export main classes for public API
from iam_validator.core.aws_service.fetcher import AWSServiceFetcher
from iam_validator.core.aws_service.patterns import CompiledPatterns
from iam_validator.core.aws_service.validators import ConditionKeyValidationResult

__all__ = [
    "AWSServiceFetcher",
    "ConditionKeyValidationResult",
    "CompiledPatterns",
]

"""
AWS API configuration constants.

This module centralizes AWS API endpoints and related configuration
used throughout the IAM Policy Validator.
"""

# AWS Service Reference API base URL
# This is the official AWS service reference that provides action, resource, and condition key metadata
AWS_SERVICE_REFERENCE_BASE_URL = "https://servicereference.us-east-1.amazonaws.com/"

# Alternative endpoints for different regions (currently not used, but available for future expansion)
AWS_SERVICE_REFERENCE_ENDPOINTS = {
    "us-east-1": "https://servicereference.us-east-1.amazonaws.com/",
    # Add other regional endpoints if they become available
}


def get_service_reference_url(region: str = "us-east-1") -> str:
    """
    Get the AWS Service Reference API URL for a specific region.

    Args:
        region: AWS region (default: us-east-1)

    Returns:
        The service reference base URL for the specified region

    Example:
        >>> get_service_reference_url()
        'https://servicereference.us-east-1.amazonaws.com/'
        >>> get_service_reference_url("us-east-1")
        'https://servicereference.us-east-1.amazonaws.com/'
    """
    return AWS_SERVICE_REFERENCE_ENDPOINTS.get(region, AWS_SERVICE_REFERENCE_BASE_URL)

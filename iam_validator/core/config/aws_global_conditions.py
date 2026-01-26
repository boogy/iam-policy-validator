"""
AWS Global Condition Keys Management.

Provides access to the list of valid AWS global condition keys
that can be used across all AWS services.

Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
Last updated: 2025-01-17
"""

import re
from typing import Any

from iam_validator.core.constants import AWS_TAG_KEY_ALLOWED_CHARS

# AWS Global Condition Keys with Type Information
# These condition keys are available for use in IAM policies across all AWS services
# Format: {key: type} where type is one of: String, ARN, Bool, Date, IPAddress, Numeric
AWS_GLOBAL_CONDITION_KEYS = {
    # Properties of the Principal
    "aws:PrincipalArn": "ARN",  # ARN of the principal making the request
    "aws:PrincipalAccount": "String",  # Account to which the requesting principal belongs
    "aws:PrincipalOrgPaths": "String",  # AWS Organizations path for the principal
    "aws:PrincipalOrgID": "String",  # Organization identifier of the principal
    "aws:PrincipalIsAWSService": "Bool",  # Checks if call is made directly by AWS service principal
    "aws:PrincipalServiceName": "String",  # Service principal name making the request
    "aws:PrincipalServiceNamesList": "String",  # List of all service principal names
    "aws:PrincipalType": "String",  # Type of principal making the request
    "aws:userid": "String",  # Principal identifier of the requester
    "aws:username": "String",  # User name of the requester
    # Properties of a Role Session
    "aws:AssumedRoot": "Bool",  # Checks if request used AssumeRoot for privileged access
    "aws:FederatedProvider": "String",  # Principal's issuing identity provider
    "aws:TokenIssueTime": "Date",  # When temporary security credentials were issued
    "aws:MultiFactorAuthAge": "Numeric",  # Seconds since MFA authorization
    "aws:MultiFactorAuthPresent": "Bool",  # Whether MFA was used for temporary credentials
    "aws:ChatbotSourceArn": "ARN",  # Source chat configuration ARN
    "aws:Ec2InstanceSourceVpc": "String",  # VPC where EC2 IAM role credentials were delivered
    "aws:Ec2InstanceSourcePrivateIPv4": "IPAddress",  # Private IPv4 of EC2 instance
    "aws:SourceIdentity": "String",  # Source identity set when assuming a role
    "ec2:RoleDelivery": "Numeric",  # Instance metadata service version
    # Network Properties
    "aws:SourceIp": "IPAddress",  # Requester's IP address (IPv4/IPv6)
    "aws:SourceVpc": "String",  # VPC through which request travels
    "aws:SourceVpce": "String",  # VPC endpoint identifier
    "aws:VpceAccount": "String",  # AWS account owning the VPC endpoint
    "aws:VpceOrgID": "String",  # Organization ID of VPC endpoint owner
    "aws:VpceOrgPaths": "String",  # AWS Organizations path of VPC endpoint
    "aws:VpcSourceIp": "IPAddress",  # IP address from VPC endpoint request
    # Resource Properties
    "aws:ResourceAccount": "String",  # Resource owner's AWS account ID
    "aws:ResourceOrgID": "String",  # Organization ID of resource owner
    "aws:ResourceOrgPaths": "String",  # AWS Organizations path of resource
    # Request Properties
    "aws:CurrentTime": "Date",  # Current date and time
    "aws:EpochTime": "Date",  # Request timestamp in epoch format (also accepts Numeric)
    "aws:referer": "String",  # HTTP referer header value (note: lowercase 'r')
    "aws:Referer": "String",  # HTTP referer header value (alternate capitalization)
    "aws:RequestedRegion": "String",  # AWS Region for the request
    "aws:TagKeys": "String",  # Tag keys present in request
    "aws:SecureTransport": "Bool",  # Whether HTTPS was used
    "aws:SourceAccount": "String",  # Account making the request
    "aws:SourceArn": "ARN",  # ARN of request source
    "aws:SourceOrgID": "String",  # Organization ID of request source
    "aws:SourceOrgPaths": "String",  # Organization paths of request source
    "aws:UserAgent": "String",  # HTTP user agent string
    # Cross-Service Keys
    "aws:CalledVia": "String",  # Services called in request chain
    "aws:CalledViaFirst": "String",  # First service in call chain
    "aws:CalledViaLast": "String",  # Last service in call chain
    "aws:ViaAWSService": "Bool",  # Whether AWS service made the request
}

# Global condition keys that restrict resource scope.
# These conditions are always valid for all services and directly constrain
# which resources can be accessed, making them suitable for lowering severity
# when used with wildcard resources.
# Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-resourceaccount
GLOBAL_RESOURCE_SCOPING_CONDITION_KEYS = frozenset(
    {
        "aws:ResourceAccount",  # Limits to specific AWS account(s)
        "aws:ResourceOrgID",  # Limits to specific AWS Organization
        "aws:ResourceOrgPaths",  # Limits to specific OU paths
    }
)

# Patterns that should be recognized (wildcards and tag-based keys)
# IMPORTANT: aws:RequestTag and aws:ResourceTag are NOT global condition keys!
# They are action-specific or resource-specific and must be explicitly listed in
# the action's ActionConditionKeys or the resource's ConditionKeys.
# Only aws:PrincipalTag is a true global condition key.
#
# Uses centralized tag key character class from constants
AWS_CONDITION_KEY_PATTERNS = [
    {
        "pattern": rf"^aws:PrincipalTag/[{AWS_TAG_KEY_ALLOWED_CHARS}]+$",
        "description": "Tags attached to the principal making the request",
    },
]


class AWSGlobalConditions:
    """Manages AWS global condition keys."""

    def __init__(self):
        """Initialize with global condition keys."""
        self._global_keys: dict[str, str] = AWS_GLOBAL_CONDITION_KEYS.copy()
        self._patterns: list[dict[str, Any]] = AWS_CONDITION_KEY_PATTERNS.copy()

    def is_valid_global_key(self, condition_key: str) -> bool:
        """
        Check if a condition key is a valid AWS global condition key.

        Args:
            condition_key: The condition key to validate (e.g., "aws:SourceIp")

        Returns:
            True if valid global condition key, False otherwise
        """
        # Check exact matches first
        if condition_key in self._global_keys:
            return True

        # Check patterns (for tags and wildcards)
        for pattern_config in self._patterns:
            pattern = pattern_config["pattern"]
            if re.match(pattern, condition_key):
                return True

        return False

    def get_key_type(self, condition_key: str) -> str | None:
        """
        Get the expected type for a global condition key.

        Args:
            condition_key: The condition key (e.g., "aws:SourceIp")

        Returns:
            Type string (String, ARN, Bool, Date, IPAddress, Numeric) or None if not found
        """
        # Check exact matches
        if condition_key in self._global_keys:
            return self._global_keys[condition_key]

        # Check patterns - all tag-based keys are String type
        for pattern_config in self._patterns:
            pattern = pattern_config["pattern"]
            if re.match(pattern, condition_key):
                return "String"

        return None

    def get_all_keys(self) -> dict[str, str]:
        """Get all explicit global condition keys with their types."""
        return self._global_keys.copy()

    def get_patterns(self) -> list[dict[str, Any]]:
        """Get all condition key patterns."""
        return self._patterns.copy()


# Singleton instance
_global_conditions_instance = None


def get_global_conditions() -> AWSGlobalConditions:
    """Get singleton instance of AWSGlobalConditions."""
    global _global_conditions_instance  # pylint: disable=global-statement

    if _global_conditions_instance is None:
        _global_conditions_instance = AWSGlobalConditions()
    return _global_conditions_instance

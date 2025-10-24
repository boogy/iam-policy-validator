"""
AWS Global Condition Keys Management.

Provides access to the list of valid AWS global condition keys
that can be used across all AWS services.

Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
Last updated: 2025-01-17
"""

import re
from typing import Any

# AWS Global Condition Keys
# These condition keys are available for use in IAM policies across all AWS services
AWS_GLOBAL_CONDITION_KEYS = {
    # Properties of the Principal
    "aws:PrincipalArn",  # ARN of the principal making the request
    "aws:PrincipalAccount",  # Account to which the requesting principal belongs
    "aws:PrincipalOrgPaths",  # AWS Organizations path for the principal
    "aws:PrincipalOrgID",  # Organization identifier of the principal
    "aws:PrincipalIsAWSService",  # Checks if call is made directly by AWS service principal
    "aws:PrincipalServiceName",  # Service principal name making the request
    "aws:PrincipalServiceNamesList",  # List of all service principal names
    "aws:PrincipalType",  # Type of principal making the request
    "aws:userid",  # Principal identifier of the requester
    "aws:username",  # User name of the requester
    # Properties of a Role Session
    "aws:AssumedRoot",  # Checks if request used AssumeRoot for privileged access
    "aws:FederatedProvider",  # Principal's issuing identity provider
    "aws:TokenIssueTime",  # When temporary security credentials were issued
    "aws:MultiFactorAuthAge",  # Seconds since MFA authorization
    "aws:MultiFactorAuthPresent",  # Whether MFA was used for temporary credentials
    "aws:ChatbotSourceArn",  # Source chat configuration ARN
    "aws:Ec2InstanceSourceVpc",  # VPC where EC2 IAM role credentials were delivered
    "aws:Ec2InstanceSourcePrivateIPv4",  # Private IPv4 of EC2 instance
    "aws:SourceIdentity",  # Source identity set when assuming a role
    "ec2:RoleDelivery",  # Instance metadata service version
    # Network Properties
    "aws:SourceIp",  # Requester's IP address (IPv4/IPv6)
    "aws:SourceVpc",  # VPC through which request travels
    "aws:SourceVpce",  # VPC endpoint identifier
    "aws:VpceAccount",  # AWS account owning the VPC endpoint
    "aws:VpceOrgID",  # Organization ID of VPC endpoint owner
    "aws:VpceOrgPaths",  # AWS Organizations path of VPC endpoint
    "aws:VpcSourceIp",  # IP address from VPC endpoint request
    # Resource Properties
    "aws:ResourceAccount",  # Resource owner's AWS account ID
    "aws:ResourceOrgID",  # Organization ID of resource owner
    "aws:ResourceOrgPaths",  # AWS Organizations path of resource
    # Request Properties
    "aws:CurrentTime",  # Current date and time
    "aws:EpochTime",  # Request timestamp in epoch format
    "aws:referer",  # HTTP referer header value (note: lowercase 'r')
    "aws:Referer",  # HTTP referer header value (alternate capitalization)
    "aws:RequestedRegion",  # AWS Region for the request
    "aws:TagKeys",  # Tag keys present in request
    "aws:SecureTransport",  # Whether HTTPS was used
    "aws:SourceAccount",  # Account making the request
    "aws:SourceArn",  # ARN of request source
    "aws:SourceOrgID",  # Organization ID of request source
    "aws:SourceOrgPaths",  # Organization paths of request source
    "aws:UserAgent",  # HTTP user agent string
    # Cross-Service Keys
    "aws:CalledVia",  # Services called in request chain
    "aws:CalledViaFirst",  # First service in call chain
    "aws:CalledViaLast",  # Last service in call chain
    "aws:ViaAWSService",  # Whether AWS service made the request
}

# Patterns that should be recognized (wildcards and tag-based keys)
# These allow things like aws:RequestTag/Department or aws:PrincipalTag/Environment
AWS_CONDITION_KEY_PATTERNS = [
    {
        "pattern": r"^aws:RequestTag/[a-zA-Z0-9+\-=._:/@]+$",
        "description": "Tag keys in the request (for tag-based access control)",
    },
    {
        "pattern": r"^aws:ResourceTag/[a-zA-Z0-9+\-=._:/@]+$",
        "description": "Tags on the resource being accessed",
    },
    {
        "pattern": r"^aws:PrincipalTag/[a-zA-Z0-9+\-=._:/@]+$",
        "description": "Tags attached to the principal making the request",
    },
]


class AWSGlobalConditions:
    """Manages AWS global condition keys."""

    def __init__(self):
        """Initialize with global condition keys."""
        self._global_keys: set[str] = AWS_GLOBAL_CONDITION_KEYS.copy()
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

    def get_all_keys(self) -> set[str]:
        """Get all explicit global condition keys."""
        return self._global_keys.copy()

    def get_patterns(self) -> list[dict[str, Any]]:
        """Get all condition key patterns."""
        return self._patterns.copy()


# Singleton instance
_global_conditions_instance = None


def get_global_conditions() -> AWSGlobalConditions:
    """Get singleton instance of AWSGlobalConditions."""
    global _global_conditions_instance
    if _global_conditions_instance is None:
        _global_conditions_instance = AWSGlobalConditions()
    return _global_conditions_instance

"""
AWS Global Condition Keys Management.

Provides access to the list of valid AWS global condition keys
that can be used across all AWS services. The live list comes from the AWS Service
Reference (`v1/global-condition-keys.json`, loaded by `AWSServiceFetcher`); the bundled
list below is the offline fallback.

Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
Last updated: 2026-10-29
"""

import logging
import re
import threading
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from iam_validator.core.constants import AWS_TAG_KEY_ALLOWED_CHARS

logger = logging.getLogger(__name__)

AWS_DOCS_BASE_URL = "https://docs.aws.amazon.com"

# Bundled AWS Global Condition Keys with Type Information (offline fallback)
# These condition keys are available for use in IAM policies across all AWS services
# Format: {key: type} where type is one of: String, ArrayOfString, ARN, Bool, Date,
# IPAddress, Numeric. The seven keys AWS documents as "Value type - Multivalued" carry
# ArrayOfString; is_multivalued_context_key() is the authority for set-operator checks.
AWS_GLOBAL_CONDITION_KEYS = {
    # Properties of the Principal
    "aws:PrincipalArn": "ARN",  # ARN of the principal making the request
    "aws:PrincipalAccount": "String",  # Account to which the requesting principal belongs
    "aws:PrincipalOrgPaths": "ArrayOfString",  # AWS Organizations paths for the principal (multivalued)
    "aws:PrincipalOrgID": "String",  # Organization identifier of the principal
    "aws:PrincipalIsAWSService": "Bool",  # Checks if call is made directly by AWS service principal
    "aws:PrincipalServiceName": "String",  # Service principal name making the request
    "aws:PrincipalServiceNamesList": "ArrayOfString",  # Service principal names of the calling service (multivalued)
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
    "aws:SignInSessionArn": "ARN",  # AWS Sign-In OAuth session ARN
    "aws:ViaCustomerDomain": "String",  # Account that issued Temporary Access Delegation credentials
    "ec2:RoleDelivery": "Numeric",  # Instance metadata service version
    # Network Properties
    "aws:SourceIp": "IPAddress",  # Requester's IP address (IPv4/IPv6)
    "aws:SourceVpc": "String",  # VPC through which request travels
    "aws:SourceVpcArn": "ARN",  # ARN of the VPC the request passed through
    "aws:SourceVpce": "String",  # VPC endpoint identifier
    "aws:VpceAccount": "String",  # AWS account owning the VPC endpoint
    "aws:VpceOrgID": "String",  # Organization ID of VPC endpoint owner
    "aws:VpceOrgPaths": "ArrayOfString",  # AWS Organizations paths of VPC endpoint owner (multivalued)
    "aws:VpcSourceIp": "IPAddress",  # IP address from VPC endpoint request
    # Resource Properties
    "aws:ResourceAccount": "String",  # Resource owner's AWS account ID
    "aws:ResourceOrgID": "String",  # Organization ID of resource owner
    "aws:ResourceOrgPaths": "ArrayOfString",  # AWS Organizations paths of resource (multivalued)
    # Request Properties
    "aws:CurrentTime": "Date",  # Current date and time
    "aws:EpochTime": "Date",  # Request timestamp in epoch format (also accepts Numeric)
    "aws:Referer": "String",  # HTTP referer header value
    "aws:RequestedRegion": "String",  # AWS Region for the request
    "aws:TagKeys": "ArrayOfString",  # Tag keys present in request (multivalued)
    "aws:SecureTransport": "Bool",  # Whether HTTPS was used
    "aws:SourceAccount": "String",  # Account making the request
    "aws:SourceArn": "ARN",  # ARN of request source
    "aws:SourceOrgID": "String",  # Organization ID of request source
    "aws:SourceOrgPaths": "ArrayOfString",  # Organization paths of request source (multivalued)
    "aws:UserAgent": "String",  # HTTP user agent string
    # Cross-Service Keys
    "aws:CalledVia": "ArrayOfString",  # Ordered list of services in the FAS call chain (multivalued)
    "aws:CalledViaFirst": "String",  # First service in call chain
    "aws:CalledViaLast": "String",  # Last service in call chain
    "aws:ViaAWSService": "Bool",  # Whether AWS service made the request
    "aws:CalledViaAWSMCP": "String",  # MCP service principal that called on the principal's behalf
    "aws:ViaAWSMCPService": "Bool",  # Whether an AWS MCP service forwarded the request
    "aws:IsMcpServiceAction": "Bool",  # Whether the authorized action is an MCP service action
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

# Keys accepted globally that the AWS global-condition-keys file does not list; merged
# into the API-sourced set too.
SUPPLEMENTAL_GLOBAL_CONDITION_KEYS = frozenset({"aws:ViaCustomerDomain", "ec2:RoleDelivery"})

# Tag-based global keys (AWS lists them as `aws:<Kind>Tag/${TagKey}`)
AWS_CONDITION_KEY_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": rf"^aws:PrincipalTag/[{AWS_TAG_KEY_ALLOWED_CHARS}]+$",
        "description": "Tags attached to the principal making the request",
        "types": ("String",),
    },
    {
        "pattern": rf"^aws:RequestTag/[{AWS_TAG_KEY_ALLOWED_CHARS}]+$",
        "description": "Tag key-value pairs passed in the request",
        "types": ("String", "Numeric"),
    },
    {
        "pattern": rf"^aws:ResourceTag/[{AWS_TAG_KEY_ALLOWED_CHARS}]+$",
        "description": "Tags attached to the resource being acted upon",
        "types": ("String",),
    },
]

_TEMPLATED_NAME_RE = re.compile(r"^(?P<prefix>[A-Za-z0-9-]+:[A-Za-z0-9]+)/\$\{[A-Za-z0-9]+\}$")


@dataclass(frozen=True)
class GlobalConditionKeyInfo:
    """A global condition key: its name (templated for tag keys), types and docs."""

    name: str
    types: tuple[str, ...]
    description: str | None = None
    doc_url: str | None = None


class _GlobalConditionKeyEntry(BaseModel):
    """One entry of the AWS `global-condition-keys.json` file."""

    model_config = ConfigDict(extra="ignore")

    name: str = Field(alias="Name", min_length=1)
    types: list[str] = Field(default_factory=list, alias="Types")
    description: str | None = Field(default=None, alias="Description")
    doc_page: str | None = Field(default=None, alias="DocPage")


def _tag_pattern(prefix: str) -> str:
    return rf"^{re.escape(prefix)}/[{AWS_TAG_KEY_ALLOWED_CHARS}]+$"


class AWSGlobalConditions:
    """Manages AWS global condition keys."""

    def __init__(
        self,
        keys: list[GlobalConditionKeyInfo] | None = None,
        source: str = "bundled",
    ) -> None:
        """Initialize with explicit keys (templated names become patterns), or the bundled list.

        Args:
            keys: Key definitions; None uses the bundled list
            source: Where the keys came from (`bundled` or `aws-api`)
        """
        if keys is None:
            keys = [GlobalConditionKeyInfo(name, (key_type,)) for name, key_type in AWS_GLOBAL_CONDITION_KEYS.items()]
            keys += [
                GlobalConditionKeyInfo(
                    name=pattern_config["pattern"][1:].split("/", 1)[0] + "/${TagKey}",
                    types=pattern_config["types"],
                    description=pattern_config["description"],
                )
                for pattern_config in AWS_CONDITION_KEY_PATTERNS
            ]

        self.source = source
        self._keys: dict[str, GlobalConditionKeyInfo] = {}
        self._patterns: list[tuple[re.Pattern[str], GlobalConditionKeyInfo]] = []
        for info in keys:
            match = _TEMPLATED_NAME_RE.match(info.name)
            if match:
                self._patterns.append((re.compile(_tag_pattern(match["prefix"]), re.IGNORECASE), info))
            else:
                self._keys[info.name] = info
        self._keys_lower: dict[str, str] = {k.lower(): k for k in self._keys}

    @classmethod
    def from_api(cls, data: Any) -> "AWSGlobalConditions | None":
        """Build from the AWS `global-condition-keys.json` payload.

        Malformed entries are skipped; returns None when nothing valid remains.
        Supplemental keys missing from the payload are added from the bundled list.
        """
        if not isinstance(data, list):
            return None

        keys: list[GlobalConditionKeyInfo] = []
        for item in data:
            try:
                entry = _GlobalConditionKeyEntry.model_validate(item)
            except ValidationError:
                logger.debug(f"Skipping malformed global condition key entry: {item!r}")
                continue
            doc_url = entry.doc_page
            if doc_url and doc_url.startswith("/"):
                doc_url = AWS_DOCS_BASE_URL + doc_url
            keys.append(
                GlobalConditionKeyInfo(
                    name=entry.name,
                    types=tuple(entry.types) or ("String",),
                    description=entry.description,
                    doc_url=doc_url,
                )
            )
        if not keys:
            return None

        names_lower = {info.name.lower() for info in keys}
        keys += [
            GlobalConditionKeyInfo(name, (AWS_GLOBAL_CONDITION_KEYS[name],))
            for name in sorted(SUPPLEMENTAL_GLOBAL_CONDITION_KEYS)
            if name.lower() not in names_lower
        ]
        return cls(keys, source="aws-api")

    def get_key_info(self, condition_key: str) -> GlobalConditionKeyInfo | None:
        """Get the definition matching a condition key (explicit name or tag pattern)."""
        resolved = self._resolve_key(condition_key)
        if resolved is not None:
            return self._keys[resolved]
        for pattern, info in self._patterns:
            if pattern.match(condition_key):
                return info
        return None

    def is_valid_global_key(self, condition_key: str) -> bool:
        """
        Check if a condition key is a valid AWS global condition key.

        Condition key names are not case-sensitive in AWS, so lookups are too.

        Args:
            condition_key: The condition key to validate (e.g., "aws:SourceIp")

        Returns:
            True if valid global condition key, False otherwise
        """
        return self.get_key_info(condition_key) is not None

    def _resolve_key(self, condition_key: str) -> str | None:
        """Resolve a condition key to its canonically cased name, or None."""
        if condition_key in self._keys:
            return condition_key
        return self._keys_lower.get(condition_key.lower())

    def get_key_types(self, condition_key: str) -> list[str]:
        """Get every type AWS lists for a global condition key; empty when unknown."""
        info = self.get_key_info(condition_key)
        return list(info.types) if info else []

    def get_key_type(self, condition_key: str) -> str | None:
        """
        Get the primary (first listed) type for a global condition key.

        Args:
            condition_key: The condition key (e.g., "aws:SourceIp")

        Returns:
            Type string (String, ArrayOfString, ARN, Bool, Date, IPAddress, Numeric)
            or None if not found
        """
        types = self.get_key_types(condition_key)
        return types[0] if types else None

    def list_keys(self) -> list[GlobalConditionKeyInfo]:
        """All key definitions, tag patterns included under their templated names."""
        return sorted([*self._keys.values(), *(info for _, info in self._patterns)], key=lambda i: i.name.lower())

    def get_all_keys(self) -> dict[str, str]:
        """Get all explicit global condition keys with their primary types."""
        return {name: info.types[0] for name, info in self._keys.items()}

    def get_patterns(self) -> list[dict[str, Any]]:
        """Get all condition key patterns."""
        return [{"pattern": pattern.pattern, "description": info.description} for pattern, info in self._patterns]


# Singleton instance
_global_conditions_instance = None
_global_conditions_lock = threading.Lock()


def get_global_conditions() -> AWSGlobalConditions:
    """Get the singleton built from the bundled list (use `AWSServiceFetcher.get_global_conditions()` for live data)."""
    global _global_conditions_instance  # pylint: disable=global-statement

    if _global_conditions_instance is None:
        with _global_conditions_lock:
            if _global_conditions_instance is None:
                _global_conditions_instance = AWSGlobalConditions()
    return _global_conditions_instance

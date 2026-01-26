"""
Condition Key and Value Validators.

This module provides validators for IAM policy condition operators, keys, and values.
Based on AWS IAM Policy Elements Reference:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html

Supports:
- All standard IAM condition operators (String, Numeric, Date, Bool, Binary, IP, ARN)
- IfExists variants for all operators (e.g., StringEqualsIfExists)
- Set operators (ForAllValues, ForAnyValue) for multivalued keys
- Null operator for key existence checking
"""

import ipaddress
import re
from datetime import datetime
from typing import Any

# Pre-compiled regex patterns for performance (compiled once at module load)
# Timezone offset pattern for ISO 8601 dates (e.g., 2025-01-01T12:00:00+00:00)
_TZ_OFFSET_PATTERN = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,6}))?"  # Optional milliseconds/microseconds
    r"([+-])(\d{2}):(\d{2})$"  # Timezone offset
)

# IAM Condition Operators mapped to their expected value types
# Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
CONDITION_OPERATORS = {
    # String operators - Case-sensitive and case-insensitive matching with wildcard support
    "StringEquals": "String",
    "StringNotEquals": "String",
    "StringEqualsIgnoreCase": "String",
    "StringNotEqualsIgnoreCase": "String",
    "StringLike": "String",  # Supports * and ? wildcards
    "StringNotLike": "String",  # Supports * and ? wildcards
    # Numeric operators - Integer and decimal comparisons
    "NumericEquals": "Numeric",
    "NumericNotEquals": "Numeric",
    "NumericLessThan": "Numeric",
    "NumericLessThanEquals": "Numeric",
    "NumericGreaterThan": "Numeric",
    "NumericGreaterThanEquals": "Numeric",
    # Date operators - W3C ISO 8601 and UNIX epoch time formats
    "DateEquals": "Date",
    "DateNotEquals": "Date",
    "DateLessThan": "Date",
    "DateLessThanEquals": "Date",
    "DateGreaterThan": "Date",
    "DateGreaterThanEquals": "Date",
    # Boolean operators
    "Bool": "Bool",
    # Binary operators - Base-64 encoded byte-for-byte comparison
    "BinaryEquals": "Binary",
    # IP address operators - IPv4 and IPv6 CIDR notation
    "IpAddress": "IPAddress",
    "NotIpAddress": "IPAddress",
    # ARN operators - Amazon Resource Name matching with wildcard support
    "ArnEquals": "ARN",
    "ArnLike": "ARN",
    "ArnNotEquals": "ARN",
    "ArnNotLike": "ARN",
    # Null check operator - Key existence validation
    "Null": "Bool",
}

# Set operator prefixes for multivalued condition keys
# Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_multi-value-conditions.html
SET_OPERATOR_PREFIXES = ["ForAllValues", "ForAnyValue"]


def normalize_operator(operator: str) -> tuple[str, str | None, str | None]:
    """
    Normalize condition operator, handling IfExists and ForAllValues/ForAnyValue prefixes.

    AWS IAM supports several operator modifiers:
    - IfExists suffix: Allows condition to pass if key is missing
    - ForAllValues/ForAnyValue prefixes: Set operators for multivalued keys

    Args:
        operator: Raw operator from policy (e.g., "StringEqualsIfExists", "ForAllValues:StringLike")

    Returns:
        Tuple of (base_operator, expected_type, set_prefix) where:
        - base_operator: Normalized operator name (e.g., "StringEquals")
        - expected_type: Expected value type (e.g., "String") or None if unknown
        - set_prefix: Set operator prefix ("ForAllValues"/"ForAnyValue") or None

    Examples:
        >>> normalize_operator("StringEquals")
        ("StringEquals", "String", None)
        >>> normalize_operator("StringEqualsIfExists")
        ("StringEquals", "String", None)
        >>> normalize_operator("ForAllValues:StringLike")
        ("StringLike", "String", "ForAllValues")
        >>> normalize_operator("ForAnyValue:NumericLessThanIfExists")
        ("NumericLessThan", "Numeric", "ForAnyValue")

    Reference:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
    """
    set_prefix = None
    cleaned = operator

    # Remove ForAllValues/ForAnyValue prefix
    if ":" in operator:
        parts = operator.split(":", 1)
        if parts[0] in SET_OPERATOR_PREFIXES:
            set_prefix = parts[0]
            cleaned = parts[1]

    # Remove IfExists suffix
    if cleaned.endswith("IfExists"):
        cleaned = cleaned[:-8]  # Remove "IfExists"

    # Look up the base operator (case-insensitive)
    for base_op, op_type in CONDITION_OPERATORS.items():
        if cleaned.lower() == base_op.lower():
            return base_op, op_type, set_prefix

    return operator, None, set_prefix


def translate_type(doc_type: str) -> str:
    """
    Translate documentation type names to normalized types.

    AWS documentation uses various type names across different services.
    This function normalizes them to standard IAM condition types.

    Args:
        doc_type: Type from AWS docs (e.g., "Long", "ARN", "Boolean", "ArrayOfString")

    Returns:
        Normalized type string (String, Numeric, Bool, Date, ARN, IPAddress, Binary)

    Examples:
        >>> translate_type("Long")
        "Numeric"
        >>> translate_type("Boolean")
        "Bool"
        >>> translate_type("ArrayOfString")
        "String"
        >>> translate_type("Arn")
        "ARN"

    Reference:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
    """
    type_map = {
        # ARN types
        "ARN": "ARN",
        "Arn": "ARN",
        # Boolean types
        "Bool": "Bool",
        "Boolean": "Bool",
        # Date types
        "Date": "Date",
        # Numeric types
        "Long": "Numeric",
        "Numeric": "Numeric",
        "Number": "Numeric",
        # String types
        "String": "String",
        "string": "String",
        "ArrayOfString": "String",
        # IP Address types
        "IPAddress": "IPAddress",
        "Ip": "IPAddress",
        # Binary types
        "Binary": "Binary",
    }

    return type_map.get(doc_type, doc_type)


def validate_value_for_type(value_type: str, values: list[Any]) -> tuple[bool, str | None]:
    """
    Validate that condition values match the expected type.

    Supports all AWS IAM condition value types with comprehensive validation:
    - String: Any text value
    - Numeric: Integers and decimals
    - Date: W3C ISO 8601 format or UNIX epoch timestamps
    - Bool: true/false (case-insensitive)
    - Binary: Base-64 encoded strings
    - IPAddress: IPv4/IPv6 with optional CIDR notation
    - ARN: Amazon Resource Names

    Args:
        value_type: Expected type (String, ARN, Bool, Date, IPAddress, Numeric, Binary)
        values: List of values from the condition

    Returns:
        Tuple of (is_valid, error_message)

    Examples:
        >>> validate_value_for_type("Date", ["2019-07-16T12:00:00Z"])
        (True, None)
        >>> validate_value_for_type("Date", ["1563278400"])  # UNIX epoch
        (True, None)
        >>> validate_value_for_type("Numeric", ["123.45"])
        (True, None)
        >>> validate_value_for_type("IPAddress", ["2001:DB8::/32"])
        (True, None)
        >>> validate_value_for_type("Bool", ["invalid"])
        (False, "Expected Bool value (true/false) but got: invalid")

    Reference:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
    """
    # Normalize the type
    value_type = translate_type(value_type)

    if value_type not in ["ARN", "Binary", "Bool", "Date", "IPAddress", "Numeric", "String"]:
        return False, f"Unknown type: {value_type}"

    for value in values:
        # Convert booleans to lowercase strings
        if isinstance(value, bool):
            value = str(value).lower()

        # Convert to string
        value_str = str(value)

        # Type-specific validation
        is_valid, error = _validate_single_value(value_type, value_str)
        if not is_valid:
            return False, error

    return True, None


def _validate_date_value(value_str: str) -> tuple[bool, str | None]:
    """
    Validate a date value for IAM condition operators.

    AWS IAM accepts the following date formats:
    1. ISO 8601 with UTC (Z suffix): 2019-07-16T12:00:00Z
    2. ISO 8601 with timezone offset: 2019-07-16T12:00:00+00:00
    3. ISO 8601 with milliseconds: 2019-07-16T12:00:00.000Z
    4. UNIX epoch timestamp: 1563278400 (seconds since 1970-01-01)

    This function validates both syntactic correctness AND semantic validity
    (e.g., month must be 1-12, day must be valid for the month).

    Args:
        value_str: The date string to validate

    Returns:
        Tuple of (is_valid, error_message)

    Reference:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_Date
    """
    # Fast path: Check for UNIX epoch timestamp (digits only)
    # Using str.isdigit() is ~3x faster than re.match(r"^\d+$", ...)
    if value_str.isdigit():
        # Validate epoch timestamp is reasonable (not before 1970, not too far in future)
        try:
            epoch = int(value_str)
            # Allow dates from 1970 to year 3000 (covers all reasonable use cases)
            if epoch > 32503680000:  # Year 3000 in seconds
                return (
                    False,
                    f"UNIX epoch timestamp appears unreasonably large: {value_str}. "
                    "Expected seconds since 1970-01-01.",
                )
            return True, None
        except (ValueError, OverflowError):
            return (
                False,
                f"Invalid UNIX epoch timestamp: {value_str}. Must be a valid integer.",
            )

    # Try parsing ISO 8601 formats (ordered by most common first for performance)
    # Using datetime.strptime with try/except is the most efficient approach
    # as it validates both format AND semantic validity (e.g., month 13 is rejected)
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",  # Basic UTC format (most common)
        "%Y-%m-%dT%H:%M:%S.%fZ",  # With milliseconds
        "%Y-%m-%d",  # Date only
    ):
        try:
            datetime.strptime(value_str, fmt)
            return True, None
        except ValueError:
            continue

    # Fall back to timezone offset parsing (e.g., +00:00, -05:00)
    # Uses pre-compiled regex pattern for performance
    match = _TZ_OFFSET_PATTERN.match(value_str)
    if match:
        year, month, day, hour, minute, second = (
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            int(match.group(4)),
            int(match.group(5)),
            int(match.group(6)),
        )
        tz_hour, tz_minute = int(match.group(9)), int(match.group(10))

        # Validate ranges
        validation_error = _validate_datetime_components(
            year, month, day, hour, minute, second, tz_hour, tz_minute
        )
        if validation_error:
            return False, validation_error

        return True, None

    # If nothing matched, provide a helpful error
    return (
        False,
        f"Invalid Date value: `{value_str}`. Expected ISO 8601 format "
        "(e.g., `2019-07-16T12:00:00Z`, `2019-07-16T12:00:00+00:00`) "
        "or UNIX epoch timestamp (e.g., `1563278400`).",
    )


def _validate_datetime_components(
    year: int,
    month: int,
    day: int,
    hour: int,
    minute: int,
    second: int,
    tz_hour: int = 0,
    tz_minute: int = 0,
) -> str | None:
    """
    Validate individual datetime components for semantic correctness.

    Args:
        year: Year (1-9999)
        month: Month (1-12)
        day: Day (1-31, depends on month)
        hour: Hour (0-23)
        minute: Minute (0-59)
        second: Second (0-59)
        tz_hour: Timezone hour offset (0-14)
        tz_minute: Timezone minute offset (0-59)

    Returns:
        Error message string if invalid, None if valid
    """
    # Validate month
    if not 1 <= month <= 12:
        return f"Invalid month: {month}. Must be between 1 and 12."

    # Validate day based on month
    days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

    # Handle leap year for February
    is_leap_year = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
    if is_leap_year and month == 2:
        max_day = 29
    else:
        max_day = days_in_month[month]

    if not 1 <= day <= max_day:
        return f"Invalid day: {day}. For month {month}, day must be between 1 and {max_day}."

    # Validate hour
    if not 0 <= hour <= 23:
        return f"Invalid hour: {hour}. Must be between 0 and 23."

    # Validate minute
    if not 0 <= minute <= 59:
        return f"Invalid minute: {minute}. Must be between 0 and 59."

    # Validate second (allow 59 for leap seconds)
    if not 0 <= second <= 59:
        return f"Invalid second: {second}. Must be between 0 and 59."

    # Validate timezone offset (max +/- 14:00 per ISO 8601)
    if not 0 <= tz_hour <= 14:
        return f"Invalid timezone hour offset: {tz_hour}. Must be between 0 and 14."

    if not 0 <= tz_minute <= 59:
        return f"Invalid timezone minute offset: {tz_minute}. Must be between 0 and 59."

    # Validate that tz offset doesn't exceed 14:00
    if tz_hour == 14 and tz_minute > 0:
        return "Invalid timezone offset. Maximum is +/-14:00."

    return None


def _validate_single_value(value_type: str, value_str: str) -> tuple[bool, str | None]:
    """
    Validate a single value against its expected type.

    Args:
        value_type: Expected type (normalized)
        value_str: String representation of value

    Returns:
        Tuple of (is_valid, error_message)
    """
    if value_type == "ARN":
        # ARN format: arn:partition:service:region:account-id:resource
        # Wildcards are allowed in ARN values
        arn_pattern = r"^arn:[^:]*:[^:]*:[^:]*:[^:]*:.+$"
        if not re.match(arn_pattern, value_str):
            return (
                False,
                f"Expected ARN value (arn:aws:service:region:account:resource) but got: {value_str}",
            )

    elif value_type == "Binary":
        # Base-64 encoded string validation
        binary_pattern = r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
        if not re.match(binary_pattern, value_str):
            return False, f"Expected Binary value (base64-encoded string) but got: {value_str}"

    elif value_type == "Bool":
        # Boolean: true or false (case-insensitive)
        if value_str.lower() not in ["true", "false"]:
            return False, f"Expected Bool value (true/false) but got: {value_str}"

    elif value_type == "Date":
        # Date: W3C ISO 8601 format or UNIX epoch timestamp
        # AWS accepts multiple ISO 8601 variants:
        # - 2019-07-16T12:00:00Z (UTC with Z suffix)
        # - 2019-07-16T12:00:00+00:00 (with timezone offset)
        # - 2019-07-16T12:00:00.000Z (with milliseconds)
        # - UNIX epoch timestamp (seconds since 1970-01-01)
        is_valid_date, date_error = _validate_date_value(value_str)
        if not is_valid_date:
            return False, date_error

    elif value_type == "IPAddress":
        # IP Address: IPv4 or IPv6 with optional CIDR notation
        # Use Python's ipaddress module for robust validation
        try:
            # Try parsing as network (with CIDR) or address
            try:
                ipaddress.ip_network(value_str, strict=False)
            except ValueError:
                ipaddress.ip_address(value_str)
        except ValueError:
            return (
                False,
                f"Expected IPAddress value (203.0.113.0/24 or 2001:DB8::/32) but got: {value_str}",
            )

    elif value_type == "Numeric":
        # Numeric: Integers and decimals (positive and negative)
        numeric_pattern = r"^-?\d+(\.\d+)?$"
        if not re.match(numeric_pattern, value_str):
            return False, f"Expected Numeric value (integer or decimal) but got: {value_str}"

    elif value_type == "String":
        # Strings can be any value
        pass

    return True, None


def is_condition_key_match(documented_key: str, policy_key: str) -> bool:
    """
    Determine if a documented condition key matches a policy condition key.

    Handles various wildcard and placeholder patterns used in AWS documentation:
    - ${...} patterns (e.g., ${TagKey})
    - <...> patterns (e.g., <key>)
    - Literal tag-key placeholders

    Args:
        documented_key: Key from AWS documentation (may contain placeholders)
        policy_key: Key from the actual policy

    Returns:
        True if they match

    Examples:
        >>> is_condition_key_match("s3:prefix", "s3:prefix")
        True
        >>> is_condition_key_match("s3:ExistingObjectTag/<key>", "s3:ExistingObjectTag/backup")
        True
        >>> is_condition_key_match("license-manager:ResourceTag/${TagKey}", "license-manager:ResourceTag/Environment")
        True
        >>> is_condition_key_match("secretsmanager:ResourceTag/tag-key", "secretsmanager:ResourceTag/Production")
        True

    Reference:
        AWS service authorization documentation for condition key patterns
    """
    # Normalize both to lowercase for comparison
    doc_key_lower = documented_key.lower()
    policy_key_lower = policy_key.lower()

    # Exact match
    if doc_key_lower == policy_key_lower:
        return True

    # Check for ${...} pattern (e.g., license-manager:ResourceTag/${TagKey})
    if "${" in doc_key_lower:
        prefix = doc_key_lower.split("${")[0]
        if policy_key_lower.startswith(prefix):
            return True

    # Check for <...> pattern (e.g., s3:ExistingObjectTag/<key>)
    if "<" in doc_key_lower:
        prefix = doc_key_lower.split("<")[0]
        if policy_key_lower.startswith(prefix):
            return True

    # Check for tag-key literal (e.g., secretsmanager:ResourceTag/tag-key)
    if "tag-key" in doc_key_lower:
        prefix = doc_key_lower.split("tag-key")[0]
        if policy_key_lower.startswith(prefix):
            return True

    return False


def is_negated_operator(operator: str) -> bool:
    """
    Determine if a condition operator is negated (NotEquals, NotLike, etc.).

    Negated operators have special behavior with missing keys:
    - Standard operators: Missing keys evaluate to false (condition fails)
    - Negated operators: Missing keys evaluate to true (condition passes)

    Args:
        operator: Condition operator to check

    Returns:
        True if the operator is negated

    Examples:
        >>> is_negated_operator("StringNotEquals")
        True
        >>> is_negated_operator("StringEquals")
        False
        >>> is_negated_operator("ForAllValues:StringNotLike")
        True
        >>> is_negated_operator("ArnNotEqualsIfExists")
        True
        >>> is_negated_operator("NotIpAddress")
        True

    Reference:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
    """
    # Remove set operator prefix if present
    cleaned = operator
    if ":" in operator:
        parts = operator.split(":", 1)
        if parts[0] in SET_OPERATOR_PREFIXES:
            cleaned = parts[1]

    # Remove IfExists suffix
    if cleaned.endswith("IfExists"):
        cleaned = cleaned[:-8]

    # Check if operator contains "Not" (case-insensitive)
    return "not" in cleaned.lower()


def is_operator_supports_policy_variables(operator: str) -> bool:
    """
    Determine if a condition operator supports policy variables.

    Policy variables allow dynamic values in conditions (e.g., ${aws:username}).

    Operators supporting policy variables:
    - String operators (all variants)
    - ARN operators (all variants)
    - Bool operator

    Operators NOT supporting policy variables:
    - Numeric operators
    - Date operators
    - Binary operators
    - IP address operators

    Args:
        operator: Condition operator to check

    Returns:
        True if the operator supports policy variables

    Examples:
        >>> is_operator_supports_policy_variables("StringEquals")
        True
        >>> is_operator_supports_policy_variables("NumericEquals")
        False
        >>> is_operator_supports_policy_variables("ArnLike")
        True
        >>> is_operator_supports_policy_variables("Bool")
        True
        >>> is_operator_supports_policy_variables("DateLessThan")
        False

    Reference:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
    """
    base_op, _, _ = normalize_operator(operator)

    # Operators that support policy variables
    policy_var_operators = {
        # String operators
        "StringEquals",
        "StringNotEquals",
        "StringEqualsIgnoreCase",
        "StringNotEqualsIgnoreCase",
        "StringLike",
        "StringNotLike",
        # ARN operators
        "ArnEquals",
        "ArnLike",
        "ArnNotEquals",
        "ArnNotLike",
        # Bool operator
        "Bool",
    }

    return base_op in policy_var_operators


def is_operator_supports_wildcards(operator: str) -> bool:
    """
    Determine if a condition operator supports wildcard characters (* and ?).

    Wildcard support:
    - StringLike/StringNotLike: Yes (* for multi-char, ? for single-char)
    - ArnLike/ArnNotLike/ArnEquals/ArnNotEquals: Yes
    - All other operators: No

    Args:
        operator: Condition operator to check

    Returns:
        True if the operator supports wildcards

    Examples:
        >>> is_operator_supports_wildcards("StringLike")
        True
        >>> is_operator_supports_wildcards("StringEquals")
        False
        >>> is_operator_supports_wildcards("ArnLike")
        True
        >>> is_operator_supports_wildcards("NumericEquals")
        False

    Reference:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
    """
    base_op, _, _ = normalize_operator(operator)

    # Operators that support wildcards
    wildcard_operators = {
        "StringLike",
        "StringNotLike",
        "ArnEquals",
        "ArnLike",
        "ArnNotEquals",
        "ArnNotLike",
    }

    return base_op in wildcard_operators


def get_operator_description(operator: str) -> str:
    """
    Get a human-readable description of what a condition operator does.

    Args:
        operator: Condition operator

    Returns:
        Description of the operator's behavior

    Examples:
        >>> get_operator_description("StringEquals")
        "Case-sensitive string matching"
        >>> get_operator_description("NumericLessThan")
        "Numeric less-than comparison"
        >>> get_operator_description("ForAllValues:StringLike")
        "All values must match pattern (case-sensitive with wildcards)"

    Reference:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
    """
    base_op, _, set_prefix = normalize_operator(operator)

    descriptions = {
        "StringEquals": "Case-sensitive string matching",
        "StringNotEquals": "Case-sensitive string non-matching",
        "StringEqualsIgnoreCase": "Case-insensitive string matching",
        "StringNotEqualsIgnoreCase": "Case-insensitive string non-matching",
        "StringLike": "Case-sensitive pattern matching (supports * and ? wildcards)",
        "StringNotLike": "Case-sensitive pattern non-matching (supports * and ? wildcards)",
        "NumericEquals": "Numeric equality comparison",
        "NumericNotEquals": "Numeric inequality comparison",
        "NumericLessThan": "Numeric less-than comparison",
        "NumericLessThanEquals": "Numeric less-than-or-equal comparison",
        "NumericGreaterThan": "Numeric greater-than comparison",
        "NumericGreaterThanEquals": "Numeric greater-than-or-equal comparison",
        "DateEquals": "Date/time equality comparison",
        "DateNotEquals": "Date/time inequality comparison",
        "DateLessThan": "Date/time before comparison",
        "DateLessThanEquals": "Date/time at-or-before comparison",
        "DateGreaterThan": "Date/time after comparison",
        "DateGreaterThanEquals": "Date/time at-or-after comparison",
        "Bool": "Boolean value matching",
        "BinaryEquals": "Binary data byte-for-byte comparison",
        "IpAddress": "IP address within CIDR range",
        "NotIpAddress": "IP address outside CIDR range",
        "ArnEquals": "ARN matching (supports wildcards)",
        "ArnLike": "ARN pattern matching (supports wildcards)",
        "ArnNotEquals": "ARN non-matching (supports wildcards)",
        "ArnNotLike": "ARN pattern non-matching (supports wildcards)",
        "Null": "Key existence check",
    }

    desc = descriptions.get(base_op, "Unknown operator")

    # Add set operator prefix description
    if set_prefix == "ForAllValues":
        desc = f"All values must match: {desc}"
    elif set_prefix == "ForAnyValue":
        desc = f"At least one value must match: {desc}"

    return desc


def is_multivalued_context_key(condition_key: str) -> bool:
    """
    Determine if a condition key is multivalued (can have multiple values in request context).

    Multivalued context keys include:
    - aws:TagKeys (list of tag keys being applied)
    - aws:PrincipalOrgPaths (organization paths)
    - Service-specific multivalued keys (e.g., s3:x-amz-grant-*)

    Single-valued context keys include:
    - aws:SourceIp (single IP address)
    - aws:userid (single user ID)
    - aws:username (single username)
    - Most global condition keys

    Args:
        condition_key: The condition key to check

    Returns:
        True if the key is multivalued

    Examples:
        >>> is_multivalued_context_key("aws:TagKeys")
        True
        >>> is_multivalued_context_key("aws:SourceIp")
        False
        >>> is_multivalued_context_key("aws:PrincipalTag/Department")
        False

    Reference:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html

    Note:
        This function identifies commonly known multivalued keys. For complete validation,
        consult AWS service documentation or use the AWSServiceFetcher to look up key metadata.
    """
    # Normalize to lowercase for comparison
    key_lower = condition_key.lower()

    # Known multivalued global condition keys
    multivalued_keys = {
        "aws:tagkeys",  # List of tag keys being applied/modified
        "aws:principalorgpaths",  # Organization paths for the principal
    }

    # Check exact matches
    if key_lower in multivalued_keys:
        return True

    # Service-specific multivalued patterns
    # S3 grant headers are multivalued
    if key_lower.startswith("s3:x-amz-grant-"):
        return True

    # EC2 resource tags in requests can be multivalued
    if "ec2:" in key_lower and ":resourcetag/" in key_lower:
        return True

    # Most condition keys are single-valued by default
    return False

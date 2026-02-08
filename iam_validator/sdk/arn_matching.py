"""
ARN pattern matching utilities for IAM policy validation.

This module provides functions for matching ARN patterns with glob support.
Portions of this code are derived from or inspired by Parliament's ARN matching
implementation.

Original work Copyright 2019 Duo Security (BSD 3-Clause License)
Modifications and additions Copyright 2024 (MIT License)

Parliament: https://github.com/duo-labs/parliament
License: https://github.com/duo-labs/parliament/blob/master/LICENSE

The is_glob_match() function is adapted from Parliament's implementation.
See: https://github.com/duo-labs/parliament/issues/36#issuecomment-574001764
"""

import re


def arn_matches(
    arn_pattern: str,
    arn: str,
    resource_type: str | None = None,
) -> bool:
    """
    Check if an ARN matches a pattern with glob support.

    Both the pattern and ARN can contain wildcards (*). This is useful for
    validating that policy resources match the required format for actions.

    Args:
        arn_pattern: ARN pattern (e.g., from AWS docs), can have wildcards
        arn: ARN from policy, can have wildcards
        resource_type: Optional resource type (e.g., "bucket", "object") for special handling

    Returns:
        True if ARN could match the pattern

    Examples:
        >>> arn_matches("arn:*:s3:::*/*", "arn:aws:s3:::bucket/key")
        True

        >>> arn_matches("arn:*:s3:::*/*", "arn:aws:s3:::bucket")
        False

        >>> # Both can have wildcards
        >>> arn_matches("arn:*:s3:::*/*", "arn:aws:s3:::*personalize*")
        True  # Could match "arn:aws:s3:::personalize/file"

        >>> # Special case: S3 buckets can't have /
        >>> arn_matches("arn:*:s3:::*", "arn:aws:s3:::bucket/key", resource_type="bucket")
        False
    """
    # Wildcard shortcuts
    if arn_pattern == "*" or arn == "*":
        return True

    # Special case for S3 buckets - no "/" allowed
    if resource_type and "bucket" in resource_type.lower():
        # Strip variables like ${aws:username} before checking
        arn_without_vars = _strip_variables_from_arn(arn)
        if "/" in arn_without_vars:
            return False

    # Parse ARN into parts
    pattern_parts = arn_pattern.split(":")
    arn_parts = arn.split(":")

    # ARN must have at least 6 parts: arn:partition:service:region:account:resource
    if len(pattern_parts) < 6 or len(arn_parts) < 6:
        # Invalid ARN format
        return False

    # Match first 5 parts (arn:partition:service:region:account)
    for i in range(5):
        pattern_part = pattern_parts[i]
        arn_part = arn_parts[i]

        # Pattern wildcard matches any non-empty value
        if pattern_part == "*" and arn_part != "":
            continue
        # ARN wildcard matches anything
        elif arn_part == "*":
            continue
        # Exact match
        elif pattern_part == arn_part:
            continue
        else:
            # No match
            return False

    # Match resource ID (everything after 5th colon)
    pattern_id = ":".join(pattern_parts[5:])
    arn_id = ":".join(arn_parts[5:])

    # Replace variables like [key] with wildcard
    arn_id = re.sub(r"\[.+?\]", "*", arn_id)

    return is_glob_match(pattern_id, arn_id)


def arn_strictly_valid(
    arn_pattern: str,
    arn: str,
    resource_type: str | None = None,
) -> bool:
    """
    Strictly validate ARN against pattern with resource type checking.

    This is stricter than arn_matches() and enforces:
    - Resource type must be present and match
    - No wildcards in resource type portion
    - No extra colons in resource ID

    Args:
        arn_pattern: ARN pattern from AWS service definition
        arn: ARN from policy
        resource_type: Optional resource type for additional validation

    Returns:
        True if ARN strictly matches the pattern

    Examples:
        >>> # Valid: has resource type "user"
        >>> arn_strictly_valid("arn:*:iam::*:user/*", "arn:aws:iam::123456789012:user/alice")
        True

        >>> # Invalid: missing resource type
        >>> arn_strictly_valid("arn:*:iam::*:user/*", "arn:aws:iam::123456789012:u*")
        False
    """
    # First check basic match
    if not arn_matches(arn_pattern, arn, resource_type):
        return False

    # Parse ARNs
    pattern_parts = arn_pattern.split(":")
    arn_parts = arn.split(":")

    pattern_id = ":".join(pattern_parts[5:])
    arn_id = ":".join(arn_parts[5:])

    # Check if pattern has a resource type component
    # Example: "user/alice" has resource type "user"
    # Regex: resource type word followed by : or / (excluding patterns starting with *)
    resource_type_match = re.match(r"(^[^\*][\w-]+)[\/\:](.+)", pattern_id)

    if resource_type_match and arn_id != "*":
        expected_resource_type = resource_type_match.group(1)

        # ARN must start with the same resource type
        # Invalid: arn:aws:iam::123456789012:u* (wildcards not allowed in resource type)
        if not arn_id.startswith(expected_resource_type):
            return False

    # Check for invalid colons in resource ID
    # Strip variables first
    arn_id_without_vars = _strip_variables_from_arn(arn_id)

    # If ARN has colons but pattern doesn't, it's invalid
    if ":" in arn_id_without_vars and ":" not in pattern_id:
        return False

    return True


def is_glob_match(s1: str, s2: str) -> bool:
    """
    Glob pattern matching for two strings using memoized recursion.

    Both strings can contain wildcards (*). Uses index-based memoization
    to avoid exponential branching on multiple wildcards.

    Args:
        s1: First string (can contain *)
        s2: Second string (can contain *)

    Returns:
        True if strings could match

    Examples:
        >>> is_glob_match("*/*", "*personalize*")
        True

        >>> is_glob_match("*/*", "mybucket")
        False

        >>> is_glob_match("*mybucket", "*myotherthing")
        False

        >>> is_glob_match("test*", "test123")
        True

    Note:
        This is adapted from Parliament's implementation:
        https://github.com/duo-labs/parliament/issues/36#issuecomment-574001764
    """
    memo: dict[tuple[int, int], bool] = {}

    def _match(i: int, j: int) -> bool:
        key = (i, j)
        if key in memo:
            return memo[key]

        a = s1[i:] if i < len(s1) else ""
        b = s2[j:] if j < len(s2) else ""

        # If strings are equal, TRUE
        if a == b:
            result = True
        # If either string is all wildcards, TRUE
        elif (a and all(c == "*" for c in a)) or (b and all(c == "*" for c in b)):
            result = True
        # If either string is empty, FALSE
        elif not a or not b:
            result = False
        # Both start with *
        elif a[0] == b[0] == "*":
            result = _match(i + 1, j) or _match(i, j + 1)
        # s1 starts with *
        elif a[0] == "*":
            result = any(_match(i + 1, j + k) for k in range(len(b) + 1))
        # s2 starts with *
        elif b[0] == "*":
            result = any(_match(i + k, j + 1) for k in range(len(a) + 1))
        # Same first character
        elif a[0] == b[0]:
            result = _match(i + 1, j + 1)
        else:
            result = False

        memo[key] = result
        return result

    return _match(0, 0)


def _strip_variables_from_arn(arn: str, replace_with: str = "") -> str:
    """
    Strip AWS policy variables from ARN.

    Examples:
        ${aws:username} → ""
        bucket-${aws:username} → "bucket-"

    Args:
        arn: ARN string that may contain variables
        replace_with: What to replace variables with (default: empty string)

    Returns:
        ARN with variables replaced
    """
    # Match AWS policy variables ${aws:X}, Terraform ${var.X},
    # CloudFormation ${AWS::X}, and other ${...} template variables
    return re.sub(r"\$\{(?:aws[\.:]|var\.|AWS::)[^\}]+\}", replace_with, arn)


def normalize_template_variables(arn: str) -> str:
    """
    Normalize template variables in ARN to valid placeholders for validation.

    This function is POSITION-AWARE and handles ANY variable name by determining
    the appropriate replacement based on where the variable appears in the ARN structure.
    It correctly handles variables with colons inside them (e.g., ${AWS::AccountId}).

    Supports template variables from:
    - Terraform/Terragrunt: ${var.name}, ${local.value}, ${data.source.attr}, etc.
    - CloudFormation: ${AWS::AccountId}, ${AWS::Region}, ${MyParameter}, etc.
    - AWS policy variables: ${aws:username}, ${aws:PrincipalTag/tag-key}, etc.

    Args:
        arn: ARN string that may contain template variables

    Returns:
        ARN with template variables replaced with valid placeholders based on position

    Examples:
        >>> normalize_template_variables("arn:aws:iam::${my_account}:role/name")
        'arn:aws:iam::123456789012:role/name'

        >>> normalize_template_variables("arn:aws:iam::${AWS::AccountId}:role/name")
        'arn:aws:iam::123456789012:role/name'

        >>> normalize_template_variables("arn:${var.partition}:s3:::${var.bucket}/*")
        'arn:aws:s3:::placeholder/*'
    """
    # Strategy: Use a simpler, more robust approach
    # First protect template variables by temporarily replacing them with markers,
    # then split the ARN, then replace based on position

    # Step 1: Find all template variables and temporarily replace them with position markers
    # This handles variables with colons inside them (like ${AWS::AccountId})
    variables = []

    def save_variable(match):
        variables.append(match.group(0))
        return f"__VAR{len(variables) - 1}__"

    # Save all template variables (including those with colons, dots, slashes, etc.)
    temp_arn = re.sub(r"\$\{[^}]+\}", save_variable, arn)

    # Step 2: Now we can safely split by colons
    parts = temp_arn.split(":", 5)

    if len(parts) < 6:
        # Not a valid ARN format, restore variables with generic placeholder
        result = arn
        for var in variables:
            result = result.replace(var, "placeholder", 1)
        return result

    # Step 3: Restore variables based on their position in the ARN
    # ARN format: arn:partition:service:region:account:resource
    replacements = {
        1: "aws",  # partition
        2: "s3",  # service (generic placeholder)
        3: "us-east-1",  # region
        4: "123456789012",  # account
        5: "placeholder",  # resource
    }

    for i, part in enumerate(parts):
        if "__VAR" in part:
            # Find all variable markers in this part
            for j, var in enumerate(variables):
                marker = f"__VAR{j}__"
                if marker in part:
                    # Determine replacement based on position
                    if i in replacements:
                        parts[i] = parts[i].replace(marker, replacements[i])
                    else:
                        parts[i] = parts[i].replace(marker, "placeholder")

    # Reconstruct ARN
    return ":".join(parts)


def has_template_variables(arn: str) -> bool:
    """
    Check if an ARN contains template variables.

    Detects template variables from:
    - Terraform/Terragrunt: ${var_name}
    - CloudFormation: ${AWS::AccountId}
    - AWS policy variables: ${aws:username}

    Args:
        arn: ARN string to check

    Returns:
        True if ARN contains template variables, False otherwise

    Examples:
        >>> has_template_variables("arn:aws:iam::${aws_account_id}:role/name")
        True

        >>> has_template_variables("arn:aws:iam::123456789012:role/name")
        False
    """
    return bool(re.search(r"\$\{[\w\-\.\_:\/]+\}", arn))


def convert_aws_pattern_to_wildcard(pattern: str) -> str:
    """
    Convert AWS ARN pattern format to wildcard pattern for matching.

    AWS provides ARN patterns with placeholders like ${Partition}, ${BucketName},
    etc. This function converts them to wildcard (*) patterns that can be used
    with arn_matches() and arn_strictly_valid().

    Args:
        pattern: ARN pattern from AWS service definition

    Returns:
        ARN pattern with placeholders replaced by wildcards

    Examples:
        >>> convert_aws_pattern_to_wildcard("arn:${Partition}:s3:::${BucketName}/${ObjectName}")
        "arn:*:s3:::*/*"

        >>> convert_aws_pattern_to_wildcard("arn:${Partition}:iam::${Account}:user/${UserNameWithPath}")
        "arn:*:iam::*:user/*"

        >>> convert_aws_pattern_to_wildcard("arn:${Partition}:ec2:${Region}:${Account}:instance/${InstanceId}")
        "arn:*:ec2:*:*:instance/*"
    """
    # Replace all ${...} placeholders with *
    # Matches ${Partition}, ${BucketName}, ${Account}, etc.
    return re.sub(r"\$\{[^}]+\}", "*", pattern)

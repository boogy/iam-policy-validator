"""Parsing and pattern matching for AWS actions and resources.

This module provides functionality to parse IAM actions, validate ARN formats,
and perform wildcard matching on action patterns.
"""

import re

from iam_validator.core.aws_service.patterns import CompiledPatterns


class ServiceParser:
    """Parses and matches AWS actions, ARNs, and wildcards.

    This class provides methods for:
    - Parsing IAM actions into service prefix and action name
    - Validating ARN format
    - Detecting and matching wildcard patterns
    - Expanding wildcard actions to full action lists
    """

    def __init__(self) -> None:
        """Initialize parser with compiled patterns."""
        self._patterns = CompiledPatterns()

    def parse_action(self, action: str) -> tuple[str, str]:
        """Parse IAM action into service prefix and action name.

        Args:
            action: Full action string (e.g., "s3:GetObject", "iam:CreateUser")

        Returns:
            Tuple of (service_prefix, action_name) both lowercase

        Raises:
            ValueError: If action format is invalid

        Example:
            >>> parser = ServiceParser()
            >>> parser.parse_action("s3:GetObject")
            ('s3', 'GetObject')
        """
        match = self._patterns.action_pattern.match(action)
        if not match:
            raise ValueError(self.describe_action_format_error(action))

        return match.group("service").lower(), match.group("action")

    def describe_action_format_error(self, action: str) -> str:
        """Explain why an action string cannot be parsed.

        The service prefix of an action must name a single service literally.
        AWS rejects either wildcard character there (`*` or `?`) with
        `MalformedPolicyDocument: Action vendors (e.g., aws, ec2, etc.) must
        not contain wildcards`, so the message calls that case out separately
        from a plain malformed action.

        Args:
            action: Action string that failed to parse

        Returns:
            Human-readable explanation, suitable for a validation finding

        Example:
            >>> parser = ServiceParser()
            >>> parser.describe_action_format_error("*:Untag*")[:44]
            'Invalid action format: `*:Untag*`. The servi'
        """
        service, separator, action_name = action.partition(":")

        if separator and any(char in service for char in ("*", "?")):
            suggestion = action_name or "*"
            return (
                f"Invalid action format: `{action}`. The service prefix cannot contain a "
                f"wildcard - AWS rejects this with `MalformedPolicyDocument: Action vendors "
                f"(e.g., aws, ec2, etc.) must not contain wildcards`. List one action per "
                f"service instead (e.g. `iam:{suggestion}`, `s3:{suggestion}`). A wildcard "
                f"inside the action name is allowed."
            )

        if not separator:
            return f"Invalid action format: `{action}`. Expected `<service>:<action>`, e.g. `s3:GetObject`."

        return (
            f"Invalid action format: `{action}`. Expected `<service>:<action>` where both "
            f"parts use only letters, digits, `_`, `-` and (in the action name) `*`."
        )

    def validate_arn_format(self, arn: str) -> tuple[bool, str | None]:
        """Validate ARN format using compiled regex.

        Args:
            arn: ARN string to validate

        Returns:
            Tuple of (is_valid, error_message). error_message is None if valid.

        Example:
            >>> parser = ServiceParser()
            >>> parser.validate_arn_format("arn:aws:s3:::my-bucket/*")
            (True, None)
            >>> parser.validate_arn_format("invalid")
            (False, "Invalid ARN format: invalid")
        """
        if arn == "*":
            return True, None

        match = self._patterns.arn_pattern.match(arn)
        if not match:
            return False, f"Invalid ARN format: {arn}"

        return True, None

    def is_wildcard_action(self, action_name: str) -> bool:
        """Check if action name contains wildcards.

        Args:
            action_name: Action name to check (e.g., "GetObject", "Get*", "*")

        Returns:
            True if action contains wildcard characters

        Example:
            >>> parser = ServiceParser()
            >>> parser.is_wildcard_action("GetObject")
            False
            >>> parser.is_wildcard_action("Get*")
            True
        """
        return bool(self._patterns.wildcard_pattern.search(action_name))

    def match_wildcard_action(self, pattern: str, actions: list[str]) -> tuple[bool, list[str]]:
        """Match wildcard pattern against list of actions.

        Args:
            pattern: Action pattern with wildcards (e.g., "Get*", "*Object", "Describe*")
            actions: List of valid action names to match against

        Returns:
            Tuple of (has_matches, list_of_matched_actions)

        Example:
            >>> parser = ServiceParser()
            >>> actions = ["GetObject", "GetBucket", "PutObject"]
            >>> parser.match_wildcard_action("Get*", actions)
            (True, ['GetObject', 'GetBucket'])
        """
        # Convert wildcard pattern to regex
        # Escape special regex chars except *, then replace * with .*
        regex_pattern = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        compiled_pattern = re.compile(regex_pattern, re.IGNORECASE)

        matched = [a for a in actions if compiled_pattern.match(a)]
        return len(matched) > 0, matched

    def expand_wildcard_to_actions(
        self,
        action_pattern: str,
        available_actions: list[str],
        service_prefix: str,
    ) -> list[str]:
        """Expand wildcard pattern to full list of actions.

        Args:
            action_pattern: Action pattern (e.g., "s3:Get*", "iam:*")
            available_actions: List of available action names for the service
            service_prefix: Service prefix (e.g., "s3", "iam")

        Returns:
            Sorted list of fully-qualified actions matching the pattern

        Example:
            >>> parser = ServiceParser()
            >>> actions = ["GetObject", "PutObject", "DeleteObject"]
            >>> parser.expand_wildcard_to_actions("s3:*Object", actions, "s3")
            ['s3:DeleteObject', 's3:GetObject', 's3:PutObject']
        """
        # Parse to get action name part
        _, action_name = self.parse_action(action_pattern)

        # Handle full service wildcard (e.g., "iam:*")
        if action_name == "*":
            return sorted([f"{service_prefix}:{action}" for action in available_actions])

        # Match wildcard pattern
        _, matched_actions = self.match_wildcard_action(action_name, available_actions)

        # Return fully-qualified actions
        return sorted([f"{service_prefix}:{action}" for action in matched_actions])

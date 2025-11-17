"""Validation logic for AWS actions, condition keys, and resources.

This module provides comprehensive validation for IAM policy elements
including actions, condition keys, and ARN formats.
"""

import logging
from dataclasses import dataclass
from typing import Any

from iam_validator.core.aws_service.parsers import ServiceParser
from iam_validator.core.models import ServiceDetail

logger = logging.getLogger(__name__)


@dataclass
class ConditionKeyValidationResult:
    """Result of condition key validation.

    Attributes:
        is_valid: True if the condition key is valid for the action
        error_message: Short error message if invalid (shown prominently)
        warning_message: Warning message if valid but not recommended
        suggestion: Detailed suggestion with valid keys (shown in collapsible section)
    """

    is_valid: bool
    error_message: str | None = None
    warning_message: str | None = None
    suggestion: str | None = None


class ServiceValidator:
    """Validates AWS actions, condition keys, and resources.

    This class provides validation logic for IAM policy elements,
    working with AWS service definitions to ensure correctness.
    """

    def __init__(self, parser: ServiceParser | None = None) -> None:
        """Initialize validator with parser.

        Args:
            parser: Optional ServiceParser instance (creates new one if not provided)
        """
        self._parser = parser or ServiceParser()

    async def validate_action(
        self,
        action: str,
        service_detail: ServiceDetail,
        allow_wildcards: bool = True,
    ) -> tuple[bool, str | None, bool]:
        """Validate IAM action against service definition.

        Supports:
        - Exact actions: s3:GetObject
        - Full wildcards: s3:*
        - Partial wildcards: s3:Get*, s3:*Object, s3:*Get*

        Args:
            action: Full action string (e.g., "s3:GetObject")
            service_detail: Service definition to validate against
            allow_wildcards: Whether to allow wildcard actions

        Returns:
            Tuple of (is_valid, error_message, is_wildcard)

        Example:
            >>> validator = ServiceValidator()
            >>> service = await fetcher.fetch_service_by_name("s3")
            >>> is_valid, error, is_wildcard = await validator.validate_action(
            ...     "s3:GetObject", service
            ... )
        """
        try:
            service_prefix, action_name = self._parser.parse_action(action)

            # Quick wildcard check
            is_wildcard = self._parser.is_wildcard_action(action_name)

            # Handle full wildcard
            if action_name == "*":
                if allow_wildcards:
                    return True, None, True
                return False, "Wildcard actions are not allowed", True

            # Get available actions from service
            available_actions = list(service_detail.actions.keys())

            # Handle partial wildcards (e.g., Get*, *Object, Describe*)
            if is_wildcard:
                if not allow_wildcards:
                    return False, "Wildcard actions are not allowed", True

                has_matches, _ = self._parser.match_wildcard_action(action_name, available_actions)

                if has_matches:
                    # Wildcard is valid and matches at least one action
                    return True, None, True

                # Wildcard doesn't match any actions
                return (
                    False,
                    f"Action pattern `{action_name}` does not match any actions in service `{service_prefix}`",
                    True,
                )

            # Check if exact action exists (case-insensitive)
            action_exists = any(a.lower() == action_name.lower() for a in available_actions)

            if action_exists:
                return True, None, False

            # Suggest similar actions
            similar = [f"`{a}`" for a in available_actions if action_name.lower() in a.lower()][:3]

            suggestion = f" Did you mean: {', '.join(similar)}?" if similar else ""
            return (
                False,
                f"Action `{action_name}` not found in service `{service_prefix}`.{suggestion}",
                False,
            )

        except ValueError as e:
            return False, str(e), False
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"Error validating action {action}: {e}")
            return False, f"Failed to validate action: {e!s}", False

    async def validate_condition_key(
        self,
        action: str,
        condition_key: str,
        service_detail: ServiceDetail,
        resources: list[str] | None = None,
    ) -> ConditionKeyValidationResult:
        """Validate condition key against action and optionally resource types.

        Args:
            action: IAM action (e.g., "s3:GetObject")
            condition_key: Condition key to validate (e.g., "s3:prefix")
            service_detail: Service definition containing actions and resources
            resources: Optional list of resource ARNs to validate against

        Returns:
            ConditionKeyValidationResult with validation details

        Example:
            >>> validator = ServiceValidator()
            >>> service = await fetcher.fetch_service_by_name("s3")
            >>> result = await validator.validate_condition_key(
            ...     "s3:GetObject", "s3:prefix", service
            ... )
        """
        try:
            from iam_validator.core.config.aws_global_conditions import (  # pylint: disable=import-outside-toplevel
                get_global_conditions,
            )

            _, action_name = self._parser.parse_action(action)

            # Check if it's a global condition key
            is_global_key = False
            if condition_key.startswith("aws:"):
                global_conditions = get_global_conditions()
                if global_conditions.is_valid_global_key(condition_key):
                    is_global_key = True
                else:
                    return ConditionKeyValidationResult(
                        is_valid=False,
                        error_message=f"Invalid AWS global condition key: `{condition_key}`.",
                    )

            # Check service-specific condition keys
            if condition_key in service_detail.condition_keys:
                return ConditionKeyValidationResult(is_valid=True)

            # Check action-specific condition keys
            if action_name in service_detail.actions:
                action_detail = service_detail.actions[action_name]
                if (
                    action_detail.action_condition_keys
                    and condition_key in action_detail.action_condition_keys
                ):
                    return ConditionKeyValidationResult(is_valid=True)

                # Check resource-specific condition keys
                # Get resource types required by this action
                if resources and action_detail.resources:
                    for res_req in action_detail.resources:
                        resource_name = res_req.get("Name", "")
                        if not resource_name:
                            continue

                        # Look up resource type definition
                        resource_type = service_detail.resources.get(resource_name)
                        if resource_type and resource_type.condition_keys:
                            if condition_key in resource_type.condition_keys:
                                return ConditionKeyValidationResult(is_valid=True)

                # If it's a global key but the action has specific condition keys defined,
                # AWS allows it but the key may not be available in every request context
                if is_global_key and action_detail.action_condition_keys is not None:
                    warning_msg = (
                        f"Global condition key `{condition_key}` is used with action `{action}`. "
                        f"While global condition keys can be used across all AWS services, "
                        f"the key may not be available in every request context. "
                        f"Verify that `{condition_key}` is available for this specific action's request context. "
                        f"Consider using `*IfExists` operators (e.g., `StringEqualsIfExists`) if the key might be missing."
                    )
                    return ConditionKeyValidationResult(is_valid=True, warning_message=warning_msg)

            # If it's a global key and action doesn't define specific keys, allow it
            if is_global_key:
                return ConditionKeyValidationResult(is_valid=True)

            # Short error message
            error_msg = f"Condition key `{condition_key}` is not valid for action `{action}`"

            # Collect valid condition keys for this action
            valid_keys: set[str] = set()

            # Add service-level condition keys
            if service_detail.condition_keys:
                if isinstance(service_detail.condition_keys, dict):
                    valid_keys.update(service_detail.condition_keys.keys())
                elif isinstance(service_detail.condition_keys, list):
                    valid_keys.update(service_detail.condition_keys)

            # Add action-specific condition keys
            if action_name in service_detail.actions:
                action_detail = service_detail.actions[action_name]
                if action_detail.action_condition_keys:
                    if isinstance(action_detail.action_condition_keys, dict):
                        valid_keys.update(action_detail.action_condition_keys.keys())
                    elif isinstance(action_detail.action_condition_keys, list):
                        valid_keys.update(action_detail.action_condition_keys)

                # Add resource-specific condition keys
                if action_detail.resources:
                    for res_req in action_detail.resources:
                        resource_name = res_req.get("Name", "")
                        if resource_name:
                            resource_type = service_detail.resources.get(resource_name)
                            if resource_type and resource_type.condition_keys:
                                if isinstance(resource_type.condition_keys, dict):
                                    valid_keys.update(resource_type.condition_keys.keys())
                                elif isinstance(resource_type.condition_keys, list):
                                    valid_keys.update(resource_type.condition_keys)

            # Build detailed suggestion with valid keys (goes in collapsible section)
            suggestion_parts = []

            if valid_keys:
                # Sort and limit to first 10 keys for readability
                sorted_keys = sorted(valid_keys)
                suggestion_parts.append("**Valid condition keys for this action:**")
                if len(sorted_keys) <= 10:
                    for key in sorted_keys:
                        suggestion_parts.append(f"- `{key}`")
                else:
                    for key in sorted_keys[:10]:
                        suggestion_parts.append(f"- `{key}`")
                    suggestion_parts.append(f"- ... and {len(sorted_keys) - 10} more")

                suggestion_parts.append("")
                suggestion_parts.append(
                    "**Global condition keys** (e.g., `aws:ResourceOrgID`, `aws:RequestedRegion`, `aws:SourceIp`, `aws:SourceVpce`) "
                    "can also be used with any AWS action"
                )
            else:
                # No action-specific keys - mention global keys
                suggestion_parts.append(
                    "This action does not have specific condition keys defined.\n\n"
                    "However, you can use **global condition keys** such as:\n"
                    "- `aws:RequestedRegion`\n"
                    "- `aws:SourceIp`\n"
                    "- `aws:SourceVpce`\n"
                    "- `aws:ResourceOrgID`\n"
                    "- `aws:PrincipalOrgID`\n"
                    "- `aws:SourceAccount`\n"
                    "- `aws:PrincipalAccount`\n"
                    "- `aws:CurrentTime`\n"
                    "- `aws:ResourceAccount`\n"
                    "- `aws:PrincipalArn`\n"
                    "- And many others"
                )

            suggestion = "\n".join(suggestion_parts)

            return ConditionKeyValidationResult(
                is_valid=False,
                error_message=error_msg,
                suggestion=suggestion,
            )

        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"Error validating condition key {condition_key} for {action}: {e}")
            return ConditionKeyValidationResult(
                is_valid=False,
                error_message=f"Failed to validate condition key: {e!s}",
            )

    def get_resources_for_action(
        self, action: str, service_detail: ServiceDetail
    ) -> list[dict[str, Any]]:
        """Get resource types required for a specific action.

        Args:
            action: Full action name (e.g., "s3:GetObject", "iam:CreateUser")
            service_detail: Service definition containing action details

        Returns:
            List of resource dictionaries from AWS API, or empty list if action not found

        Example:
            >>> validator = ServiceValidator()
            >>> service = await fetcher.fetch_service_by_name("s3")
            >>> resources = validator.get_resources_for_action("s3:GetObject", service)
        """
        try:
            _, action_name = self._parser.parse_action(action)  # pylint: disable=unused-variable

            # Find the action (case-insensitive)
            action_detail = service_detail.actions.get(action_name)
            if action_detail and action_detail.resources:
                return action_detail.resources
            return []
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"Error getting resources for action {action}: {e}")
            return []

    def get_arn_formats_for_action(self, action: str, service_detail: ServiceDetail) -> list[str]:
        """Get ARN formats/patterns for resources used by a specific action.

        This method extracts the ARN format patterns from the resource types
        that an action can operate on. Useful for validating Resource elements
        in IAM policies.

        Args:
            action: Full action name (e.g., "s3:GetObject", "iam:CreateUser")
            service_detail: Service definition containing action and resource details

        Returns:
            List of ARN format strings, or empty list if action not found or has no resources

        Example:
            >>> validator = ServiceValidator()
            >>> service = await fetcher.fetch_service_by_name("s3")
            >>> arns = validator.get_arn_formats_for_action("s3:GetObject", service)
            >>> # Returns: ["arn:${Partition}:s3:::${BucketName}/${ObjectName}"]
        """
        try:
            _, action_name = self._parser.parse_action(action)

            # Find the action
            action_detail = service_detail.actions.get(action_name)
            if not action_detail or not action_detail.resources:
                return []

            # Extract ARN formats from resource types
            arn_formats = []
            for resource_ref in action_detail.resources:
                # resource_ref is a dict with "Name" key pointing to resource type name
                resource_name = resource_ref.get("Name", "")
                if not resource_name:
                    continue

                # Look up the resource type in service definition
                resource_type = service_detail.resources.get(resource_name)
                if resource_type and resource_type.arn_formats:
                    arn_formats.extend(resource_type.arn_formats)

            return arn_formats

        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"Error getting ARN formats for action {action}: {e}")
            return []

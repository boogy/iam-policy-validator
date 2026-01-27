"""Wildcard resource check - detects Resource: '*' in IAM policies.

This check detects statements with Resource: '*' that could grant overly broad access.
It intelligently adjusts severity based on conditions that restrict resource scope:

- Global resource-scoping conditions (aws:ResourceAccount, aws:ResourceOrgID, aws:ResourceOrgPaths)
  always lower severity since they apply to all services.
- Resource tag conditions (aws:ResourceTag/*) lower severity only if ALL actions in the
  statement support the condition (validated against AWS service definitions).
"""

import asyncio
import logging
from typing import ClassVar

from iam_validator.checks.utils.action_parser import get_action_case_insensitive, parse_action
from iam_validator.checks.utils.wildcard_expansion import expand_wildcard_actions
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.config.aws_global_conditions import GLOBAL_RESOURCE_SCOPING_CONDITION_KEYS
from iam_validator.core.models import ActionDetail, ServiceDetail, Statement, ValidationIssue
from iam_validator.sdk.policy_utils import extract_condition_keys_from_statement

logger = logging.getLogger(__name__)

# Module-level cache for action resource support lookups.
# Maps action name (e.g., "s3:GetObject") to whether it supports resource-level permissions.
# True = supports resources (should be flagged for wildcard)
# False = doesn't support resources (wildcard is appropriate)
# None = unknown (be conservative, assume it supports resources)
_action_resource_support_cache: dict[str, bool | None] = {}

# Module-level cache for action access level lookups.
# Maps action name (e.g., "s3:ListBuckets") to its access level.
# "list" = list-level action (safe with wildcards)
# Other values or None = unknown
_action_access_level_cache: dict[str, str | None] = {}


def _get_access_level(action_detail: ActionDetail) -> str:
    """Derive access level from action annotations.

    AWS API provides Properties dict with boolean flags instead of AccessLevel string.
    We derive the access level from these flags.

    Args:
        action_detail: Action detail object with annotations

    Returns:
        Access level string: "permissions-management", "tagging", "write", "list", or "read"
    """
    if not action_detail.annotations:
        return "unknown"

    props = action_detail.annotations.get("Properties", {})
    if not props:
        return "unknown"

    # Check flags in priority order
    if props.get("IsPermissionManagement"):
        return "permissions-management"
    if props.get("IsTaggingOnly"):
        return "tagging"
    if props.get("IsWrite"):
        return "write"
    if props.get("IsList"):
        return "list"

    # Default to read if none of the above
    return "read"


def clear_resource_support_cache() -> None:
    """Clear the action resource support and access level caches.

    This is primarily useful for testing to ensure a clean state between tests.
    In production, the cache persists for the lifetime of the process, which is
    beneficial as AWS action definitions don't change frequently.
    """
    _action_resource_support_cache.clear()
    _action_access_level_cache.clear()


def _has_global_resource_scoping(condition_keys: set[str]) -> bool:
    """Check if any global resource-scoping conditions are present.

    Args:
        condition_keys: Set of condition keys from the statement

    Returns:
        True if any global resource-scoping condition is present
    """
    return bool(condition_keys & GLOBAL_RESOURCE_SCOPING_CONDITION_KEYS)


async def _validate_condition_key_support(
    actions: list[str],
    condition_key: str,
    fetcher: AWSServiceFetcher,
) -> tuple[bool, list[str]]:
    """Validate if all actions support a specific condition key.

    This is a generic function that works for any condition key,
    including aws:ResourceTag/*, service-specific tags, etc.

    Uses parallel execution for performance when validating multiple actions.

    Args:
        actions: List of actions to validate
        condition_key: The condition key to check support for
        fetcher: AWS service fetcher for looking up service definitions

    Returns:
        Tuple of (all_support, unsupported_actions) where all_support is True
        if all actions support the condition key
    """
    # Validate all actions in parallel for performance using centralized fetcher method
    results = await asyncio.gather(
        *[fetcher.is_condition_key_supported(action, condition_key) for action in actions],
        return_exceptions=True,
    )

    unsupported = []
    for action, result in zip(actions, results):
        # Treat exceptions as unsupported (conservative)
        if isinstance(result, BaseException) or not result:
            unsupported.append(action)

    return (len(unsupported) == 0, unsupported)


class WildcardResourceCheck(PolicyCheck):
    """Checks for wildcard resources (Resource: '*') which grant access to all resources."""

    check_id: ClassVar[str] = "wildcard_resource"
    description: ClassVar[str] = "Checks for wildcard resources (*)"
    default_severity: ClassVar[str] = "medium"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute wildcard resource check on a statement."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        actions = statement.get_actions()
        resources = statement.get_resources()

        # Check for wildcard resource (Resource: "*")
        if "*" in resources:
            # First, filter out actions that don't support resource-level permissions
            # These actions legitimately require Resource: "*"
            actions_requiring_specific_resources = await self._filter_actions_requiring_resources(
                actions, fetcher
            )

            # If all actions don't support resources, wildcard is appropriate - no issue
            if not actions_requiring_specific_resources:
                return issues

            # Use filtered actions for the rest of the check
            actions = actions_requiring_specific_resources
            # Check if all actions are in the allowed_wildcards list
            # allowed_wildcards works by expanding wildcard patterns (like "ec2:Describe*")
            # to all matching AWS actions using the AWS API, then checking if the policy's
            # actions are in that expanded list. This ensures only validated AWS actions
            # are allowed with Resource: "*".
            allowed_wildcards_config = config.config.get("allowed_wildcards", [])
            allowed_wildcards_expanded = await self._get_expanded_allowed_wildcards(config, fetcher)

            # Check if ALL actions (excluding full wildcard "*") are in the expanded list
            non_wildcard_actions = [a for a in actions if a != "*"]

            if (allowed_wildcards_config or allowed_wildcards_expanded) and non_wildcard_actions:
                # Strategy 1: Check literal pattern match (fast path)
                # If policy action matches config pattern literally, allow it
                # Example: Policy has "iam:Get*", config has "iam:Get*" -> match
                all_actions_allowed_literal = all(
                    action in allowed_wildcards_config for action in non_wildcard_actions
                )

                if all_actions_allowed_literal:
                    # All actions match literally, Resource: "*" is acceptable
                    return issues

                # Strategy 2: Check expanded pattern match (comprehensive path)
                # Expand both policy actions and config patterns, then compare
                # Example: Policy has "iam:Get*" -> ["iam:GetUser", ...],
                #          config has "iam:Get*" -> ["iam:GetUser", ...] -> all match
                if allowed_wildcards_expanded:
                    expanded_statement_actions = await expand_wildcard_actions(
                        non_wildcard_actions, fetcher
                    )

                    # Check if all expanded actions are in the expanded allowed list (exact match)
                    all_actions_allowed_expanded = all(
                        action in allowed_wildcards_expanded
                        for action in expanded_statement_actions
                    )

                    # If all actions are in the expanded list, skip the wildcard resource warning
                    if all_actions_allowed_expanded:
                        # All actions are safe, Resource: "*" is acceptable
                        return issues

            # Flag the issue if actions are not all allowed or no allowed_wildcards configured
            # First, determine if severity should be adjusted based on conditions
            base_severity = self.get_severity(config)
            adjusted_severity, adjustment_reason = await self._determine_severity_adjustment(
                statement,
                actions_requiring_specific_resources,
                fetcher,
                base_severity,
            )

            # Build a helpful message showing which actions require specific resources
            custom_message = config.config.get("message")
            if custom_message:
                message = custom_message
            else:
                # Build default message with action list
                # Note: actions_requiring_specific_resources is guaranteed non-empty here
                # because we return early above if it's empty
                sorted_actions = sorted(actions_requiring_specific_resources)
                if len(sorted_actions) <= 5:
                    action_list = ", ".join(f"`{a}`" for a in sorted_actions)
                else:
                    action_list = ", ".join(f"`{a}`" for a in sorted_actions[:5])
                    action_list += f" (+{len(sorted_actions) - 5} more)"
                message = f'Statement applies to all resources (`"*"`) with actions that typically require specific resources: {action_list}'

                # Add adjustment reason if present
                if adjustment_reason:
                    message += f". {adjustment_reason}"

            suggestion = config.config.get(
                "suggestion", "Replace wildcard with specific resource ARNs"
            )
            example = config.config.get("example", "")

            issues.append(
                ValidationIssue(
                    severity=adjusted_severity,
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="overly_permissive",
                    message=message,
                    suggestion=suggestion,
                    example=example if example else None,
                    line_number=statement.line_number,
                    field_name="resource",
                )
            )

        return issues

    async def _get_expanded_allowed_wildcards(
        self, config: CheckConfig, fetcher: AWSServiceFetcher
    ) -> frozenset[str]:
        """Get and expand allowed_wildcards configuration.

        This method retrieves wildcard patterns from the allowed_wildcards config
        and expands them using the AWS API to get all matching actual AWS actions.

        How it works:
        1. Retrieves patterns from config (e.g., ["ec2:Describe*", "s3:List*"])
        2. Expands each pattern using AWS API:
           - "ec2:Describe*" → ["ec2:DescribeInstances", "ec2:DescribeImages", ...]
           - "s3:List*" → ["s3:ListBucket", "s3:ListObjects", ...]
        3. Returns a set of all expanded actions

        This allows you to:
        - Specify patterns like "ec2:Describe*" in config
        - Have the validator allow specific actions like "ec2:DescribeInstances" with Resource: "*"
        - Ensure only real AWS actions (validated via API) are allowed

        Example:
            Config: allowed_wildcards: ["ec2:Describe*"]
            Expands to: ["ec2:DescribeInstances", "ec2:DescribeImages", ...]
            Policy: "Action": ["ec2:DescribeInstances"], "Resource": "*"
            Result: ✅ Allowed (ec2:DescribeInstances is in expanded list)

        Args:
            config: The check configuration
            fetcher: AWS service fetcher for expanding wildcards via AWS API

        Returns:
            A frozenset of all expanded action names from the configured patterns
        """
        patterns_to_expand = config.config.get("allowed_wildcards", [])

        # If no patterns configured, return empty set
        if not patterns_to_expand or not isinstance(patterns_to_expand, list):
            return frozenset()

        # Expand the wildcard patterns using the AWS API
        # This converts patterns like "ec2:Describe*" to actual AWS actions
        expanded_actions = await expand_wildcard_actions(patterns_to_expand, fetcher)

        return frozenset(expanded_actions)

    async def _determine_severity_adjustment(
        self,
        statement: Statement,
        actions: list[str],
        fetcher: AWSServiceFetcher,
        base_severity: str,
    ) -> tuple[str, str | None]:
        """Determine if severity should be adjusted based on resource-scoping conditions.

        This method checks if the statement has conditions that meaningfully restrict
        resource scope:
        1. Global resource-scoping conditions (aws:ResourceAccount, etc.) always lower severity
        2. Resource tag conditions (aws:ResourceTag/*) lower severity only if ALL actions support them

        Args:
            statement: The policy statement being checked
            actions: List of actions that require specific resources
            fetcher: AWS service fetcher for validating condition key support
            base_severity: The default severity level

        Returns:
            Tuple of (adjusted_severity, reason) where reason explains the adjustment
        """
        condition_keys = extract_condition_keys_from_statement(statement)
        if not condition_keys:
            return (base_severity, None)

        # Check for global resource-scoping conditions (always valid for all services)
        if _has_global_resource_scoping(condition_keys):
            global_keys = condition_keys & GLOBAL_RESOURCE_SCOPING_CONDITION_KEYS
            return (
                "low",
                f"Severity lowered: resource scope restricted by `{', '.join(sorted(global_keys))}`",
            )

        # Check for aws:ResourceTag conditions (must validate per-action support)
        resource_tag_keys = {k for k in condition_keys if k.startswith("aws:ResourceTag/")}
        if resource_tag_keys:
            # Use the first tag key for validation (all should have same support pattern)
            tag_key = next(iter(resource_tag_keys))
            all_support, unsupported = await _validate_condition_key_support(
                actions, tag_key, fetcher
            )
            if all_support:
                return (
                    "low",
                    f"Severity lowered: resource scope restricted by `{', '.join(sorted(resource_tag_keys))}`",
                )
            else:
                # Tag condition present but not all actions support it
                unsupported_display = unsupported[:3]
                more = f" (+{len(unsupported) - 3} more)" if len(unsupported) > 3 else ""
                return (
                    base_severity,
                    f"Note: `aws:ResourceTag` condition found but these actions don't support "
                    f"resource tags: `{', '.join(unsupported_display)}`{more}",
                )

        # Has conditions but none that scope resources
        return (base_severity, None)

    async def _filter_actions_requiring_resources(
        self, actions: list[str], fetcher: AWSServiceFetcher
    ) -> list[str]:
        """Filter actions to only those that should be flagged for wildcard resources.

        This method filters out actions that legitimately use Resource: "*":
        1. Actions that don't support resource-level permissions (e.g., sts:GetCallerIdentity)
        2. List-level actions (e.g., s3:ListBuckets) - these only enumerate resources
           and are not dangerous with wildcards

        Examples of actions filtered out:
        - iam:ListUsers (list-level, must use Resource: "*")
        - sts:GetCallerIdentity (must use Resource: "*")
        - ec2:DescribeInstances (must use Resource: "*")
        - s3:ListAllMyBuckets (list-level)

        This method uses a module-level cache to avoid repeated lookups and
        fetches all required services in parallel for better performance.

        Args:
            actions: List of actions from the policy statement
            fetcher: AWS service fetcher for looking up action definitions

        Returns:
            List of actions that should be flagged for wildcard resource usage
        """
        actions_requiring_resources = []
        # Actions that need service lookup, grouped by service
        service_actions: dict[str, list[tuple[str, str]]] = {}  # service -> [(action, action_name)]

        for action in actions:
            # Full wildcard "*" - keep it (it's too broad to determine)
            if action == "*":
                actions_requiring_resources.append(action)
                continue

            # Parse action using the utility
            parsed = parse_action(action)
            if not parsed:
                # Malformed action - keep it (be conservative)
                actions_requiring_resources.append(action)
                continue

            # Wildcard in service or action name - keep it (can't determine resource support)
            if parsed.has_wildcard:
                actions_requiring_resources.append(action)
                continue

            service = parsed.service
            action_name = parsed.action_name

            # Check module-level caches first
            if action in _action_resource_support_cache and action in _action_access_level_cache:
                cached_resource_support = _action_resource_support_cache[action]
                cached_access_level = _action_access_level_cache[action]

                # Skip list-level actions - they're safe with wildcards
                if cached_access_level == "list":
                    continue

                if cached_resource_support is True or cached_resource_support is None:
                    # Supports resources or unknown - include it
                    actions_requiring_resources.append(action)
                # If False, action doesn't support resources - skip it
                continue

            # Group actions by service for parallel fetching
            if service not in service_actions:
                service_actions[service] = []
            service_actions[service].append((action, action_name))

        # If no services to look up, return early
        if not service_actions:
            return actions_requiring_resources

        # Fetch all services in parallel
        services = list(service_actions.keys())
        results = await asyncio.gather(
            *[fetcher.fetch_service_by_name(s) for s in services],
            return_exceptions=True,
        )

        # Build service cache from successful results
        service_cache: dict[str, ServiceDetail | None] = {}
        for service, result in zip(services, results):
            if isinstance(result, BaseException):
                logger.debug(f"Could not look up service {service}: {result}")
                # Mark service as failed - will keep all its actions (conservative)
                service_cache[service] = None
            else:
                # Result is ServiceDetail when not an exception
                service_cache[service] = result

        # Process actions using cached service data
        for service, action_list in service_actions.items():
            service_detail = service_cache.get(service)

            if not service_detail:
                # Unknown service - keep all its actions (be conservative)
                for action, _ in action_list:
                    _action_resource_support_cache[action] = None  # Cache as unknown
                    _action_access_level_cache[action] = None  # Cache as unknown
                    actions_requiring_resources.append(action)
                continue

            for action, action_name in action_list:
                # Use case-insensitive lookup since AWS actions are case-insensitive
                action_detail = get_action_case_insensitive(service_detail.actions, action_name)
                if not action_detail:
                    # Unknown action - keep it (be conservative)
                    _action_resource_support_cache[action] = None  # Cache as unknown
                    _action_access_level_cache[action] = None  # Cache as unknown
                    actions_requiring_resources.append(action)
                    continue

                # Get action's access level and cache it
                access_level = _get_access_level(action_detail)
                _action_access_level_cache[action] = access_level

                # Skip list-level actions - they only enumerate resources and are safe with wildcards
                if access_level == "list":
                    _action_resource_support_cache[action] = False  # Mark as not needing resources
                    continue

                # Check if action supports resource-level permissions
                # action_detail.resources is empty for actions that don't support resources
                supports_resources = bool(action_detail.resources)
                _action_resource_support_cache[action] = supports_resources  # Cache result

                if supports_resources:
                    # Action supports resources - should be flagged for wildcard
                    actions_requiring_resources.append(action)
                # Else: action doesn't support resources, Resource: "*" is appropriate

        return actions_requiring_resources

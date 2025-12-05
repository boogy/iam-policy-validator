"""Wildcard resource check - detects Resource: '*' in IAM policies."""

from typing import ClassVar

from iam_validator.checks.utils.wildcard_expansion import expand_wildcard_actions
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


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
            message = config.config.get(
                "message", 'Statement applies to all resources `"*"` (wildcard resource).'
            )
            suggestion = config.config.get(
                "suggestion", "Replace wildcard with specific resource ARNs"
            )
            example = config.config.get("example", "")

            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="overly_permissive",
                    message=message,
                    suggestion=suggestion,
                    example=example if example else None,
                    line_number=statement.line_number,
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

    async def _filter_actions_requiring_resources(
        self, actions: list[str], fetcher: AWSServiceFetcher
    ) -> list[str]:
        """Filter actions to only those that support resource-level permissions.

        Some AWS actions don't support resource-level permissions and legitimately
        require Resource: "*". This method filters out those actions so we only
        flag wildcards for actions that could be scoped to specific resources.

        Examples of actions that don't support resources:
        - iam:ListUsers (must use Resource: "*")
        - sts:GetCallerIdentity (must use Resource: "*")
        - ec2:DescribeInstances (must use Resource: "*")

        Args:
            actions: List of actions from the policy statement
            fetcher: AWS service fetcher for looking up action definitions

        Returns:
            List of actions that DO support resource-level permissions
        """
        actions_requiring_resources = []

        for action in actions:
            # Full wildcard "*" - keep it (it's too broad to determine)
            if action == "*":
                actions_requiring_resources.append(action)
                continue

            # Skip malformed actions
            if ":" not in action:
                actions_requiring_resources.append(action)
                continue

            # Parse service and action name
            try:
                service, action_name = action.split(":", 1)
            except ValueError:
                actions_requiring_resources.append(action)
                continue

            # Wildcard in service or action name - keep it (can't determine resource support)
            if "*" in service or "*" in action_name:
                actions_requiring_resources.append(action)
                continue

            # Look up the action in AWS service definitions
            try:
                service_detail = await fetcher.fetch_service_by_name(service)
            except (ValueError, Exception):  # pylint: disable=broad-exception-caught
                # Unknown service - keep it (be conservative)
                actions_requiring_resources.append(action)
                continue

            if not service_detail:
                # Unknown service - keep it (be conservative)
                actions_requiring_resources.append(action)
                continue

            action_detail = service_detail.actions.get(action_name)
            if not action_detail:
                # Unknown action - keep it (be conservative)
                actions_requiring_resources.append(action)
                continue

            # Check if action supports resource-level permissions
            # action_detail.resources is empty for actions that don't support resources
            if action_detail.resources:
                # Action supports resources - should be flagged for wildcard
                actions_requiring_resources.append(action)
            # Else: action doesn't support resources, Resource: "*" is appropriate

        return actions_requiring_resources

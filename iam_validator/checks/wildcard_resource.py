"""Wildcard resource check - detects Resource: '*' in IAM policies."""

from iam_validator.checks.utils.wildcard_expansion import expand_wildcard_actions
from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class WildcardResourceCheck(PolicyCheck):
    """Checks for wildcard resources (Resource: '*') which grant access to all resources."""

    @property
    def check_id(self) -> str:
        return "wildcard_resource"

    @property
    def description(self) -> str:
        return "Checks for wildcard resources (*)"

    @property
    def default_severity(self) -> str:
        return "medium"

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
            # Check if all actions are in the allowed_wildcards list
            # allowed_wildcards works by expanding wildcard patterns (like "ec2:Describe*")
            # to all matching AWS actions using the AWS API, then checking if the policy's
            # actions are in that expanded list. This ensures only validated AWS actions
            # are allowed with Resource: "*".
            allowed_wildcards_expanded = await self._get_expanded_allowed_wildcards(config, fetcher)

            # Check if ALL actions (excluding full wildcard "*") are in the expanded list
            non_wildcard_actions = [a for a in actions if a != "*"]

            if allowed_wildcards_expanded and non_wildcard_actions:
                # Check if all actions are in the expanded allowed list (exact match)
                all_actions_allowed = all(
                    action in allowed_wildcards_expanded for action in non_wildcard_actions
                )

                # If all actions are in the expanded list, skip the wildcard resource warning
                if all_actions_allowed:
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

"""Sensitive action check - detects sensitive actions without IAM conditions."""

from typing import TYPE_CHECKING, Any, ClassVar

from iam_validator.checks.utils.policy_level_checks import check_policy_level_actions
from iam_validator.checks.utils.sensitive_action_matcher import (
    DEFAULT_SENSITIVE_ACTIONS,
    check_sensitive_actions,
)
from iam_validator.checks.utils.wildcard_expansion import expand_wildcard_actions
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.config.sensitive_actions import get_category_for_action
from iam_validator.core.models import Statement, ValidationIssue

if TYPE_CHECKING:
    from iam_validator.core.models import IAMPolicy


def get_suggestion_from_requirement(requirement: dict[str, Any]) -> tuple[str, str] | None:
    """
    Extract suggestion and example from a condition requirement.

    This is a public utility function that can be used by custom checks
    to extract user-friendly suggestions from condition requirement structures.

    Args:
        requirement: Condition requirement dictionary containing:
            - suggestion_text: Human-readable guidance text
            - required_conditions: Conditions structure (list or dict with any_of/all_of/none_of)

    Returns:
        Tuple of (suggestion_text, example) if available, None otherwise

    Example:
        >>> from iam_validator.core.config.condition_requirements import IAM_PASS_ROLE_REQUIREMENT
        >>> suggestion, example = get_suggestion_from_requirement(IAM_PASS_ROLE_REQUIREMENT)
        >>> print(suggestion)
        This action allows passing IAM roles to AWS services...
    """
    # Check if requirement has suggestion_text
    if "suggestion_text" not in requirement:
        return None

    suggestion_text = requirement["suggestion_text"]

    # Extract example from required_conditions
    example = ""
    required_conditions = requirement.get("required_conditions", [])

    # Handle different condition structures (list, dict with any_of/all_of/none_of)
    if isinstance(required_conditions, list) and required_conditions:
        # Get first condition's example
        first_condition = required_conditions[0]
        example = first_condition.get("example", "")
    elif isinstance(required_conditions, dict):
        # Handle any_of, all_of, none_of structures
        for logic_key in ["any_of", "all_of", "none_of"]:
            if logic_key in required_conditions:
                conditions = required_conditions[logic_key]
                if isinstance(conditions, list) and conditions:
                    # Get first option's example
                    first_option = conditions[0]
                    if isinstance(first_option, dict):
                        if "example" in first_option:
                            example = first_option["example"]
                            break
                        # Handle nested all_of/any_of/none_of structures
                        for nested_key in ["all_of", "any_of", "none_of"]:
                            if nested_key in first_option and isinstance(
                                first_option[nested_key], list
                            ):
                                for nested in first_option[nested_key]:
                                    if "example" in nested:
                                        example = nested["example"]
                                        break
                                if example:
                                    break
                        if example:
                            break

    return (suggestion_text, example)


class SensitiveActionCheck(PolicyCheck):
    """Checks for sensitive actions without IAM conditions to limit their use."""

    check_id: ClassVar[str] = "sensitive_action"
    description: ClassVar[str] = "Checks for sensitive actions without conditions"
    default_severity: ClassVar[str] = "medium"

    def _get_severity_for_action(self, action: str, config: CheckConfig) -> str:
        """
        Get severity for a specific action, considering category-based overrides.

        Args:
            action: The AWS action to check
            config: Check configuration

        Returns:
            Severity level for the action (considers category overrides)
        """
        # Check if category severities are configured
        category_severities = config.config.get("category_severities", {})
        if not category_severities:
            return self.get_severity(config)

        # Get the category for this action
        category = get_category_for_action(action)
        if category and category in category_severities:
            return category_severities[category]

        # Fall back to default severity
        return self.get_severity(config)

    def _get_actions_covered_by_condition_enforcement(self, config: CheckConfig) -> set[str]:
        """
        Get set of actions that are covered by action_condition_enforcement requirements.

        This prevents duplicate warnings when an action is already validated by
        formal condition requirements.

        Args:
            config: Check configuration with root_config access

        Returns:
            Set of action strings that are covered by condition requirements
        """
        covered_actions: set[str] = set()

        # Access action_condition_enforcement config from root_config
        ace_config = config.root_config.get("action_condition_enforcement", {})
        requirements = ace_config.get("requirements", [])

        for requirement in requirements:
            # Get actions from requirement
            actions_config = requirement.get("actions", [])
            if isinstance(actions_config, list):
                covered_actions.update(actions_config)

        return covered_actions

    def _get_category_specific_suggestion(
        self, action: str, config: CheckConfig
    ) -> tuple[str, str]:
        """
        Get category-specific suggestion and example for an action using two-tier lookup.

        This method provides suggestions for the sensitive_action check, which flags
        actions that have NO conditions. It does NOT validate specific conditions
        (that's handled by the action_condition_enforcement check).

        Tier 1: Check action_overrides in category suggestions for important actions
        Tier 2: Fall back to category-level default suggestions

        Args:
            action: The AWS action to check
            config: Check configuration

        Returns:
            Tuple of (suggestion_text, example_text) tailored to the action's category
        """
        # TIER 1: Check action-specific overrides in category suggestions
        category = get_category_for_action(action)
        category_suggestions = config.config.get("category_suggestions", {})

        if category and category in category_suggestions:
            category_data = category_suggestions[category]

            # Check if there's an action-specific override
            action_overrides = category_data.get("action_overrides", {})
            if action in action_overrides:
                override = action_overrides[action]
                return (override["suggestion"], override["example"])

            # TIER 2: Fall back to category-level defaults
            return (category_data["suggestion"], category_data["example"])

        # Ultimate fallback: Generic ABAC guidance for uncategorized actions
        return (
            "Add IAM conditions to limit when this action can be used. Use ABAC for scalability:\n"
            "• Match principal tags to resource tags (`aws:PrincipalTag/<tag-name>` = `aws:ResourceTag/<tag-name>`)\n"
            "• Match organization principal tags to resource tags (`aws:PrincipalOrgID` = `aws:ResourceOrgID`)\n"
            "• Require MFA (`aws:MultiFactorAuthPresent` = `true`)\n"
            "• Restrict by IP (`aws:SourceIp`) or VPC (`aws:SourceVpc`)",
            '"Condition": {\n'
            '  "StringEquals": {\n'
            '    "aws:PrincipalTag/owner": "${aws:ResourceTag/owner}"\n'
            "  }\n"
            "}",
        )

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute sensitive action check on a statement."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        actions = statement.get_actions()
        has_conditions = statement.condition is not None and len(statement.condition) > 0

        # Expand wildcards to actual actions using AWS API
        expanded_actions = await expand_wildcard_actions(actions, fetcher)

        # Check if sensitive actions match using any_of/all_of logic
        is_sensitive, matched_actions = check_sensitive_actions(
            expanded_actions, config, DEFAULT_SENSITIVE_ACTIONS
        )

        if is_sensitive and not has_conditions:
            # Filter out actions already covered by action_condition_enforcement
            # This prevents duplicate warnings with different messages
            covered_actions = self._get_actions_covered_by_condition_enforcement(config)
            matched_actions = [
                action for action in matched_actions if action not in covered_actions
            ]

            # If all matched actions are covered elsewhere, skip this check
            if not matched_actions:
                return issues
            # Create appropriate message based on matched actions using configurable templates
            if len(matched_actions) == 1:
                message_template = config.config.get(
                    "message_single",
                    "Sensitive action `{action}` should have conditions to limit when it can be used",
                )
                message = message_template.format(action=matched_actions[0])
            else:
                action_list = "', '".join(matched_actions)
                message_template = config.config.get(
                    "message_multiple",
                    "Sensitive actions `{actions}` should have conditions to limit when they can be used",
                )
                message = message_template.format(actions=action_list)

            # Get category-specific suggestion and example (or use config defaults)
            # Use the first matched action to determine the category
            suggestion_text, example = self._get_category_specific_suggestion(
                matched_actions[0], config
            )

            # Determine severity based on the highest severity action in the list
            # If single action, use its category severity
            # If multiple actions, use the highest severity among them
            severity = self.get_severity(config)  # Default
            if matched_actions:
                # Get severity for first action (or highest if we want to be more sophisticated)
                severity = self._get_severity_for_action(matched_actions[0], config)

            issues.append(
                ValidationIssue(
                    severity=severity,
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="missing_condition",
                    message=message,
                    action=(matched_actions[0] if len(matched_actions) == 1 else None),
                    suggestion=suggestion_text,
                    example=example if example else None,
                    line_number=statement.line_number,
                    field_name="action",
                )
            )

        return issues

    def _apply_merge_strategy(
        self,
        merge_strategy: str,
        user_config: list[dict] | None,
        default_config: list[dict] | None,
    ) -> list[dict] | None:
        """
        Apply merge strategy to combine user and default sensitive action patterns.

        Args:
            merge_strategy: One of "per_action_override", "user_only", "append",
                          "replace_all", or "defaults_only"
            user_config: User-provided sensitive action patterns (or None)
            default_config: Default sensitive action patterns (or None)

        Returns:
            Merged list of patterns based on strategy, or None if no patterns
        """
        if merge_strategy == "user_only":
            # Use ONLY user patterns, completely ignore defaults
            return user_config

        elif merge_strategy == "defaults_only":
            # Use ONLY defaults, ignore user patterns
            return default_config

        elif merge_strategy == "append":
            # Combine both (defaults first, then user)
            result = []
            if default_config:
                result.extend(default_config)
            if user_config:
                result.extend(user_config)
            return result if result else None

        elif merge_strategy == "replace_all":
            # User replaces all if provided, otherwise use defaults
            return user_config if user_config else default_config

        else:  # "per_action_override" (default)
            # If user provides patterns, use them; otherwise use defaults
            # This is the legacy behavior
            return user_config if user_config else default_config

    async def execute_policy(
        self,
        policy: "IAMPolicy",
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        """
        Execute policy-level sensitive action checks.

        This method examines the entire policy to detect privilege escalation patterns
        and other security issues that span multiple statements.

        Args:
            policy: The complete IAM policy to check
            policy_file: Path to the policy file (for context/reporting)
            fetcher: AWS service fetcher for validation against AWS APIs
            config: Configuration for this check instance

        Returns:
            List of ValidationIssue objects found by this check
        """
        del policy_file, fetcher  # Not used in current implementation
        issues = []

        # Handle policies with no statements
        if not policy.statement:
            return []

        # Collect all actions from all Allow statements across the entire policy
        all_actions: set[str] = set()
        statement_map: dict[
            str, list[tuple[int, str | None]]
        ] = {}  # action -> [(stmt_idx, sid), ...]

        for idx, statement in enumerate(policy.statement):
            if statement.effect == "Allow":
                actions = statement.get_actions()
                # Filter out wildcards for privilege escalation detection
                filtered_actions = [a for a in actions if a != "*"]

                for action in filtered_actions:
                    all_actions.add(action)
                    if action not in statement_map:
                        statement_map[action] = []
                    statement_map[action].append((idx, statement.sid))

        # Get configuration for sensitive actions with merge_strategy support
        # merge_strategy options:
        # - "append": Add user patterns ON TOP OF defaults (both apply) - DEFAULT
        # - "user_only": Use ONLY user patterns, disable ALL default privilege escalation patterns
        # - "defaults_only": Ignore user patterns, use only defaults
        # - "replace_all": User patterns completely replace ALL defaults (if provided)
        # - "per_action_override": User patterns replace defaults for matching action combos
        merge_strategy = config.config.get("merge_strategy", "append")

        # Determine which sensitive_actions patterns to use based on merge_strategy
        # Note: The config.config already contains deep-merged values from defaults + user config
        # For lists like sensitive_actions, user config REPLACES defaults (not merges)
        # So if user provided sensitive_actions, it's already the only value in config.config
        sensitive_actions_config: list[dict] | None = None
        sensitive_patterns_config: list[dict] | None = None

        if merge_strategy == "user_only":
            # user_only: Disable ALL default patterns
            # If user set merge_strategy: "user_only", they want NO defaults
            # They must explicitly provide sensitive_actions if they want any checks
            # Since we can't distinguish user-provided from defaults after merge,
            # we assume user_only means "no patterns" unless user explicitly provided them
            # (which would have replaced defaults anyway)
            sensitive_actions_config = None
            sensitive_patterns_config = None

        elif merge_strategy == "defaults_only":
            # Use only defaults - but since config is merged, we use what's there
            # (user would need to NOT provide sensitive_actions to get defaults)
            sensitive_actions_config = config.config.get("sensitive_actions")
            sensitive_patterns_config = config.config.get("sensitive_action_patterns")

        else:
            # append, replace_all, per_action_override all use the merged config
            # The deep_merge already handled the merging:
            # - If user provided sensitive_actions, it replaced defaults
            # - If user didn't provide it, defaults are in config
            sensitive_actions_config = config.config.get("sensitive_actions")
            sensitive_patterns_config = config.config.get("sensitive_action_patterns")

        # Check for privilege escalation patterns using all_of logic
        # We need to check both exact actions and patterns
        policy_issues = []

        # Check sensitive_actions configuration
        if sensitive_actions_config:
            policy_issues.extend(
                check_policy_level_actions(
                    list(all_actions),
                    statement_map,
                    sensitive_actions_config,
                    config,
                    "actions",
                    self.get_severity,
                )
            )

        # Check sensitive_action_patterns configuration
        if sensitive_patterns_config:
            policy_issues.extend(
                check_policy_level_actions(
                    list(all_actions),
                    statement_map,
                    sensitive_patterns_config,
                    config,
                    "patterns",
                    self.get_severity,
                )
            )

        issues.extend(policy_issues)
        return issues

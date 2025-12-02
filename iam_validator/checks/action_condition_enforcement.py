"""Action-Specific Condition Enforcement Check.

Ensures specific actions have required IAM conditions (MFA, IP, tags, etc.).

Action Matching Modes:
- Simple list: actions: ["iam:PassRole"]
- any_of: Require conditions if ANY action matches
- all_of: Require conditions if ALL actions present (overly permissive detection)
- none_of: Flag forbidden actions

Merge Strategies (merge_strategy setting):
- append (default): User + defaults both apply
- user_only: Disable ALL defaults, use only user requirements
- per_action_override: User replaces defaults for matching actions
- replace_all: User replaces all if provided
- defaults_only: Ignore user, use only defaults

For full documentation, see: docs/condition-requirements.md
"""

import re
from typing import TYPE_CHECKING, Any, ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.ignore_patterns import IgnorePatternMatcher
from iam_validator.core.models import Statement, ValidationIssue
from iam_validator.utils.regex import compile_and_cache

if TYPE_CHECKING:
    from iam_validator.core.models import IAMPolicy


class ActionConditionEnforcementCheck(PolicyCheck):
    """Enforces specific condition requirements for specific actions with all_of/any_of support."""

    check_id: ClassVar[str] = "action_condition_enforcement"
    description: ClassVar[str] = (
        "Enforces conditions (MFA, IP, tags, etc.) for specific actions (supports all_of/any_of)"
    )
    default_severity: ClassVar[str] = "error"

    async def execute_policy(
        self,
        policy: "IAMPolicy",
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        """
        Execute policy-wide condition enforcement check.

        This method scans the entire policy once and enforces conditions based on action matching:
        - Simple list: Checks each statement for matching actions
        - all_of: Finds statements that contain ALL specified actions (overly permissive detection)
        - any_of: Finds statements that contain ANY of the specified actions
        - none_of: Flags statements that contain forbidden actions

        Example use cases:
        - any_of: "If ANY statement grants iam:CreateUser, iam:AttachUserPolicy,
          or iam:PutUserPolicy, then ALL such statements must have MFA condition."
        - all_of: "Flag statements that grant BOTH iam:CreateAccessKey AND
          iam:UpdateAccessKey (overly permissive)"

        Args:
            policy: The complete IAM policy to check
            policy_file: Path to the policy file (for context/reporting)
            fetcher: AWS service fetcher for validation against AWS APIs
            config: CheckConfig: Configuration for this check instance
            **kwargs: Additional context (policy_type, etc.)

        Returns:
            List of ValidationIssue objects found by this check
        """
        del kwargs  # Not used in current implementation
        issues = []

        # Get action condition requirements using configurable merge strategy
        requirements = self._get_merged_requirements(config, policy_file)

        if not requirements:
            return issues

        # Process each requirement
        for requirement in requirements:
            # Check if actions use all_of/any_of/none_of (policy-wide) or simple list (per-statement)
            actions_config = requirement.get("actions", [])
            uses_logical_operators = isinstance(actions_config, dict) and any(
                key in actions_config for key in ("all_of", "any_of", "none_of")
            )

            if uses_logical_operators:
                # Policy-wide detection (all_of/any_of/none_of)
                policy_issues = await self._check_policy_wide(policy, requirement, fetcher, config)
                # Filter by requirement-level ignore_patterns
                policy_issues = self._filter_requirement_issues(
                    policy_issues, requirement.get("ignore_patterns", []), policy_file
                )
                issues.extend(policy_issues)
            else:
                # Per-statement check (simple list)
                statement_issues = await self._check_per_statement(
                    policy, requirement, fetcher, config
                )
                # Filter by requirement-level ignore_patterns
                statement_issues = self._filter_requirement_issues(
                    statement_issues, requirement.get("ignore_patterns", []), policy_file
                )
                issues.extend(statement_issues)

        return issues

    def _get_merged_requirements(
        self,
        config: CheckConfig,
        policy_file: str,
    ) -> list[dict[str, Any]]:
        """
        Get merged requirements based on configured merge strategy.

        Supports multiple merge strategies to control how user requirements
        interact with default requirements:
        - "per_action_override": User requirements replace defaults for matching actions (default)
        - "append": User requirements added to defaults (both apply)
        - "replace_all": User requirements completely replace ALL defaults
        - "defaults_only": Ignore user requirements, use only defaults
        - "user_only": Ignore defaults, use only user requirements

        Args:
            config: Check configuration containing requirements and merge strategy
            policy_file: Path to the policy file being checked (for ignore_patterns)

        Returns:
            Merged list of requirements based on strategy
        """
        # Get default and user requirements
        default_requirements = config.config.get(
            "requirements",
            config.config.get("policy_level_requirements", []),
        )
        user_requirements = config.config.get("action_condition_requirements")

        # Get merge strategy (default: append - both defaults and user requirements apply)
        merge_strategy = config.config.get("merge_strategy", "append")

        # For user_only, replace_all, and per_action_override:
        # Filter user requirements by ignore_patterns BEFORE merging
        # For append and defaults_only: ignore_patterns on user requirements still apply
        if user_requirements:
            active_user_requirements = self._filter_requirements_by_filepath(
                user_requirements, policy_file
            )
        else:
            active_user_requirements = []

        # Apply merge strategy
        if merge_strategy == "user_only":
            # Use ONLY user requirements - no defaults at all
            # If a user requirement is filtered by ignore_patterns, it's simply not checked
            return active_user_requirements

        elif merge_strategy == "defaults_only":
            # Use ONLY defaults - ignore all user requirements
            return default_requirements

        elif merge_strategy == "replace_all":
            # User requirements completely replace ALL defaults (if user provided any)
            # If no user requirements provided, fall back to defaults
            if user_requirements:  # Check original, not filtered
                return active_user_requirements
            return default_requirements

        elif merge_strategy == "per_action_override":
            # User requirements replace defaults for MATCHING actions only
            # Non-matching defaults are kept
            # Note: We use the ORIGINAL user_requirements to determine which actions
            # are "user-defined" (even if filtered out by ignore_patterns)
            return self._merge_per_action_override(
                default_requirements, user_requirements or [], active_user_requirements
            )

        else:  # "append" (default)
            # Both defaults AND user requirements apply
            # User requirements are added on top of defaults
            return default_requirements + active_user_requirements

    def _filter_requirements_by_filepath(
        self,
        requirements: list[dict[str, Any]],
        policy_file: str,
    ) -> list[dict[str, Any]]:
        """
        Filter out requirements that should be ignored for this file.

        This handles ignore_patterns at the requirement level BEFORE merging,
        allowing defaults to apply when user requirements are ignored.

        Args:
            requirements: List of requirements to filter
            policy_file: Path to the policy file being checked

        Returns:
            Filtered list of requirements (excluding ignored ones)

        Example:
            User defines: iam:CreateRole with ignore_patterns: [".*test/.*"]
            When checking test/policy.json:
            - User requirement is filtered out
            - Default iam:CreateRole requirement can apply instead
        """
        active_reqs = []

        for req in requirements:
            ignore_patterns = req.get("ignore_patterns", [])

            if not ignore_patterns:
                # No ignore patterns - include this requirement
                active_reqs.append(req)
                continue

            # Check if any ignore pattern matches this file
            should_ignore = self._should_ignore_filepath(policy_file, ignore_patterns)

            if not should_ignore:
                active_reqs.append(req)

        return active_reqs

    def _should_ignore_filepath(
        self,
        filepath: str,
        ignore_patterns: list[dict[str, Any]],
    ) -> bool:
        """
        Check if filepath matches any of the ignore patterns.

        Only checks filepath-based patterns (filepath, filepath_regex).
        This is used for filtering requirements before merging.

        Args:
            filepath: Path to the policy file
            ignore_patterns: List of ignore pattern dictionaries

        Returns:
            True if filepath matches any pattern
        """
        for pattern in ignore_patterns:
            # Only check filepath-based patterns
            if "filepath" in pattern or "filepath_regex" in pattern:
                regex_pattern = pattern.get("filepath") or pattern.get("filepath_regex")
                if regex_pattern:
                    compiled = compile_and_cache(regex_pattern)
                    if compiled and compiled.search(filepath):
                        return True
        return False

    def _merge_per_action_override(
        self,
        default_requirements: list[dict[str, Any]],
        all_user_requirements: list[dict[str, Any]],
        active_user_requirements: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Merge user requirements with defaults on a per-action basis.

        User requirements override defaults for matching actions.
        Defaults are kept for actions not specified by user.

        Key behavior with ignore_patterns:
        - If user defines a requirement for action X with ignore_patterns
        - And the current file matches the ignore_patterns
        - Then: The user requirement is SKIPPED (not applied)
        - AND: The default for action X is ALSO skipped (user "owns" this action)
        - Result: No check for action X on this file

        Args:
            default_requirements: Default requirements from system config
            all_user_requirements: ALL user requirements (before ignore_patterns filtering)
            active_user_requirements: User requirements after ignore_patterns filtering

        Returns:
            Merged list of requirements
        """
        # Build a set of actions that user has customized (from ALL user requirements)
        # This determines which defaults to exclude
        user_actions = set()
        for req in all_user_requirements:
            actions = req.get("actions", [])
            # Handle both single action and list of actions
            if isinstance(actions, str):
                user_actions.add(actions)
            else:
                user_actions.update(actions)

        # Start with ACTIVE user requirements (filtered by ignore_patterns)
        merged = list(active_user_requirements)

        # Add defaults that don't conflict with user requirements
        for default_req in default_requirements:
            default_actions = default_req.get("actions", [])
            # Handle both single action and list of actions
            if isinstance(default_actions, str):
                default_actions = [default_actions]

            # Check if any of the default actions are customized by user
            has_overlap = any(action in user_actions for action in default_actions)

            if not has_overlap:
                # No overlap - keep this default requirement
                merged.append(default_req)

        return merged

    def _filter_requirement_issues(
        self,
        issues: list[ValidationIssue],
        ignore_patterns: list[dict[str, Any]],
        filepath: str,
    ) -> list[ValidationIssue]:
        """
        Filter issues based on requirement-level ignore patterns.

        This allows each requirement within action_condition_enforcement to have its own
        ignore patterns, enabling fine-grained control over which findings to suppress.

        Args:
            issues: List of validation issues to filter
            ignore_patterns: List of ignore pattern dictionaries for this requirement
            filepath: Path to the policy file being checked

        Returns:
            Filtered list of issues (issues matching ignore patterns are removed)

        Example:
            A requirement can ignore specific files while other requirements check them:
            - actions: ["iam:CreateRole"]
              required_conditions: [...]
              ignore_patterns:
                - filepath_regex: ".*modules/iam-openid.*"
        """
        if not ignore_patterns:
            return issues

        return [
            issue
            for issue in issues
            if not IgnorePatternMatcher.should_ignore_issue(issue, filepath, ignore_patterns)
        ]

    async def _check_policy_wide(
        self,
        policy: "IAMPolicy",
        requirement: dict[str, Any],
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """
        Check actions across the entire policy using all_of/any_of/none_of logic.

        This enables policy-wide detection patterns:
        - all_of: ALL required actions must exist somewhere in the policy
        - any_of: At least ONE required action must exist somewhere in the policy
        - none_of: NONE of the forbidden actions should exist in the policy
        """
        issues = []
        actions_config = requirement.get("actions", {})
        all_of = actions_config.get("all_of", [])
        any_of = actions_config.get("any_of", [])
        none_of = actions_config.get("none_of", [])

        # Collect all actions across the entire policy
        policy_wide_actions: set[str] = set()
        statements_by_action: dict[str, list[tuple[int, Statement]]] = {}

        for idx, statement in enumerate(policy.statement or []):
            if statement.effect != "Allow":
                continue

            statement_actions = statement.get_actions()
            policy_wide_actions.update(statement_actions)

            # Track which statements grant which actions
            for action in statement_actions:
                if action not in statements_by_action:
                    statements_by_action[action] = []
                statements_by_action[action].append((idx, statement))

        # Check all_of: ALL required actions must exist in policy
        if all_of:
            all_of_result = await self._check_all_of_policy_wide(
                all_of,
                policy_wide_actions,
                statements_by_action,
                requirement,
                fetcher,
                config,
            )
            issues.extend(all_of_result)

        # Check any_of: At least ONE required action must exist in policy
        if any_of:
            any_of_result = await self._check_any_of_policy_wide(
                any_of,
                policy_wide_actions,
                statements_by_action,
                requirement,
                fetcher,
                config,
            )
            issues.extend(any_of_result)

        # Check none_of: NONE of the forbidden actions should exist in policy
        if none_of:
            none_of_result = await self._check_none_of_policy_wide(
                none_of,
                policy_wide_actions,
                statements_by_action,
                requirement,
                config,
                fetcher,
            )
            issues.extend(none_of_result)

        return issues

    async def _check_all_of_policy_wide(
        self,
        all_of_actions: list[str],
        policy_wide_actions: set[str],
        statements_by_action: dict[str, list[tuple[int, Statement]]],
        requirement: dict[str, Any],
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """
        Check if ALL required actions exist anywhere in the policy.

        For all_of, we report ONLY statements that contain ALL the required actions,
        not statements that contain just some of them. This is useful for detecting
        overly permissive individual statements.
        """
        issues = []

        # First, check if ALL required actions exist somewhere in the policy
        found_actions_mapping: dict[str, str] = {}  # req_action -> matched_policy_action
        missing_actions: list[str] = []

        for req_action in all_of_actions:
            action_found = False
            for policy_action in policy_wide_actions:
                if await self._action_matches(
                    policy_action, req_action, requirement.get("action_patterns", []), fetcher
                ):
                    action_found = True
                    found_actions_mapping[req_action] = policy_action
                    break

            if not action_found:
                missing_actions.append(req_action)

        # If not all actions exist in the policy, no issue
        if missing_actions:
            return issues

        # ALL required actions exist in the policy
        # Now find statements that have ALL of them (not just some)
        statements_with_all_actions: list[tuple[int, Statement, list[str]]] = []

        # Check each statement to see if it contains ALL required actions
        for statement in statements_by_action.get(list(found_actions_mapping.values())[0], []):
            stmt_idx, stmt = statement
            stmt_actions = stmt.get_actions()

            # Check if this statement has ALL required actions
            has_all_actions = True
            matched_actions = []

            for req_action in all_of_actions:
                req_action_found = False
                for stmt_action in stmt_actions:
                    if await self._action_matches(
                        stmt_action, req_action, requirement.get("action_patterns", []), fetcher
                    ):
                        req_action_found = True
                        if stmt_action not in matched_actions:
                            matched_actions.append(stmt_action)
                        break

                if not req_action_found:
                    has_all_actions = False
                    break

            if has_all_actions:
                statements_with_all_actions.append((stmt_idx, stmt, matched_actions))

        # Also check other statements not in the first action's list
        checked_indices = {s[0] for s in statements_with_all_actions}
        for policy_action, stmt_list in statements_by_action.items():
            for stmt_idx, stmt in stmt_list:
                if stmt_idx in checked_indices:
                    continue

                stmt_actions = stmt.get_actions()

                # Check if this statement has ALL required actions
                has_all_actions = True
                matched_actions = []

                for req_action in all_of_actions:
                    req_action_found = False
                    for stmt_action in stmt_actions:
                        if await self._action_matches(
                            stmt_action, req_action, requirement.get("action_patterns", []), fetcher
                        ):
                            req_action_found = True
                            if stmt_action not in matched_actions:
                                matched_actions.append(stmt_action)
                            break

                    if not req_action_found:
                        has_all_actions = False
                        break

                if has_all_actions:
                    statements_with_all_actions.append((stmt_idx, stmt, matched_actions))
                    checked_indices.add(stmt_idx)

        # If no statements have ALL actions, no issue to report
        if not statements_with_all_actions:
            return issues

        # Report statements that have ALL the dangerous actions
        return self._generate_policy_wide_issues(
            statements_with_all_actions,
            list(found_actions_mapping.values()),
            requirement,
            config,
            "all_of",
        )

    async def _check_any_of_policy_wide(
        self,
        any_of_actions: list[str],
        policy_wide_actions: set[str],
        statements_by_action: dict[str, list[tuple[int, Statement]]],
        requirement: dict[str, Any],
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Check if at least ONE required action exists anywhere in the policy."""
        issues = []
        found_actions: list[str] = []
        statements_with_required_actions: list[tuple[int, Statement, list[str]]] = []

        for req_action in any_of_actions:
            for policy_action in policy_wide_actions:
                if await self._action_matches(
                    policy_action, req_action, requirement.get("action_patterns", []), fetcher
                ):
                    found_actions.append(policy_action)

                    # Track statements that have this action
                    if policy_action in statements_by_action:
                        for stmt_idx, stmt in statements_by_action[policy_action]:
                            existing = next(
                                (s for s in statements_with_required_actions if s[0] == stmt_idx),
                                None,
                            )
                            if existing:
                                if policy_action not in existing[2]:
                                    existing[2].append(policy_action)
                            else:
                                statements_with_required_actions.append(
                                    (stmt_idx, stmt, [policy_action])
                                )

        # If no actions found, no issue
        if not found_actions:
            return issues

        # At least one action found - validate conditions
        return self._generate_policy_wide_issues(
            statements_with_required_actions,
            found_actions,
            requirement,
            config,
            "any_of",
        )

    async def _check_none_of_policy_wide(
        self,
        none_of_actions: list[str],
        policy_wide_actions: set[str],
        statements_by_action: dict[str, list[tuple[int, Statement]]],
        requirement: dict[str, Any],
        config: CheckConfig,
        fetcher: AWSServiceFetcher,
    ) -> list[ValidationIssue]:
        """Check if any forbidden actions exist in the policy."""
        issues = []
        forbidden_found: list[str] = []
        statements_with_forbidden: list[tuple[int, Statement, list[str]]] = []

        for forbidden_action in none_of_actions:
            for policy_action in policy_wide_actions:
                if await self._action_matches(
                    policy_action, forbidden_action, requirement.get("action_patterns", []), fetcher
                ):
                    forbidden_found.append(policy_action)

                    # Track statements with forbidden actions
                    if policy_action in statements_by_action:
                        for stmt_idx, stmt in statements_by_action[policy_action]:
                            existing = next(
                                (s for s in statements_with_forbidden if s[0] == stmt_idx), None
                            )
                            if existing:
                                if policy_action not in existing[2]:
                                    existing[2].append(policy_action)
                            else:
                                statements_with_forbidden.append((stmt_idx, stmt, [policy_action]))

        # If forbidden actions found, create issues
        if not forbidden_found:
            return issues

        description = requirement.get("description", "These actions should not be used")
        severity = requirement.get("severity", self.get_severity(config))

        for stmt_idx, stmt, actions in statements_with_forbidden:
            actions_formatted = ", ".join(f"`{a}`" for a in actions)
            statement_refs = [
                f"Statement #{idx + 1}{' (SID: ' + s.sid + ')' if s.sid else ''}"
                for idx, s, _ in statements_with_forbidden
            ]

            issues.append(
                ValidationIssue(
                    severity=severity,
                    statement_sid=stmt.sid,
                    statement_index=stmt_idx,
                    issue_type="forbidden_action",
                    message=f"Forbidden actions {actions_formatted} found. {description}",
                    action=", ".join(actions),
                    suggestion=f"Remove these forbidden actions. Found in: {', '.join(statement_refs)}. {description}",
                    line_number=stmt.line_number,
                    field_name="action",
                )
            )

        return issues

    def _generate_policy_wide_issues(
        self,
        statements_with_actions: list[tuple[int, Statement, list[str]]],
        found_actions: list[str],
        requirement: dict[str, Any],
        config: CheckConfig,
        operator_type: str,
    ) -> list[ValidationIssue]:
        """Generate validation issues for policy-wide checks."""
        issues = []
        required_conditions_config = requirement.get("required_conditions", [])
        description = requirement.get("description", "")
        severity = requirement.get("severity", self.get_severity(config))

        if not required_conditions_config:
            # No conditions specified, just report that actions were found
            all_actions_formatted = ", ".join(f"`{a}`" for a in sorted(set(found_actions)))
            statement_refs = [
                f"Statement #{idx + 1}{' (SID: ' + stmt.sid + ')' if stmt.sid else ''}"
                for idx, stmt, _ in statements_with_actions
            ]

            first_idx, first_stmt, _ = statements_with_actions[0]
            issues.append(
                ValidationIssue(
                    severity=severity,
                    statement_sid=first_stmt.sid,
                    statement_index=first_idx,
                    issue_type="action_detected",
                    message=f"Actions {all_actions_formatted} found across {len(statements_with_actions)} statement(s) ({operator_type}). {description}",
                    action=", ".join(sorted(set(found_actions))),
                    suggestion=f"Review these statements: {', '.join(statement_refs)}. {description}",
                    line_number=first_stmt.line_number,
                    field_name="action",
                )
            )
            return issues

        # Validate conditions for each statement
        for idx, statement, matching_actions in statements_with_actions:
            condition_issues = self._validate_conditions(
                statement,
                idx,
                required_conditions_config,
                matching_actions,
                config,
                requirement,
            )

            # Add context
            for issue in condition_issues:
                issue.suggestion = (
                    f"{issue.suggestion}\n\n"
                    f"Note: Found {len(statements_with_actions)} statement(s) with these actions in the policy ({operator_type})."
                )

            issues.extend(condition_issues)

        return issues

    async def _check_per_statement(
        self,
        policy: "IAMPolicy",
        requirement: dict[str, Any],
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """
        Check each statement individually for matching actions (simple list format).

        Used when actions are specified as a simple list (not using all_of/any_of/none_of).
        """
        issues = []
        matching_statements: list[tuple[int, Statement, list[str]]] = []

        for idx, statement in enumerate(policy.statement or []):
            # Only check Allow statements
            if statement.effect != "Allow":
                continue

            statement_actions = statement.get_actions()

            # Check if this statement matches the action requirement
            actions_match, matching_actions = await self._check_action_match(
                statement_actions, requirement, fetcher
            )

            if actions_match and matching_actions:
                matching_statements.append((idx, statement, matching_actions))

        # If no statements match, skip this requirement
        if not matching_statements:
            return issues

        # Now validate that ALL matching statements have the required conditions
        required_conditions_config = requirement.get("required_conditions", [])
        if not required_conditions_config:
            # No conditions specified, just report that actions were found
            description = requirement.get("description", "")
            severity = requirement.get("severity", self.get_severity(config))

            # Create a summary issue for all matching statements
            all_actions = set()
            statement_refs = []
            for idx, stmt, actions in matching_statements:
                all_actions.update(actions)
                sid_info = f" (SID: {stmt.sid})" if stmt.sid else ""
                statement_refs.append(f"Statement #{idx + 1}{sid_info}")

            # Use the first matching statement's index for the issue
            first_idx, first_stmt, _ = matching_statements[0]
            all_actions_formatted = ", ".join(f"`{a}`" for a in sorted(all_actions))

            issues.append(
                ValidationIssue(
                    severity=severity,
                    statement_sid=first_stmt.sid,
                    statement_index=first_idx,
                    issue_type="action_detected",
                    message=f"Actions {all_actions_formatted} found in {len(matching_statements)} statement(s). {description}",
                    action=", ".join(sorted(all_actions)),
                    suggestion=f"Review these statements: {', '.join(statement_refs)}. {description}",
                    line_number=first_stmt.line_number,
                    field_name="action",
                )
            )
            return issues

        # Validate conditions for each matching statement
        for idx, statement, matching_actions in matching_statements:
            condition_issues = self._validate_conditions(
                statement,
                idx,
                required_conditions_config,
                matching_actions,
                config,
                requirement,
            )

            # Add context to each issue
            for issue in condition_issues:
                issue.suggestion = (
                    f"{issue.suggestion}\n\n"
                    f"Note: Found {len(matching_statements)} statement(s) with these actions in the policy."
                )

            issues.extend(condition_issues)

        return issues

    async def _check_action_match(
        self,
        statement_actions: list[str],
        requirement: dict[str, Any],
        fetcher: AWSServiceFetcher,
    ) -> tuple[bool, list[str]]:
        """
        Check if statement actions match the requirement.
        Supports: simple list, all_of, any_of, none_of, and action_patterns.

        Returns:
            (matches, list_of_matching_actions)
        """
        actions_config = requirement.get("actions", [])
        action_patterns = requirement.get("action_patterns", [])

        matching_actions: list[str] = []

        # Handle simple list format (backward compatibility)
        # Also handle requirements with only action_patterns (when actions is empty list)
        if isinstance(actions_config, list) and (actions_config or action_patterns):
            # Simple list - check if any action matches
            for stmt_action in statement_actions:
                if stmt_action == "*":
                    continue

                # Check if this statement action matches any of the required actions or patterns
                # Use _action_matches which handles wildcards in both statement and config
                matched = False

                # Check against configured actions
                for required_action in actions_config:
                    if await self._action_matches(
                        stmt_action, required_action, action_patterns, fetcher
                    ):
                        matched = True
                        break

                # If not matched by actions, check against action_patterns directly
                if not matched and action_patterns:
                    # Check if statement action matches any of the patterns
                    matched = await self._action_matches(stmt_action, "", action_patterns, fetcher)

                if matched and stmt_action not in matching_actions:
                    matching_actions.append(stmt_action)

            return len(matching_actions) > 0, matching_actions

        # Handle all_of/any_of/none_of format
        if isinstance(actions_config, dict):
            all_of = actions_config.get("all_of", [])
            any_of = actions_config.get("any_of", [])
            none_of = actions_config.get("none_of", [])

            # Check all_of: ALL specified actions must be in statement
            if all_of:
                all_present = True
                for req_action in all_of:
                    found = False
                    for stmt_action in statement_actions:
                        if await self._action_matches(
                            stmt_action, req_action, action_patterns, fetcher
                        ):
                            found = True
                            break
                    if not found:
                        all_present = False
                        break

                if not all_present:
                    return False, []

                # Collect matching actions
                for stmt_action in statement_actions:
                    for req_action in all_of:
                        if await self._action_matches(
                            stmt_action, req_action, action_patterns, fetcher
                        ):
                            if stmt_action not in matching_actions:
                                matching_actions.append(stmt_action)

            # Check any_of: At least ONE specified action must be in statement
            if any_of:
                any_present = False
                for stmt_action in statement_actions:
                    for req_action in any_of:
                        if await self._action_matches(
                            stmt_action, req_action, action_patterns, fetcher
                        ):
                            any_present = True
                            if stmt_action not in matching_actions:
                                matching_actions.append(stmt_action)

                if not any_present:
                    return False, []

            # Check none_of: NONE of the specified actions should be in statement
            if none_of:
                forbidden_actions = []
                for stmt_action in statement_actions:
                    for forbidden_action in none_of:
                        if await self._action_matches(
                            stmt_action, forbidden_action, action_patterns, fetcher
                        ):
                            forbidden_actions.append(stmt_action)

                # If forbidden actions are found, this is a match for flagging
                if forbidden_actions:
                    return True, forbidden_actions

            return len(matching_actions) > 0, matching_actions

        return False, []

    async def _action_matches(
        self,
        statement_action: str,
        required_action: str,
        patterns: list[str],
        fetcher: AWSServiceFetcher,
    ) -> bool:
        """
        Check if a statement action matches a required action or pattern.
        Supports:
        - Exact matches: "s3:GetObject"
        - AWS wildcards in both statement and required actions: "s3:*", "s3:Get*", "iam:Creat*"
        - Regex patterns: "^s3:Get.*", "^iam:Delete.*"

        This method handles bidirectional wildcard matching using real AWS actions from the fetcher:
        - statement_action="iam:Create*" matches required_action="iam:CreateUser"
        - statement_action="iam:C*" matches pattern="^iam:Create" (by checking actual AWS actions)
        """
        if statement_action == "*":
            return False

        # Exact match
        if statement_action == required_action:
            return True

        # AWS wildcard match in required_action (e.g., "s3:*", "s3:Get*")
        if "*" in required_action:
            # Convert AWS wildcard to regex and cache compilation
            wildcard_pattern = required_action.replace("*", ".*").replace("?", ".")
            try:
                compiled_pattern = compile_and_cache(f"^{wildcard_pattern}$")
                if compiled_pattern.match(statement_action):
                    return True
            except re.error:
                # Invalid regex pattern - skip this match attempt
                pass

        # AWS wildcard match in statement_action (e.g., "iam:Creat*" in policy)
        # Check if this wildcard would grant access to actions matching our patterns
        if "*" in statement_action:
            # Convert statement wildcard to regex pattern
            stmt_wildcard_pattern = statement_action.replace("*", ".*").replace("?", ".")

            # Check if statement wildcard overlaps with required action
            if "*" not in required_action:
                # Required action is specific (e.g., "iam:CreateUser")
                # Check if statement wildcard would grant it
                try:
                    compiled_pattern = compile_and_cache(f"^{stmt_wildcard_pattern}$")
                    if compiled_pattern.match(required_action):
                        return True
                except re.error:
                    # Invalid regex pattern - skip this match attempt
                    pass

            # Check if statement wildcard overlaps with any of our action patterns
            # Strategy: Use real AWS actions from the fetcher instead of hardcoded guesses
            # For example: "iam:C*" should match pattern "^iam:Create" because:
            # - "iam:C*" grants iam:CreateUser, iam:CreateRole, etc. (from AWS)
            # - "^iam:Create" pattern is meant to catch iam:CreateUser, iam:CreateRole, etc.
            # - Therefore they overlap
            if patterns:
                try:
                    # Parse the service from the wildcard action
                    service_prefix, _ = fetcher.parse_action(statement_action)

                    # Fetch the real list of actions for this service
                    service_detail = await fetcher.fetch_service_by_name(service_prefix)
                    available_actions = list(service_detail.actions.keys())

                    # Find which actual AWS actions the wildcard would grant
                    _, granted_actions = fetcher.match_wildcard_action(
                        statement_action.split(":", 1)[1],  # Just the action part (e.g., "C*")
                        available_actions,
                    )

                    # Check if any of the granted actions match our patterns
                    for granted_action in granted_actions:
                        full_granted_action = f"{service_prefix}:{granted_action}"
                        for pattern in patterns:
                            try:
                                compiled_pattern = compile_and_cache(pattern)
                                if compiled_pattern.match(full_granted_action):
                                    return True
                            except re.error:
                                continue

                except (ValueError, Exception):  # pylint: disable=broad-exception-caught
                    # If we can't fetch the service or parse the action, fall back to prefix matching
                    stmt_prefix = statement_action.rstrip("*")
                    for pattern in patterns:
                        try:
                            compiled_pattern = compile_and_cache(pattern)
                            if compiled_pattern.match(stmt_prefix):
                                return True
                        except re.error:
                            continue

        # Regex pattern match (from action_patterns config)
        for pattern in patterns:
            try:
                compiled_pattern = compile_and_cache(pattern)
                if compiled_pattern.match(statement_action):
                    return True
            except re.error:
                continue

        return False

    def _validate_conditions(
        self,
        statement: Statement,
        statement_idx: int,
        required_conditions_config: Any,
        matching_actions: list[str],
        config: CheckConfig,
        requirement: dict[str, Any] | None = None,
    ) -> list[ValidationIssue]:
        """
        Validate that required conditions are present.
        Supports: simple list, all_of, any_of formats.
        Can use per-requirement severity override from requirement['severity'].
        """
        issues: list[ValidationIssue] = []

        # Handle simple list format (backward compatibility)
        if isinstance(required_conditions_config, list):
            for condition_requirement in required_conditions_config:
                if not self._has_condition_requirement(statement, condition_requirement):
                    issues.append(
                        self._create_issue(
                            statement,
                            statement_idx,
                            condition_requirement,
                            matching_actions,
                            config,
                            requirement=requirement,
                        )
                    )
            return issues

        # Handle all_of/any_of/none_of format
        if isinstance(required_conditions_config, dict):
            all_of = required_conditions_config.get("all_of", [])
            any_of = required_conditions_config.get("any_of", [])
            none_of = required_conditions_config.get("none_of", [])

            # Validate all_of: ALL conditions must be present
            if all_of:
                for condition_requirement in all_of:
                    if not self._has_condition_requirement(statement, condition_requirement):
                        issues.append(
                            self._create_issue(
                                statement,
                                statement_idx,
                                condition_requirement,
                                matching_actions,
                                config,
                                requirement_type="all_of",
                                requirement=requirement,
                            )
                        )

            # Validate any_of: At least ONE condition must be present
            if any_of:
                any_present = any(
                    self._has_condition_requirement(statement, cond_req) for cond_req in any_of
                )

                if not any_present:
                    # Check if requirement has custom message/suggestion/example
                    custom_message = requirement.get("message") if requirement else None
                    custom_suggestion = requirement.get("suggestion") if requirement else None
                    custom_example = requirement.get("example") if requirement else None

                    if custom_message:
                        # Use fully custom message/suggestion/example from requirement
                        message = custom_message
                        suggestion = custom_suggestion or ""
                        example = custom_example or ""
                    else:
                        # Generate default message and build suggestion from conditions
                        condition_keys = []
                        for cond in any_of:
                            if "all_of" in cond:
                                # Nested all_of - collect all condition keys
                                nested_keys = [
                                    c.get("condition_key", "unknown") for c in cond["all_of"]
                                ]
                                condition_keys.append(
                                    f"({' + '.join(f'`{k}`' for k in nested_keys)})"
                                )
                            else:
                                # Simple condition
                                condition_keys.append(f"`{cond.get('condition_key', 'unknown')}`")
                        condition_keys_formatted = " OR ".join(condition_keys)
                        matching_actions_formatted = ", ".join(f"`{a}`" for a in matching_actions)

                        message = (
                            f"Actions {matching_actions_formatted} require at least ONE of these conditions: "
                            f"{condition_keys_formatted}"
                        )

                        # Build suggestion and examples from conditions
                        suggestion, example = self._build_any_of_suggestion(any_of)

                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            statement_sid=statement.sid,
                            statement_index=statement_idx,
                            issue_type="missing_required_condition_any_of",
                            message=message,
                            action=", ".join(matching_actions),
                            suggestion=suggestion,
                            example=example if example else None,
                            line_number=statement.line_number,
                            field_name="condition",
                        )
                    )

            # Validate none_of: NONE of these conditions should be present
            if none_of:
                for condition_requirement in none_of:
                    if self._has_condition_requirement(statement, condition_requirement):
                        issues.append(
                            self._create_none_of_issue(
                                statement,
                                statement_idx,
                                condition_requirement,
                                matching_actions,
                                config,
                            )
                        )

        return issues

    def _has_condition_requirement(
        self, statement: Statement, condition_requirement: dict[str, Any]
    ) -> bool:
        """Check if statement has the required condition."""
        condition_key = condition_requirement.get("condition_key")
        if not condition_key:
            return True  # No condition key specified, skip

        operator = condition_requirement.get("operator")
        expected_value = condition_requirement.get("expected_value")

        return self._has_condition(statement, condition_key, operator, expected_value)

    def _has_condition(
        self,
        statement: Statement,
        condition_key: str,
        operator: str | None = None,
        expected_value: Any = None,
    ) -> bool:
        """
        Check if statement has the specified condition key.

        Args:
            statement: The IAM policy statement
            condition_key: The condition key to look for
            operator: Optional specific operator (e.g., "StringEquals")
            expected_value: Optional expected value for the condition

        Returns:
            True if condition is present (and matches expected value if specified)
        """
        if not statement.condition:
            return False

        # If operator specified, only check that operator
        operators_to_check = [operator] if operator else list(statement.condition.keys())

        # Look through specified condition operators
        for op in operators_to_check:
            if op not in statement.condition:
                continue

            conditions = statement.condition[op]
            if isinstance(conditions, dict):
                if condition_key in conditions:
                    # If no expected value specified, just presence is enough
                    if expected_value is None:
                        return True

                    # Check if the value matches
                    actual_value = conditions[condition_key]

                    # Handle boolean values
                    if isinstance(expected_value, bool):
                        if isinstance(actual_value, bool):
                            return actual_value == expected_value
                        if isinstance(actual_value, str):
                            return actual_value.lower() == str(expected_value).lower()

                    # Handle exact matches
                    if actual_value == expected_value:
                        return True

                    # Handle list values (actual can be string or list)
                    if isinstance(expected_value, list):
                        if isinstance(actual_value, list):
                            return set(expected_value) == set(actual_value)
                        if actual_value in expected_value:
                            return True

                    # Handle string matches for variable references like ${aws:PrincipalTag/owner}
                    if str(actual_value) == str(expected_value):
                        return True

        return False

    def _create_issue(
        self,
        statement: Statement,
        statement_idx: int,
        condition_requirement: dict[str, Any],
        matching_actions: list[str],
        config: CheckConfig,
        requirement_type: str = "required",
        requirement: dict[str, Any] | None = None,
    ) -> ValidationIssue:
        """Create a validation issue for a missing condition.

        Severity precedence:
        1. Individual condition requirement's severity (condition_requirement['severity'])
        2. Parent requirement's severity (requirement['severity'])
        3. Global check severity (config.severity)
        """
        condition_key = condition_requirement.get("condition_key", "unknown")
        description = condition_requirement.get("description", "")
        expected_value = condition_requirement.get("expected_value")
        example = condition_requirement.get("example", "")
        operator = condition_requirement.get("operator", "StringEquals")

        message_prefix = "ALL required:" if requirement_type == "all_of" else "Required:"

        # Determine severity with precedence: condition > requirement > global
        severity = (
            condition_requirement.get("severity")  # Condition-level override
            or (requirement.get("severity") if requirement else None)  # Requirement-level override
            or self.get_severity(config)  # Global check severity
        )

        suggestion_text, example_code = self._build_suggestion(
            condition_key, description, example, expected_value, operator
        )

        matching_actions_str = ", ".join(f"`{a}`" for a in matching_actions)
        return ValidationIssue(
            severity=severity,
            statement_sid=statement.sid,
            statement_index=statement_idx,
            issue_type="missing_required_condition",
            message=f"{message_prefix} Action(s) {matching_actions_str} require condition `{condition_key}`",
            action=", ".join(matching_actions),
            condition_key=condition_key,
            suggestion=suggestion_text,
            example=example_code,
            line_number=statement.line_number,
            field_name="condition",
        )

    def _build_suggestion(
        self,
        condition_key: str,
        description: str,
        example: str,
        expected_value: Any = None,
        operator: str = "StringEquals",
    ) -> tuple[str, str]:
        """Build suggestion and example for adding the missing condition.

        Returns:
            Tuple of (suggestion_text, example_code)
        """
        suggestion = description if description else f"Add condition: `{condition_key}`"

        # Build example based on condition key type
        if example:
            example_code = example
        else:
            # Auto-generate example
            example_lines = [f'  "{operator}": {{']

            if isinstance(expected_value, list):
                value_str = (
                    "["
                    + ", ".join(
                        [
                            f'"{v}"' if not str(v).startswith("${") else f'"{v}"'
                            for v in expected_value
                        ]
                    )
                    + "]"
                )
            elif expected_value is not None:
                # Don't quote if it's a variable reference like ${aws:PrincipalTag/owner}
                if str(expected_value).startswith("${"):
                    value_str = f'"{expected_value}"'
                elif isinstance(expected_value, bool):
                    value_str = str(expected_value).lower()
                else:
                    value_str = f'"{expected_value}"'
            else:
                value_str = '"<value>"'

            example_lines.append(f'    "{condition_key}": {value_str}')
            example_lines.append("  }")

            example_code = "\n".join(example_lines)

        return suggestion, example_code

    def _build_any_of_suggestion(self, any_of_conditions: list[dict[str, Any]]) -> tuple[str, str]:
        """Build suggestion and combined examples for any_of conditions.

        Always uses clean formatting without "Option X" prefixes.
        Uses either:
        - 'message' field if provided (custom message)
        - 'description' field if provided (displays as: `condition_key` - description)
        - Just 'condition_key' if neither message nor description provided

        Returns:
            Tuple of (suggestion_text, combined_examples)
        """
        suggestions = []
        examples = []

        suggestions.append("Add at least ONE of these conditions:")

        for cond in any_of_conditions:
            # Handle nested all_of blocks
            if "all_of" in cond:
                # Nested all_of - show all required conditions together
                all_of_list = cond["all_of"]
                condition_keys = [c.get("condition_key", "unknown") for c in all_of_list]
                condition_keys_formatted = " + ".join(f"`{k}`" for k in condition_keys)

                # Check for custom message first
                custom_message = cond.get("message")
                if custom_message:
                    suggestions.append(f"\n- {custom_message}")
                else:
                    # Use description from first condition or combine them
                    descriptions = [
                        c.get("description", "") for c in all_of_list if c.get("description")
                    ]
                    if descriptions:
                        suggestions.append(f"\n- {condition_keys_formatted} - {descriptions[0]}")
                    else:
                        suggestions.append(f"\n- {condition_keys_formatted} (both required)")

                # Collect example from first condition that has one
                for c in all_of_list:
                    if c.get("example"):
                        examples.append(c["example"])
                        break
            else:
                # Simple condition - check for message, description, or just condition_key
                custom_message = cond.get("message")
                if custom_message:
                    # Use custom message directly
                    suggestions.append(f"\n- {custom_message}")
                else:
                    # Use description if available
                    condition_key = cond.get("condition_key", "unknown")
                    description = cond.get("description", "")
                    expected_value = cond.get("expected_value")

                    if description:
                        # Format: - `condition_key` - description
                        suggestions.append(f"\n- `{condition_key}` - {description}")
                    else:
                        # Format: - `condition_key` (with expected value if present)
                        suggestion_line = f"\n- `{condition_key}`"
                        if expected_value is not None:
                            suggestion_line += f" (value: `{expected_value}`)"
                        suggestions.append(suggestion_line)

                # Collect example if present (no prefix)
                if cond.get("example"):
                    examples.append(cond["example"])

        suggestion_text = "".join(suggestions)
        combined_examples = "\n\n".join(examples) if examples else ""

        return suggestion_text, combined_examples

    def _create_none_of_issue(
        self,
        statement: Statement,
        statement_idx: int,
        condition_requirement: dict[str, Any],
        matching_actions: list[str],
        config: CheckConfig,
    ) -> ValidationIssue:
        """Create a validation issue for a forbidden condition that is present."""
        condition_key = condition_requirement.get("condition_key", "unknown")
        description = condition_requirement.get("description", "")
        expected_value = condition_requirement.get("expected_value")

        matching_actions_str = ", ".join(f"`{a}`" for a in matching_actions)
        message = f"FORBIDDEN: Action(s) `{matching_actions_str}` must NOT have condition `{condition_key}`"
        if expected_value is not None:
            message += f" with value `{expected_value}`"

        suggestion = f"Remove the `{condition_key}` condition from the statement"
        if description:
            suggestion += f". {description}"

        return ValidationIssue(
            severity=self.get_severity(config),
            statement_sid=statement.sid,
            statement_index=statement_idx,
            issue_type="forbidden_condition_present",
            message=message,
            action=", ".join(matching_actions),
            condition_key=condition_key,
            suggestion=suggestion,
            line_number=statement.line_number,
            field_name="condition",
        )

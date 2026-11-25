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

import logging
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, ClassVar

from iam_validator.checks.utils import format_list_with_backticks
from iam_validator.checks.utils.aws_matching import action_matches, iam_glob_match
from iam_validator.checks.utils.condition_matching import has_condition_key
from iam_validator.checks.utils.finding_identity import (
    PRESENTATION_KEYS,
    canonical_rule,
    keep_most_severe,
    rule_key,
    severity_problem_key,
    unordered,
)
from iam_validator.checks.utils.requirement_branches import (
    CONDITION_GROUPS,
    DEFAULT_EFFECTS,
    TOP_LEVEL_PREFIX,
    VALID_SEVERITIES,
    branch_effects,
    branch_enforces_allow_everywhere,
    branch_matches_resources,
    branch_problem,
    conditions_problem,
    describe_entry,
    has_key_and_group,
    has_no_conditions,
    is_evaluable_entry,
    regex_problem,
    requirement_branches,
    severity_problem,
)
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.ignore_patterns import IgnorePatternMatcher
from iam_validator.core.models import Statement, ValidationIssue
from iam_validator.utils.regex import compile_and_cache

if TYPE_CHECKING:
    from iam_validator.core.models import IAMPolicy

logger = logging.getLogger(__name__)

ACTIONS_SHAPE_PROBLEM = "`actions` must be a string, a list or a mapping of `all_of`/`any_of`/`none_of`"
ACTION_PATTERNS_SHAPE_PROBLEM = "`action_patterns` must be a string or a list of regex strings"
IGNORE_PATTERNS_SHAPE_PROBLEM = "`ignore_patterns` must be a list of mappings"


def _ignore_patterns(requirement: dict[str, Any]) -> list[dict[str, Any]]:
    """The mapping entries of a requirement's ``ignore_patterns``; anything else ignores nothing."""
    value = requirement.get("ignore_patterns")
    return [entry for entry in value if isinstance(entry, dict)] if isinstance(value, list) else []


class ActionConditionEnforcementCheck(PolicyCheck):
    """Enforces specific condition requirements for specific actions with all_of/any_of support."""

    check_id: ClassVar[str] = "action_condition_enforcement"
    description: ClassVar[str] = (
        "Enforces conditions (MFA, IP, tags, etc.) for specific actions (supports all_of/any_of)"
    )
    # Missing a required condition (MFA, tag, IP, etc.) is an organizational
    # policy / security concern, not an AWS-rejectable structural error. Classify
    # it as a finding so it appears under "Policies with Findings" rather than
    # "Policies with Errors (AWS-invalid)". Users can override via config.
    default_severity: ClassVar[str] = "high"
    # In a boundary policy (SCP/RCP) an Allow declines to restrict; it never grants access.
    applies_to_policy_types: ClassVar[frozenset[str] | None] = frozenset(
        {"IDENTITY_POLICY", "RESOURCE_POLICY", "TRUST_POLICY"}
    )

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
        issues: list[ValidationIssue] = self._requirement_list_problems(config)

        # Get action condition requirements using configurable merge strategy
        requirements = self._get_merged_requirements(config, policy_file)

        if not requirements:
            return self._dedupe_issues(issues)

        # Process each requirement
        for raw_requirement in requirements:
            requirement, problems = self._prepare_requirement(raw_requirement)
            branch_problems = requirement_branches(requirement)[1] if "if" in requirement else []
            has_problems = bool(problems) or bool(branch_problems)
            if has_problems and await self._matches_any_statement(policy, raw_requirement, fetcher):
                issues.extend(problems)
                issues.extend(self._create_malformed_branch_issue(requirement, p) for p in branch_problems)
            # Check if actions use all_of/any_of/none_of (policy-wide) or simple list (per-statement)
            uses_logical_operators = self._is_policy_wide(requirement)

            if "if" in requirement:
                branch_issues = await self._check_branches(
                    policy, requirement, fetcher, config, policy_wide=uses_logical_operators
                )
                issues.extend(
                    self._filter_requirement_issues(branch_issues, _ignore_patterns(requirement), policy_file)
                )
            elif uses_logical_operators:
                # Policy-wide detection (all_of/any_of/none_of)
                policy_issues = await self._check_policy_wide(policy, requirement, fetcher, config)
                # Filter by requirement-level ignore_patterns
                policy_issues = self._filter_requirement_issues(
                    policy_issues, _ignore_patterns(requirement), policy_file
                )
                issues.extend(policy_issues)
            else:
                # Per-statement check (simple list)
                statement_issues = await self._check_per_statement(policy, requirement, fetcher, config)
                # Filter by requirement-level ignore_patterns
                statement_issues = self._filter_requirement_issues(
                    statement_issues, _ignore_patterns(requirement), policy_file
                )
                issues.extend(statement_issues)

        return self._dedupe_issues(issues)

    async def _matches_any_statement(
        self, policy: "IAMPolicy", requirement: dict[str, Any], fetcher: AWSServiceFetcher
    ) -> bool:
        """Whether any statement, of either effect, names an action of ``requirement``; true when it names none."""
        configured = requirement.get("actions", [])
        if isinstance(configured, dict):
            configured = [a for v in configured.values() for a in (v if isinstance(v, list) else [v])]
        actions = [a for a in configured if isinstance(a, str)] if isinstance(configured, list) else []
        raw_patterns = requirement.get("action_patterns")
        patterns = [p for p in raw_patterns if isinstance(p, str)] if isinstance(raw_patterns, list) else []
        if not actions and not patterns:
            return True
        probe = {**requirement, "actions": actions, "action_patterns": patterns}
        for statement in policy.statement or []:
            if patterns and (statement.not_action is not None or "*" in statement.get_actions()):
                return True
            matched, _ = await self._check_action_match(self._granted_actions(statement, actions), probe, fetcher)
            if matched:
                return True
        return False

    @staticmethod
    def _is_policy_wide(requirement: dict[str, Any]) -> bool:
        actions_config = requirement.get("actions", [])
        return isinstance(actions_config, dict) and any(key in actions_config for key in CONDITION_GROUPS)

    async def _check_branches(
        self,
        policy: "IAMPolicy",
        requirement: dict[str, Any],
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        *,
        policy_wide: bool,
    ) -> list[ValidationIssue]:
        """Enforce each ``if`` branch as an ordinary requirement scoped by its effect and resource predicates."""
        branches, _ = requirement_branches(requirement)
        issues: list[ValidationIssue] = []

        base = {k: v for k, v in requirement.items() if k not in ("if", "required_conditions", "severity")}
        for branch in branches:
            branch_requirement = {**base, "required_conditions": branch["required_conditions"]}
            severity = branch.get("severity") or requirement.get("severity")
            if severity:
                branch_requirement["severity"] = severity

            def matches(statement: Statement, branch: dict[str, Any] = branch) -> bool:
                return branch_matches_resources(branch, statement)

            effects = branch_effects(branch)
            if policy_wide:
                issues.extend(
                    await self._check_policy_wide(
                        policy, branch_requirement, fetcher, config, effects=effects, statement_filter=matches
                    )
                )
            else:
                issues.extend(
                    await self._check_per_statement(
                        policy, branch_requirement, fetcher, config, effects=effects, statement_filter=matches
                    )
                )
        return issues

    @staticmethod
    def _dedupe_issues(issues: list[ValidationIssue]) -> list[ValidationIssue]:
        """Collapse findings that differ only in severity or suggestion, keeping the most severe."""

        def key(issue: ValidationIssue) -> tuple[Any, ...]:
            unidentified = issue.finding_key is None
            return (
                issue.issue_type,
                issue.statement_index,
                issue.field_name,
                issue.action if unidentified else frozenset((issue.action or "").split(", ")),
                issue.condition_key,
                issue.line_number,
                issue.finding_key,
                issue.message if unidentified else None,
                issue.example if unidentified else None,
            )

        return keep_most_severe(issues, key)

    def _prepare_requirement(self, requirement: dict[str, Any]) -> tuple[dict[str, Any], list[ValidationIssue]]:
        """A copy of ``requirement`` without null or invalid severities, and one issue per config problem."""
        issues: list[ValidationIssue] = []
        cleaned = self._without_bad_severity(requirement, requirement, "", issues)
        self._prepare_actions(requirement, cleaned, issues)
        self._prepare_action_patterns(requirement, cleaned, issues)
        self._report_ignore_patterns(requirement, issues)
        if "if" not in cleaned:
            if "required_conditions" in cleaned:
                cleaned["required_conditions"] = self._prepare_conditions(
                    requirement, cleaned["required_conditions"], "", issues, report_shape=True
                )
            return cleaned, issues
        if isinstance(cleaned["if"], list):
            branches: list[Any] = []
            for index, branch in enumerate(cleaned["if"]):
                if isinstance(branch, dict):
                    branch = self._without_bad_severity(requirement, branch, f"`if[{index}]`", issues)
                    if branch_problem(branch) is None:
                        branch["required_conditions"] = self._prepare_conditions(
                            requirement, branch["required_conditions"], f"if[{index}].", issues, report_shape=False
                        )
                branches.append(branch)
            cleaned["if"] = branches
        top_level = cleaned.get("required_conditions")
        if not has_no_conditions(top_level) and branch_problem({"required_conditions": top_level}) is None:
            cleaned["required_conditions"] = self._prepare_conditions(
                requirement, top_level, "", issues, report_shape=False
            )
        return cleaned, issues

    def _prepare_actions(
        self, requirement: dict[str, Any], cleaned: dict[str, Any], issues: list[ValidationIssue]
    ) -> None:
        actions = cleaned.get("actions")
        if actions is None:
            return
        if isinstance(actions, list):
            cleaned["actions"] = self._string_actions(requirement, actions, "actions", issues)
            return
        if not isinstance(actions, dict):
            issues.append(self._create_malformed_requirement_issue(requirement, ACTIONS_SHAPE_PROBLEM, actions))
            cleaned["actions"] = []
            return
        kept: dict[str, Any] = {}
        for group, value in actions.items():
            if group not in CONDITION_GROUPS:
                problem = f"`actions.{group}` is not `all_of`, `any_of` or `none_of`"
            elif value is not None and not isinstance(value, list):
                problem = f"`actions.{group}` must be a list"
            else:
                kept[group] = value and self._string_actions(requirement, value, f"actions.{group}", issues)
                continue
            issues.append(self._create_malformed_requirement_issue(requirement, problem, value))
        cleaned["actions"] = kept

    def _prepare_action_patterns(
        self, requirement: dict[str, Any], cleaned: dict[str, Any], issues: list[ValidationIssue]
    ) -> None:
        patterns = cleaned.get("action_patterns")
        if patterns is None:
            return
        if isinstance(patterns, list):
            kept = []
            for pattern in self._string_actions(requirement, patterns, "action_patterns", issues):
                if problem := regex_problem("action_patterns", pattern):
                    issues.append(self._create_malformed_requirement_issue(requirement, problem, pattern))
                else:
                    kept.append(pattern)
            cleaned["action_patterns"] = kept
            return
        issues.append(self._create_malformed_requirement_issue(requirement, ACTION_PATTERNS_SHAPE_PROBLEM, patterns))
        cleaned["action_patterns"] = []

    def _report_ignore_patterns(self, requirement: dict[str, Any], issues: list[ValidationIssue]) -> None:
        value = requirement.get("ignore_patterns")
        if value is None:
            return
        bad = [entry for entry in value if not isinstance(entry, dict)] if isinstance(value, list) else [value]
        issues.extend(
            self._create_malformed_requirement_issue(requirement, IGNORE_PATTERNS_SHAPE_PROBLEM, entry) for entry in bad
        )

    def _string_actions(
        self, requirement: dict[str, Any], actions: list[Any], label: str, issues: list[ValidationIssue]
    ) -> list[str]:
        problem = f"`{label}` element must be an action string"
        issues.extend(
            self._create_malformed_requirement_issue(requirement, problem, a) for a in actions if not isinstance(a, str)
        )
        return [a for a in actions if isinstance(a, str)]

    def _without_bad_severity(
        self, requirement: dict[str, Any], node: dict[str, Any], where: str, issues: list[ValidationIssue]
    ) -> dict[str, Any]:
        cleaned = {k: v for k, v in node.items() if k != "severity"}
        severity = node.get("severity")
        if severity_problem(severity):
            issues.append(self._create_invalid_severity_issue(requirement, severity, where, node))
        elif severity is not None:
            cleaned["severity"] = severity
        return cleaned

    def _prepare_conditions(
        self,
        requirement: dict[str, Any],
        required_conditions: Any,
        prefix: str,
        issues: list[ValidationIssue],
        *,
        report_shape: bool,
    ) -> Any:
        if isinstance(required_conditions, list):
            return self._prepare_entries(requirement, required_conditions, f"{prefix}required_conditions", issues)
        if report_shape and not has_no_conditions(required_conditions):
            self._report_conditions_shape(requirement, required_conditions, issues)
        if not isinstance(required_conditions, dict):
            return required_conditions
        cleaned = dict(required_conditions)
        for group in CONDITION_GROUPS:
            value = required_conditions.get(group)
            if isinstance(value, list):
                cleaned[group] = self._prepare_entries(requirement, value, f"{prefix}{group}", issues)
        return cleaned

    def _report_conditions_shape(
        self, requirement: dict[str, Any], required_conditions: Any, issues: list[ValidationIssue]
    ) -> None:
        if not isinstance(required_conditions, dict):
            problem = conditions_problem(required_conditions)
            if problem:
                issues.append(self._create_malformed_requirement_issue(requirement, problem, required_conditions))
            return
        for key in sorted(required_conditions, key=str):
            value = required_conditions[key]
            if key in CONDITION_GROUPS and (value is None or isinstance(value, list)):
                continue
            problem = conditions_problem({key: value})
            if problem:
                issues.append(self._create_malformed_requirement_issue(requirement, problem, value))

    def _prepare_entries(
        self, requirement: dict[str, Any], entries: list[Any], label: str, issues: list[ValidationIssue]
    ) -> list[Any]:
        prepared: list[Any] = []
        for entry in entries:
            if not is_evaluable_entry(entry):
                issues.append(self._create_malformed_requirement_issue(requirement, None, entry, label))
                prepared.append(entry)
            else:
                prepared.append(self._entry_without_bad_severity(requirement, entry, label, issues))
        return prepared

    def _entry_without_bad_severity(
        self, requirement: dict[str, Any], entry: dict[str, Any], label: str, issues: list[ValidationIssue]
    ) -> dict[str, Any]:
        cleaned = self._without_bad_severity(requirement, entry, f"entry under `{label}`", issues)
        if cleaned.get("all_of") is None:
            cleaned.pop("all_of", None)
        else:
            cleaned["all_of"] = [
                self._entry_without_bad_severity(requirement, e, f"{label}.all_of", issues) for e in cleaned["all_of"]
            ]
        return cleaned

    @staticmethod
    def _actions_label(requirement: dict[str, Any]) -> tuple[str, str | None]:
        """The requirement's actions as backticked text, and as the issue's ``action`` field."""
        actions = requirement.get("actions", [])
        if isinstance(actions, list):
            return format_list_with_backticks(actions), ", ".join(a for a in actions if isinstance(a, str))
        if isinstance(actions, dict):
            named = [
                a for g in CONDITION_GROUPS if isinstance(v := actions.get(g), list) for a in v if isinstance(a, str)
            ]
            return f"`{actions!r}`", ", ".join(named) or None
        return f"`{actions!r}`", None

    def _create_invalid_severity_issue(
        self, requirement: dict[str, Any], severity: Any, where: str, node: dict[str, Any]
    ) -> ValidationIssue:
        actions_str, action = self._actions_label(requirement)
        located = (
            f" has an invalid `severity` `{severity!r}` in {where}"
            if where
            else f" has an invalid `severity` `{severity!r}`"
        )
        fallback = "the enclosing severity" if where else "the check severity"
        return ValidationIssue(
            severity="error",
            statement_sid=None,
            statement_index=-1,
            issue_type="invalid_condition_requirement",
            message=(
                f"`action_condition_requirements` entry for action(s) {actions_str}{located}; "
                f"its findings use {fallback} instead"
            ),
            action=action,
            suggestion=f"Set `severity` to one of {', '.join(sorted(VALID_SEVERITIES))}, or remove it.",
            field_name="condition",
            finding_key=rule_key(
                "severity",
                requirement.get("actions"),
                where,
                severity,
                severity_problem_key(node),
            ),
        )

    def _create_malformed_requirement_issue(
        self, requirement: dict[str, Any], problem: str | None, entry: Any, label: str = ""
    ) -> ValidationIssue:
        actions_str, action = self._actions_label(requirement)
        if problem:
            message = (
                f"`action_condition_requirements` {problem}, so it cannot be enforced for action(s) "
                f"{actions_str}: `{entry!r}`"
            )
            suggestion = "Fix its shape. Until then it enforces nothing."
        elif has_key_and_group(entry):
            message = (
                f"`action_condition_requirements` entry under `{label}` has both `condition_key` and `all_of`, "
                f"so it cannot be enforced for action(s) {actions_str}: `{entry!r}`"
            )
            suggestion = "Keep either `condition_key` or `all_of`; nest the key under `all_of` to require both."
        elif isinstance(entry, dict) and "all_of" in entry:
            message = (
                f"`action_condition_requirements` entry under `{label}` has an empty, non-list or malformed nested "
                f"`all_of`, so it cannot be enforced for action(s) {actions_str}: `{entry!r}`"
            )
            suggestion = "Give `all_of` a non-empty list of entries, each with a string `condition_key`."
        else:
            message = (
                f"`action_condition_requirements` entry under `{label}` names no string `condition_key` "
                f"(or has a non-string `operator`), so it cannot be enforced for action(s) {actions_str}: `{entry!r}`"
            )
            suggestion = (
                "Give this entry a string `condition_key` and `operator` (or nest the entry under `all_of`). "
                "Until then the entry enforces nothing."
            )
        return ValidationIssue(
            severity="error",
            statement_sid=None,
            statement_index=-1,
            issue_type="invalid_condition_requirement",
            message=message,
            action=action,
            suggestion=suggestion,
            field_name="condition",
            finding_key=rule_key("malformed", requirement.get("actions"), problem, label, repr(entry)),
        )

    def _create_malformed_branch_issue(self, requirement: dict[str, Any], problem: str) -> ValidationIssue:
        actions_str, action = self._actions_label(requirement)
        top_level = problem.startswith(TOP_LEVEL_PREFIX)
        return ValidationIssue(
            severity="error",
            statement_sid=None,
            statement_index=-1,
            issue_type="invalid_condition_requirement",
            message=(
                f"`action_condition_requirements` entry for action(s) {actions_str} has a malformed "
                f"{'`required_conditions`' if top_level else '`if` branch'}, which enforces nothing: {problem}"
            ),
            action=action,
            suggestion=(
                "Make the top-level `required_conditions` a non-empty list or an `all_of`/`any_of`/`none_of` "
                "mapping, or remove it."
                if top_level
                else "Each `if` branch is a mapping with a non-empty `required_conditions` and optional `effect` "
                "(`Allow`/`Deny`), `resource`, `not_resource` (regex) and `severity`."
            ),
            field_name="condition",
            finding_key=rule_key("branch", requirement.get("actions"), problem, canonical_rule(requirement)),
        )

    @classmethod
    def _resolve_own_config(cls, root_config: dict[str, Any]) -> dict[str, Any]:
        """Locate this check's own config inside a full config dict.

        Mirrors `ValidatorConfig.checks_config`: a `checks:` key wins outright, otherwise
        the check id is looked up as a top-level key, `_check`-suffixed spelling first.
        """
        if "checks" in root_config:
            nested = root_config.get("checks")
            if isinstance(nested, dict):
                own = nested.get(cls.check_id)
                return own if isinstance(own, dict) else {}
            return {}

        for key in (f"{cls.check_id}_check", cls.check_id):
            own = root_config.get(key)
            if isinstance(own, dict):
                return own
        return {}

    @classmethod
    def enforced_actions(cls, root_config: dict[str, Any], policy_file: str | None = None) -> set[str]:
        """The actions this check will actually enforce under ``root_config``.

        Other checks dedup against this rather than reading ``requirements`` directly, so a
        ``merge_strategy``, a disabled check, or an ``ignore_patterns`` match that stops
        enforcement also stops the dedup that assumed it.
        """
        own_config = cls._resolve_own_config(root_config)
        if not own_config.get("enabled", True):
            return set()

        hidden = own_config.get("hide_severities")
        if hidden is None:
            settings = root_config.get("settings")
            hidden = settings.get("hide_severities") if isinstance(settings, dict) else None
        if isinstance(hidden, str):
            hidden = [hidden]

        check = cls()
        config = CheckConfig(
            check_id=cls.check_id,
            enabled=True,
            severity=own_config.get("severity"),
            config=own_config,
            root_config=root_config,
            hide_severities=frozenset(hidden) if isinstance(hidden, list) else None,
        )
        requirements = check._filter_requirements_by_filepath(
            check._get_merged_requirements(config, policy_file), policy_file
        )

        return {a for raw_requirement in requirements for a in check._owned_enforced_actions(raw_requirement, config)}

    def _owned_enforced_actions(self, raw_requirement: dict[str, Any], config: CheckConfig | None) -> list[str]:
        """The owned actions of a requirement that reports, on every ``Allow``, a missing evaluable condition (or detection).

        With ``config`` ``None``, a finding's severity is not considered.
        """
        requirement, _ = self._prepare_requirement(raw_requirement)
        if "if" in requirement:
            enforces = any(
                branch_enforces_allow_everywhere(b)
                and self._reports_missing(config, {**requirement, **b}, b["required_conditions"])
                for b in requirement_branches(requirement)[0]
            )
        else:
            required = requirement.get("required_conditions")
            if has_no_conditions(required):
                enforces = config is None or self._is_kept(config, self._resolve_severity(config, requirement))
            else:
                enforces = self._reports_missing(config, requirement, required)
        return self._owned_actions(requirement.get("actions", [])) if enforces else []

    def _reports_missing(self, config: CheckConfig | None, requirement: dict[str, Any], required: Any) -> bool:
        """Whether a statement lacking every entry of ``required`` gets a finding the registry keeps."""
        if not self._requires_evaluable_condition(required):
            return False
        if config is None:
            return True
        if isinstance(required, dict):
            if self._evaluable_requirements(required.get("any_of")) and self._is_kept(
                config, self._resolve_severity(config, requirement)
            ):
                return True
            required = required.get("all_of")
        return any(
            self._is_kept(config, self._resolve_severity(config, requirement, leaf))
            for entry in self._evaluable_requirements(required)
            for leaf in self._leaf_requirements(entry)
        )

    @classmethod
    def _leaf_requirements(cls, entry: dict[str, Any], inherited: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """The leaves of ``entry``, each carrying the presentation keys a nested ``all_of`` passes down."""
        merged = {**(inherited or {}), **{k: v for k, v in entry.items() if v is not None}}
        if not isinstance(merged.get("all_of"), list):
            return [merged]
        passed = {k: merged[k] for k in PRESENTATION_KEYS if k in merged}
        return [leaf for e in merged["all_of"] if isinstance(e, dict) for leaf in cls._leaf_requirements(e, passed)]

    @staticmethod
    def _is_kept(config: CheckConfig, severity: str) -> bool:
        return severity != "none" and config.should_show_severity(severity)

    @staticmethod
    def _owned_actions(configured: Any) -> list[str]:
        """Actions a requirement enforces on its own: list entries, ``any_of`` entries and a single-entry ``all_of``."""
        if isinstance(configured, dict):
            all_of = configured.get("all_of") or []
            any_of = configured.get("any_of") or []
            single = all_of if isinstance(all_of, list) and len(all_of) == 1 else []
            configured = [*(any_of if isinstance(any_of, list) else []), *single]
        if not isinstance(configured, list):
            return []
        return [a for a in configured if isinstance(a, str)]

    _REQUIREMENT_LIST_KEYS: ClassVar[tuple[str, ...]] = (
        "requirements",
        "policy_level_requirements",
        "action_condition_requirements",
    )

    @staticmethod
    def _requirement_entries(config: CheckConfig, key: str) -> list[dict[str, Any]]:
        """The mapping entries of the requirement list under ``key``."""
        value = config.config.get(key)
        if not isinstance(value, list):
            return []
        return [
            {**r, **{k: [r[k]] for k in ("actions", "action_patterns") if isinstance(r.get(k), str)}}
            for r in value
            if isinstance(r, dict)
        ]

    @classmethod
    def _requirement_list_problems(cls, config: CheckConfig) -> list[ValidationIssue]:
        """A non-list requirement list, or a non-mapping entry in one, each reported once per policy."""
        problems: list[tuple[str, Any, str]] = []
        for key in cls._REQUIREMENT_LIST_KEYS:
            value = config.config.get(key)
            if value is None:
                continue
            if not isinstance(value, list):
                problems.append((key, value, "is not a list"))
            else:
                problems.extend(
                    (key, entry, "has an entry that is not a mapping") for entry in value if not isinstance(entry, dict)
                )
        return [
            ValidationIssue(
                severity="error",
                statement_sid=None,
                statement_index=-1,
                issue_type="invalid_condition_requirement",
                message=f"`{key}` {problem}, so it is not enforced: `{entry!r}`",
                suggestion=f"Make `{key}` a list of mappings, each with `actions` and `required_conditions`.",
                field_name="condition",
                finding_key=rule_key("requirement_list", key, problem, repr(entry)),
            )
            for key, entry, problem in problems
        ]

    def _get_merged_requirements(
        self,
        config: CheckConfig,
        policy_file: str | None,
    ) -> list[dict[str, Any]]:
        """
        Get merged requirements based on configured merge strategy.

        Supports multiple merge strategies to control how user requirements
        interact with default requirements:
        - "append": User requirements added to defaults (both apply) (default)
        - "per_action_override": User requirements replace defaults for matching actions
        - "replace_all": User requirements completely replace ALL defaults
        - "defaults_only": Ignore user requirements, use only defaults
        - "user_only": Ignore defaults, use only user requirements

        Args:
            config: Check configuration containing requirements and merge strategy
            policy_file: Path to the policy file being checked (for ignore_patterns)

        Returns:
            Merged list of requirements based on strategy
        """
        # The default layer is `requirements` plus `policy_level_requirements`.
        default_requirements = [
            *self._requirement_entries(config, "requirements"),
            *self._requirement_entries(config, "policy_level_requirements"),
        ]
        user_requirements = self._requirement_entries(config, "action_condition_requirements")

        # Get merge strategy (default: append - both defaults and user requirements apply)
        merge_strategy = config.config.get("merge_strategy", "append")

        # For user_only, replace_all, and per_action_override:
        # Filter user requirements by ignore_patterns BEFORE merging
        # For append and defaults_only: ignore_patterns on user requirements still apply
        if user_requirements:
            active_user_requirements = self._filter_requirements_by_filepath(user_requirements, policy_file)
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
            return self._merge_per_action_override(default_requirements, user_requirements, active_user_requirements)

        else:  # "append" (default)
            # Both defaults AND user requirements apply
            # User requirements are added on top of defaults
            return default_requirements + active_user_requirements

    def _filter_requirements_by_filepath(
        self,
        requirements: list[dict[str, Any]],
        policy_file: str | None,
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
            User defines: iam:CreateRole with ignore_patterns: [{filepath: ".*test/.*"}]
            When checking test/policy.json:
            - User requirement is filtered out
            - Default iam:CreateRole requirement can apply instead
        """
        active_reqs = []

        for req in requirements:
            ignore_patterns = _ignore_patterns(req)

            if not ignore_patterns:
                # No ignore patterns - include this requirement
                active_reqs.append(req)
                continue

            # Untestable without a file: assume ignored so `enforced_actions` never over-reports.
            if policy_file is None:
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
        An overlapping default keeps its uncovered list or ``any_of`` actions; one with ``action_patterns`` is dropped.

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
        user_actions = {a for req in all_user_requirements for a in self._owned_enforced_actions(req, None)}

        # Start with ACTIVE user requirements (filtered by ignore_patterns)
        merged = list(active_user_requirements)

        def covered(action: Any) -> bool:
            return isinstance(action, str) and any(iam_glob_match(user, action) for user in user_actions)

        for default_req in default_requirements:
            actions = default_req.get("actions", [])
            if not any(covered(a) for a in self._owned_actions(actions)):
                merged.append(default_req)
            elif not default_req.get("action_patterns"):
                trimmed = self._without_covered_actions(actions, covered)
                if trimmed is not None:
                    merged.append({**default_req, "actions": trimmed})

        return merged

    def _without_covered_actions(self, actions: Any, covered: Callable[[Any], bool]) -> Any:
        """``actions`` minus the covered list or ``any_of`` entries, or ``None`` when nothing enforceable remains."""
        if isinstance(actions, list):
            remaining = [a for a in actions if not covered(a)]
            return remaining if any(isinstance(a, str) for a in remaining) else None
        if any(covered(a) for a in self._owned_actions({**actions, "any_of": []})):
            return None
        any_of = [a for a in actions.get("any_of") or [] if not covered(a)]
        trimmed = {k: v for k, v in actions.items() if k != "any_of"} | ({"any_of": any_of} if any_of else {})
        return trimmed if any(trimmed.get(group) for group in ("all_of", "any_of", "none_of")) else None

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
            issue for issue in issues if not IgnorePatternMatcher.should_ignore_issue(issue, filepath, ignore_patterns)
        ]

    async def _check_policy_wide(
        self,
        policy: "IAMPolicy",
        requirement: dict[str, Any],
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        *,
        effects: frozenset[str] = DEFAULT_EFFECTS,
        statement_filter: Callable[[Statement], bool] | None = None,
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
        all_of = actions_config.get("all_of") or []
        any_of = actions_config.get("any_of") or []
        none_of = actions_config.get("none_of") or []

        # Collect all actions across the entire policy
        policy_wide_actions: dict[str, None] = {}
        statements_by_action: dict[str, list[tuple[int, Statement]]] = {}

        for idx, statement in enumerate(policy.statement or []):
            if statement.effect not in effects or (statement_filter and not statement_filter(statement)):
                continue

            statement_actions = self._granted_actions(statement, [*all_of, *any_of, *none_of])
            policy_wide_actions.update(dict.fromkeys(statement_actions))

            # Track which statements grant which actions
            for action in statement_actions:
                if action not in statements_by_action:
                    statements_by_action[action] = []
                statements_by_action[action].append((idx, statement))

        # Check all_of: ALL required actions must exist in policy
        if all_of:
            all_of_result = await self._check_all_of_policy_wide(
                all_of,
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
            allowed_by_action = {
                action: allowed
                for action, statements in statements_by_action.items()
                if (allowed := [(i, s) for i, s in statements if s.effect == "Allow"])
            }
            none_of_result = await self._check_none_of_policy_wide(
                none_of,
                dict.fromkeys(allowed_by_action),
                allowed_by_action,
                requirement,
                config,
                fetcher,
            )
            issues.extend(none_of_result)

        return issues

    async def _check_all_of_policy_wide(
        self,
        all_of_actions: list[str],
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
        statements_with_all_actions: list[tuple[int, Statement, list[str]]] = []

        for stmt_idx, stmt in sorted({i: st for lst in statements_by_action.values() for i, st in lst}.items()):
            matched_actions = await self._all_of_matches(stmt, all_of_actions, fetcher)
            if matched_actions is not None:
                statements_with_all_actions.append((stmt_idx, stmt, self._in_statement_order(stmt, matched_actions)))

        if not statements_with_all_actions:
            return []

        return self._generate_policy_wide_issues(
            statements_with_all_actions,
            requirement,
            config,
            "all_of",
        )

    async def _all_of_matches(
        self,
        stmt: Statement,
        all_of_actions: list[str],
        fetcher: AWSServiceFetcher,
    ) -> list[str] | None:
        """The statement actions matching every ``all_of`` action by name, or ``None`` when one is missing."""
        stmt_actions = self._granted_actions(stmt, all_of_actions)
        matched: list[str] = []
        for req_action in all_of_actions:
            for stmt_action in stmt_actions:
                if await self._action_matches(stmt_action, req_action, [], fetcher):
                    if stmt_action not in matched:
                        matched.append(stmt_action)
                    break
            else:
                return None
        return matched

    async def _statements_granting(
        self,
        candidates: list[str],
        policy_wide_actions: dict[str, None],
        statements_by_action: dict[str, list[tuple[int, Statement]]],
        requirement: dict[str, Any],
        fetcher: AWSServiceFetcher,
    ) -> tuple[list[str], list[tuple[int, Statement, list[str]]]]:
        """Policy actions matching any of ``candidates``, and each granting statement (by index) with its matches."""
        patterns = requirement.get("action_patterns", [])
        found: list[str] = []
        for policy_action in policy_wide_actions:
            for candidate in candidates:
                if await self._action_matches(policy_action, candidate, patterns, fetcher):
                    found.append(policy_action)
                    break
        by_statement: dict[int, tuple[Statement, list[str]]] = {}
        for action in found:
            for idx, stmt in statements_by_action.get(action, []):
                by_statement.setdefault(idx, (stmt, []))[1].append(action)
        return found, [
            (idx, stmt, self._in_statement_order(stmt, actions))
            for idx, (stmt, actions) in sorted(by_statement.items())
        ]

    @staticmethod
    def _in_statement_order(stmt: Statement, actions: list[str]) -> list[str]:
        """``actions`` in the order ``stmt`` lists them; alphabetical for ``NotAction`` statements."""
        rank: dict[str, int] = {}
        for i, action in enumerate(stmt.get_actions()):
            rank.setdefault(action, i)
        return sorted(set(actions), key=lambda a: (rank.get(a, len(rank)), a))

    async def _check_any_of_policy_wide(
        self,
        any_of_actions: list[str],
        policy_wide_actions: dict[str, None],
        statements_by_action: dict[str, list[tuple[int, Statement]]],
        requirement: dict[str, Any],
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Check if at least ONE required action exists anywhere in the policy."""
        _, statements_with_required_actions = await self._statements_granting(
            any_of_actions, policy_wide_actions, statements_by_action, requirement, fetcher
        )
        if not statements_with_required_actions:
            return []

        return self._generate_policy_wide_issues(
            statements_with_required_actions,
            requirement,
            config,
            "any_of",
        )

    async def _check_none_of_policy_wide(
        self,
        none_of_actions: list[str],
        policy_wide_actions: dict[str, None],
        statements_by_action: dict[str, list[tuple[int, Statement]]],
        requirement: dict[str, Any],
        config: CheckConfig,
        fetcher: AWSServiceFetcher,
    ) -> list[ValidationIssue]:
        """Check if any forbidden actions exist in the policy."""
        issues: list[ValidationIssue] = []
        forbidden_found, statements_with_forbidden = await self._statements_granting(
            none_of_actions, policy_wide_actions, statements_by_action, requirement, fetcher
        )
        if not forbidden_found:
            return issues

        description = requirement.get("description", "These actions should not be used")
        severity = self._resolve_severity(config, requirement)
        statement_refs = ", ".join(self._statement_refs(statements_with_forbidden))
        patterns = requirement.get("action_patterns") or []

        for stmt_idx, stmt, actions in statements_with_forbidden:
            actions_formatted = format_list_with_backticks(actions)

            issues.append(
                self._with_rule_identity(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=stmt.sid,
                        statement_index=stmt_idx,
                        issue_type="forbidden_action",
                        message=f"Forbidden actions {actions_formatted} found. {description}",
                        action=", ".join(actions),
                        suggestion=f"Remove these forbidden actions. Found in: {statement_refs}. {description}",
                        line_number=stmt.line_number,
                        field_name="action",
                    ),
                    "none_of",
                    unordered([a.lower() if isinstance(a, str) else a for a in none_of_actions]),
                    *([unordered(patterns)] if patterns else []),
                )
            )

        return issues

    @staticmethod
    def _statement_refs(matching: list[tuple[int, Statement, list[str]]]) -> list[str]:
        """``Statement #n (SID: x)`` for each matching statement."""
        return [f"Statement #{idx + 1}{f' (SID: {stmt.sid})' if stmt.sid else ''}" for idx, stmt, _ in matching]

    @staticmethod
    def _detection_identity(requirement: dict[str, Any], scope: str) -> tuple[Any, ...]:
        """Rule identity of a detection-only requirement: its action spec (any order or case), patterns and scope."""

        def actions_key(actions: Any) -> list[str]:
            return unordered([a.lower() if isinstance(a, str) else a for a in actions or []])

        actions = requirement.get("actions")
        spec = (
            {k: actions_key(v) for k, v in actions.items() if v}
            if isinstance(actions, dict)
            else actions_key(actions if isinstance(actions, list) else [actions])
        )
        patterns = requirement.get("action_patterns") or []
        return ("detected", spec, scope, *([unordered(patterns)] if patterns else []))

    @classmethod
    def _action_detected_issues(
        cls,
        matching: list[tuple[int, Statement, list[str]]],
        requirement: dict[str, Any],
        severity: str,
        scope: str = "",
    ) -> list[ValidationIssue]:
        """One ``action_detected`` issue per matching statement, naming its actions in the statement's own order."""
        refs = cls._statement_refs(matching)
        description = requirement.get("description", "")
        identity = cls._detection_identity(requirement, scope)
        issues = []
        for idx, stmt, actions in matching:
            found = cls._in_statement_order(stmt, actions)
            issues.append(
                cls._with_rule_identity(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=stmt.sid,
                        statement_index=idx,
                        issue_type="action_detected",
                        message=f"Actions {format_list_with_backticks(found)} found{scope}. {description}",
                        action=", ".join(found),
                        suggestion=f"Review these statements: {', '.join(refs)}. {description}",
                        line_number=stmt.line_number,
                        field_name="action",
                    ),
                    *identity,
                )
            )
        return issues

    def _generate_policy_wide_issues(
        self,
        statements_with_actions: list[tuple[int, Statement, list[str]]],
        requirement: dict[str, Any],
        config: CheckConfig,
        operator_type: str,
    ) -> list[ValidationIssue]:
        """Generate validation issues for policy-wide checks."""
        issues = []
        required_conditions_config = requirement.get("required_conditions", [])
        severity = self._resolve_severity(config, requirement)

        if has_no_conditions(required_conditions_config):
            return self._action_detected_issues(statements_with_actions, requirement, severity, f" ({operator_type})")

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

            # Add cross-statement context when multiple statements share these actions
            if len(statements_with_actions) > 1:
                for issue in condition_issues:
                    issue.suggestion = (
                        f"{issue.suggestion}\n\n"
                        f"Note: {len(statements_with_actions)} statements in this policy use these actions — each needs this condition."
                    )

            issues.extend(condition_issues)

        return issues

    async def _check_per_statement(
        self,
        policy: "IAMPolicy",
        requirement: dict[str, Any],
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        *,
        effects: frozenset[str] = DEFAULT_EFFECTS,
        statement_filter: Callable[[Statement], bool] | None = None,
    ) -> list[ValidationIssue]:
        """
        Check each statement individually for matching actions (simple list format).

        Used when actions are specified as a simple list (not using all_of/any_of/none_of).
        """
        issues: list[ValidationIssue] = []
        matching_statements: list[tuple[int, Statement, list[str]]] = []

        for idx, statement in enumerate(policy.statement or []):
            if statement.effect not in effects or (statement_filter and not statement_filter(statement)):
                continue

            required = requirement.get("actions", [])
            statement_actions = self._granted_actions(statement, required if isinstance(required, list) else [])

            # Check if this statement matches the action requirement
            actions_match, matching_actions = await self._check_action_match(statement_actions, requirement, fetcher)

            if actions_match and matching_actions:
                matching_statements.append((idx, statement, matching_actions))

        # If no statements match, skip this requirement
        if not matching_statements:
            return issues

        # Now validate that ALL matching statements have the required conditions
        required_conditions_config = requirement.get("required_conditions", [])
        if has_no_conditions(required_conditions_config):
            return self._action_detected_issues(
                matching_statements,
                requirement,
                self._resolve_severity(config, requirement),
            )

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

            # Add cross-statement context when multiple statements share these actions
            if len(matching_statements) > 1:
                for issue in condition_issues:
                    issue.suggestion = (
                        f"{issue.suggestion}\n\n"
                        f"Note: {len(matching_statements)} statements in this policy use these actions — each needs this condition."
                    )

            issues.extend(condition_issues)

        return issues

    @staticmethod
    def _granted_actions(statement: Statement, candidates: list[str]) -> list[str]:
        """The statement's actions; for ``NotAction``, the ``candidates`` it does not exclude."""
        if statement.not_action is None:
            return statement.get_actions()
        excluded = statement.get_not_actions()
        return [c for c in candidates if not any(iam_glob_match(n, c) for n in excluded)]

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
                # Check if this statement action matches any of the required actions or patterns
                # Use _action_matches which handles wildcards in both statement and config
                matched = False

                # Full wildcard "*" matches any required action
                if stmt_action == "*":
                    if actions_config or action_patterns:
                        matched = True
                else:
                    # Check against configured actions
                    for required_action in actions_config:
                        if await self._action_matches(stmt_action, required_action, action_patterns, fetcher):
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
            all_of = actions_config.get("all_of") or []
            any_of = actions_config.get("any_of") or []
            none_of = actions_config.get("none_of") or []

            # Check all_of: ALL specified actions must be in statement
            if all_of:
                all_present = True
                for req_action in all_of:
                    found = False
                    for stmt_action in statement_actions:
                        if await self._action_matches(stmt_action, req_action, [], fetcher):
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
                        if await self._action_matches(stmt_action, req_action, [], fetcher):
                            if stmt_action not in matching_actions:
                                matching_actions.append(stmt_action)

            # Check any_of: At least ONE specified action must be in statement
            if any_of:
                any_present = False
                for stmt_action in statement_actions:
                    for req_action in any_of:
                        if await self._action_matches(stmt_action, req_action, action_patterns, fetcher):
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
                        if await self._action_matches(stmt_action, forbidden_action, action_patterns, fetcher):
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
        # Exact match, and bidirectional case-insensitive wildcard match
        # (statement_action="*" or "iam:Create*", required_action="iam:CreateUser" or "iam:Creat*")
        if action_matches(statement_action, required_action):
            return True

        # AWS wildcard match in statement_action (e.g., "iam:Creat*" in policy)
        # Check if this wildcard would grant access to actions matching our patterns
        if "*" in statement_action:
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

                except Exception as exc:  # pylint: disable=broad-exception-caught
                    logger.debug("Falling back to prefix matching for %s: %r", statement_action, exc)
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

        if isinstance(required_conditions_config, list):
            for condition_requirement in self._evaluable_requirements(required_conditions_config):
                for missing in self._missing_requirements(statement, condition_requirement):
                    issues.append(
                        self._create_issue(
                            statement,
                            statement_idx,
                            missing,
                            matching_actions,
                            config,
                            requirement=requirement,
                        )
                    )
            return issues

        if not isinstance(required_conditions_config, dict):
            return issues

        all_of, any_of, none_of = (
            self._evaluable_requirements(required_conditions_config.get(group)) for group in CONDITION_GROUPS
        )

        for condition_requirement in all_of:
            for missing in self._missing_requirements(statement, condition_requirement):
                issues.append(
                    self._create_issue(
                        statement,
                        statement_idx,
                        missing,
                        matching_actions,
                        config,
                        requirement_type="all_of",
                        requirement=requirement,
                    )
                )

        if any_of:
            any_present = any(self._has_condition_requirement(statement, cond_req) for cond_req in any_of)

            if not any_present:
                custom_message = requirement.get("message") if requirement else None
                custom_suggestion = requirement.get("suggestion") if requirement else None
                custom_example = requirement.get("example") if requirement else None

                if custom_message:
                    message = custom_message
                    suggestion = custom_suggestion or ""
                    example = custom_example or ""
                else:
                    condition_keys_formatted = " OR ".join(describe_entry(c) for c in any_of)
                    matching_actions_formatted = format_list_with_backticks(matching_actions)

                    message = (
                        f"Actions {matching_actions_formatted} require at least ONE of these conditions: "
                        f"{condition_keys_formatted}"
                    )

                    suggestion, example = self._build_any_of_suggestion(any_of)

                issues.append(
                    self._with_rule_identity(
                        ValidationIssue(
                            severity=self._resolve_severity(config, requirement),
                            statement_sid=statement.sid,
                            statement_index=statement_idx,
                            issue_type="missing_required_condition_any_of",
                            message=message,
                            action=", ".join(matching_actions),
                            suggestion=suggestion,
                            example=example if example else None,
                            line_number=statement.line_number,
                            field_name="condition",
                        ),
                        "any_of",
                        unordered(any_of),
                    )
                )

        for condition_requirement in none_of:
            if statement.effect == "Allow" and self._has_condition_requirement(statement, condition_requirement):
                issues.append(
                    self._create_none_of_issue(
                        statement,
                        statement_idx,
                        condition_requirement,
                        matching_actions,
                        config,
                        requirement=requirement,
                    )
                )

        return issues

    def _has_condition_requirement(self, statement: Statement, condition_requirement: dict[str, Any]) -> bool:
        """Check if statement has the required condition."""
        nested_all_of = condition_requirement.get("all_of")
        if nested_all_of:
            return all(self._has_condition_requirement(statement, nested) for nested in nested_all_of)

        condition_key = condition_requirement.get("condition_key")
        if not condition_key:
            return False

        operator = condition_requirement.get("operator")
        expected_value = condition_requirement.get("expected_value")

        return has_condition_key(statement, condition_key, operator, expected_value)

    @classmethod
    def _requires_evaluable_condition(cls, required_conditions: Any) -> bool:
        """Whether ``required_conditions`` requires (not only forbids) at least one evaluable entry."""
        if isinstance(required_conditions, list):
            return bool(cls._evaluable_requirements(required_conditions))
        if isinstance(required_conditions, dict):
            return any(cls._evaluable_requirements(required_conditions.get(g)) for g in ("all_of", "any_of"))
        return False

    @staticmethod
    def _evaluable_requirements(entries: Any) -> list[dict[str, Any]]:
        """The entries of a condition group that can be evaluated; malformed ones are reported once per policy."""
        if not isinstance(entries, list):
            return []
        return [e for e in entries if is_evaluable_entry(e)]

    @staticmethod
    def _with_rule_identity(issue: ValidationIssue, *rule: Any) -> ValidationIssue:
        issue.finding_key = rule_key(*rule)
        return issue

    def _missing_requirements(self, statement: Statement, entry: dict[str, Any]) -> list[dict[str, Any]]:
        """The leaf requirements of ``entry`` the statement lacks; a nested ``all_of`` passes down its severity, description and example."""
        if "all_of" not in entry:
            return [] if self._has_condition_requirement(statement, entry) else [entry]
        inherited: dict[str, Any] = {k: entry[k] for k in PRESENTATION_KEYS if k in entry}
        return [
            m
            for e in entry["all_of"]
            for m in self._missing_requirements(
                statement, {**inherited, **{k: v for k, v in e.items() if v is not None}}
            )
        ]

    def _resolve_severity(
        self,
        config: CheckConfig,
        requirement: dict[str, Any] | None = None,
        condition_requirement: dict[str, Any] | None = None,
    ) -> str:
        """Severity for a finding: condition-level override, then requirement-level, then global."""
        return (
            (condition_requirement.get("severity") if condition_requirement else None)
            or (requirement.get("severity") if requirement else None)
            or self.get_severity(config)
        )

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
        operator = condition_requirement.get("operator") or "StringEquals"

        message_prefix = "ALL required:" if requirement_type == "all_of" else "Required:"

        severity = self._resolve_severity(config, requirement, condition_requirement)

        suggestion_text, example_code = self._build_suggestion(
            condition_key, description, example, expected_value, operator
        )

        matching_actions_str = format_list_with_backticks(matching_actions)
        return self._with_rule_identity(
            ValidationIssue(
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
            ),
            "all_of" if requirement_type == "required" else requirement_type,
            condition_requirement,
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
                    + ", ".join([f'"{v}"' if not str(v).startswith("${") else f'"{v}"' for v in expected_value])
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
                condition_keys_formatted = " + ".join(describe_entry(c) for c in all_of_list)

                # Check for custom message first
                custom_message = cond.get("message")
                if custom_message:
                    suggestions.append(f"\n- {custom_message}")
                else:
                    descriptions = [c.get("description", "") for c in [cond, *all_of_list] if c.get("description")]
                    if descriptions:
                        suggestions.append(f"\n- {condition_keys_formatted} - {descriptions[0]}")
                    else:
                        suggestions.append(f"\n- {condition_keys_formatted} (both required)")

                for c in [cond, *all_of_list]:
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
        requirement: dict[str, Any] | None = None,
    ) -> ValidationIssue:
        """Create a validation issue for a forbidden condition that is present."""
        condition_key = None if "all_of" in condition_requirement else condition_requirement.get("condition_key")
        label = describe_entry(condition_requirement)
        description = condition_requirement.get("description", "")
        expected_value = condition_requirement.get("expected_value")

        matching_actions_str = format_list_with_backticks(matching_actions)
        message = f"FORBIDDEN: Action(s) {matching_actions_str} must NOT have condition {label}"
        if expected_value is not None:
            message += f" with value `{expected_value}`"

        suggestion = f"Remove the {label} condition from the statement"
        if description:
            suggestion += f". {description}"

        return self._with_rule_identity(
            ValidationIssue(
                severity=self._resolve_severity(config, requirement, condition_requirement),
                statement_sid=statement.sid,
                statement_index=statement_idx,
                issue_type="forbidden_condition_present",
                message=message,
                action=", ".join(matching_actions),
                condition_key=condition_key,
                suggestion=suggestion,
                line_number=statement.line_number,
                field_name="condition",
            ),
            "none_of",
            condition_requirement,
        )

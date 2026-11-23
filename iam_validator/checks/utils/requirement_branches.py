"""Parsing and matching for the ``if:`` branches of an ``action_condition_enforcement`` requirement."""

import re
from typing import Any

from iam_validator.core.models import Statement, ValidationIssue
from iam_validator.utils.regex import compile_and_cache

BRANCH_KEYS = frozenset({"effect", "resource", "not_resource", "required_conditions", "severity"})
EFFECTS = {"allow": "Allow", "deny": "Deny"}
VALID_SEVERITIES = ValidationIssue.VALID_SEVERITIES
DEFAULT_EFFECTS = frozenset({"Allow"})
CONDITION_GROUPS = ("all_of", "any_of", "none_of")
TOP_LEVEL_PREFIX = "top-level "
CONDITIONS_SHAPE_PROBLEM = "`required_conditions` must be a list or a mapping of `all_of`/`any_of`/`none_of`"


def has_no_conditions(required_conditions: Any) -> bool:
    """Whether ``required_conditions`` is ``None``, ``[]``, ``{}`` or a mapping whose groups are all empty or null."""
    if isinstance(required_conditions, dict) and required_conditions.keys() <= set(CONDITION_GROUPS):
        return all(v is None or v == [] for v in required_conditions.values())
    return required_conditions is None or required_conditions == [] or required_conditions == {}


def has_key_and_group(entry: Any) -> bool:
    """Whether a condition entry sets both ``condition_key`` and ``all_of`` to non-null values."""
    return isinstance(entry, dict) and entry.get("condition_key") is not None and entry.get("all_of") is not None


def without_null_all_of(entry: dict[str, Any]) -> dict[str, Any]:
    """An evaluable ``entry`` with every null ``all_of`` (its own and nested ones) removed."""
    nested = entry.get("all_of")
    if nested is None:
        return {k: v for k, v in entry.items() if k != "all_of"}
    return {**entry, "all_of": [without_null_all_of(e) for e in nested]}


def is_evaluable_entry(entry: Any) -> bool:
    """Whether a condition entry has a non-empty string ``condition_key`` (and string ``operator``, if set), or a non-empty ``all_of`` of such entries; a null key or group counts as unset."""
    if not isinstance(entry, dict) or has_key_and_group(entry):
        return False
    if entry.get("all_of") is not None:
        nested = entry["all_of"]
        return isinstance(nested, list) and bool(nested) and all(is_evaluable_entry(e) for e in nested)
    condition_key = entry.get("condition_key")
    operator = entry.get("operator")
    return isinstance(condition_key, str) and bool(condition_key) and (operator is None or isinstance(operator, str))


def severity_problem(severity: Any) -> str | None:
    """Why ``severity`` is not a valid severity, or ``None`` when it is valid or unset."""
    if severity is None or (isinstance(severity, str) and severity in VALID_SEVERITIES):
        return None
    return f"`severity` must be one of {', '.join(sorted(VALID_SEVERITIES))}, got `{severity!r}`"


def conditions_problem(required_conditions: Any) -> str | None:
    """Why ``required_conditions`` cannot be enforced, or ``None`` when it holds at least one group or entry."""
    if isinstance(required_conditions, list) and required_conditions:
        return None
    if required_conditions is not None and not isinstance(required_conditions, (list, dict)):
        return CONDITIONS_SHAPE_PROBLEM
    if isinstance(required_conditions, dict):
        unknown = sorted(map(str, required_conditions.keys() - set(CONDITION_GROUPS)))
        if unknown:
            return f"`required_conditions.{unknown[0]}` is not `all_of`, `any_of` or `none_of`"
        groups = {k: v for k in CONDITION_GROUPS if (v := required_conditions.get(k)) is not None}
        not_lists = [k for k, v in groups.items() if not isinstance(v, list)]
        if not_lists:
            return f"`required_conditions.{not_lists[0]}` must be a list, got `{groups[not_lists[0]]!r}`"
        if any(groups.values()):
            return None
    return "`required_conditions` is missing or empty"


def _effect_problem(effect: Any) -> str | None:
    values = effect if isinstance(effect, list) else [effect]
    if not values or not all(isinstance(v, str) and v.lower() in EFFECTS for v in values):
        return f"`effect` must be `Allow`, `Deny` or a non-empty list of them, got `{effect!r}`"
    return None


def _only_none_of(groups: Any) -> bool:
    return (
        isinstance(groups, dict)
        and bool(groups.get("none_of"))
        and not groups.get("all_of")
        and not groups.get("any_of")
    )


def _deny_only(branch: dict[str, Any]) -> bool:
    return branch_effects(branch) == frozenset({"Deny"})


def _deny_only_none_of(branch: dict[str, Any]) -> bool:
    return _deny_only(branch) and _only_none_of(branch.get("required_conditions"))


def _regex_problem(key: str, pattern: Any) -> str | None:
    if not isinstance(pattern, str):
        return f"`{key}` must be a regex string, got `{pattern!r}`"
    try:
        compile_and_cache(pattern)
    except re.error as exc:
        return f"`{key}` is not a valid regex (`{pattern}`): {exc}"
    return None


def branch_problem(branch: Any) -> str | None:
    """Why ``branch`` cannot be enforced, or ``None`` when it is well formed; ``severity`` is checked by the caller."""
    if not isinstance(branch, dict):
        return f"branch must be a mapping, got `{branch!r}`"
    unknown = sorted(str(k) for k in branch if k not in BRANCH_KEYS)
    if unknown:
        allowed = ", ".join(f"`{k}`" for k in sorted(BRANCH_KEYS))
        return f"unknown key(s) {', '.join(f'`{k}`' for k in unknown)} (allowed: {allowed})"
    if "resource" in branch and "not_resource" in branch:
        return "`resource` and `not_resource` are mutually exclusive: a statement has only one of them"
    problem = conditions_problem(branch.get("required_conditions"))
    if problem:
        return problem
    if "effect" in branch and (problem := _effect_problem(branch["effect"])):
        return problem
    if _deny_only_none_of(branch):
        return "`none_of` only flags `Allow` statements, so a `Deny`-only branch carrying just `none_of` never fires"
    for key in ("resource", "not_resource"):
        if key in branch and (problem := _regex_problem(key, branch[key])):
            return problem
    return None


def requirement_branches(requirement: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """The enforceable branches of a requirement carrying ``if``, and a message per malformed one.

    A top-level ``required_conditions`` beside ``if`` is returned as one more branch with no predicate.
    """
    branches: list[dict[str, Any]] = []
    problems: list[str] = []
    raw = requirement.get("if")
    if not isinstance(raw, list) or not raw:
        problems.append(f"`if` must be a non-empty list of branches, got `{raw!r}`")
        raw = []
    forbids_only = _only_none_of(requirement.get("actions"))
    for index, branch in enumerate(raw):
        problem = branch_problem(branch)
        if problem is None and forbids_only and _deny_only(branch):
            problem = "`actions.none_of` only flags `Allow` statements, so a `Deny`-only branch never fires"
        if problem:
            problems.append(f"`if[{index}]`: {problem}")
        else:
            branches.append(branch)
    if not has_no_conditions(requirement.get("required_conditions")):
        top_level = requirement["required_conditions"]
        problem = conditions_problem(top_level)
        if problem:
            problems.append(f"{TOP_LEVEL_PREFIX}{problem}")
        else:
            branches.append({"required_conditions": top_level})
    return branches, problems


def branch_effects(branch: dict[str, Any]) -> frozenset[str]:
    """Statement effects ``branch`` applies to; ``Allow`` when ``effect`` is omitted."""
    if "effect" not in branch:
        return DEFAULT_EFFECTS
    effect = branch["effect"]
    values = effect if isinstance(effect, list) else [effect]
    return frozenset(EFFECTS[v.lower()] for v in values)


def _any_fullmatch(pattern: str, values: list[str]) -> bool:
    compiled = compile_and_cache(pattern)
    return any(compiled.fullmatch(v) for v in values)


def branch_matches_resources(branch: dict[str, Any], statement: Statement) -> bool:
    """True when every resource predicate of ``branch`` full-matches some entry of the statement."""
    if "resource" in branch and not _any_fullmatch(branch["resource"], statement.get_resources()):
        return False
    if "not_resource" in branch and not _any_fullmatch(branch["not_resource"], statement.get_not_resources()):
        return False
    return True


def branch_enforces_allow_everywhere(branch: dict[str, Any]) -> bool:
    """True when ``branch`` applies to every ``Allow`` statement regardless of resource."""
    if "resource" in branch or "not_resource" in branch:
        return False
    return "Allow" in branch_effects(branch)

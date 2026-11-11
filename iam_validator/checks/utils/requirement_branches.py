"""Parsing and matching for the ``if:`` branches of an ``action_condition_enforcement`` requirement."""

import re
from typing import Any

from iam_validator.core.models import Statement
from iam_validator.utils.regex import compile_and_cache

BRANCH_KEYS = frozenset({"effect", "resource", "not_resource", "required_conditions", "severity"})
EFFECTS = {"allow": "Allow", "deny": "Deny"}
VALID_SEVERITIES = frozenset({"error", "warning", "info", "critical", "high", "medium", "low", "none"})

PER_STATEMENT_DEFAULT_EFFECTS = frozenset({"Allow", "Deny"})
POLICY_WIDE_DEFAULT_EFFECTS = frozenset({"Allow"})


def _conditions_problem(required_conditions: Any) -> str | None:
    if isinstance(required_conditions, list) and required_conditions:
        return None
    if isinstance(required_conditions, dict) and any(
        required_conditions.get(k) for k in ("all_of", "any_of", "none_of")
    ):
        return None
    return "`required_conditions` is missing or empty"


def _effect_problem(effect: Any) -> str | None:
    values = effect if isinstance(effect, list) else [effect]
    if not values or not all(isinstance(v, str) and v.lower() in EFFECTS for v in values):
        return f"`effect` must be `Allow`, `Deny` or a non-empty list of them, got `{effect!r}`"
    return None


def _regex_problem(key: str, pattern: Any) -> str | None:
    if not isinstance(pattern, str):
        return f"`{key}` must be a regex string, got `{pattern!r}`"
    try:
        compile_and_cache(pattern)
    except re.error as exc:
        return f"`{key}` is not a valid regex (`{pattern}`): {exc}"
    return None


def branch_problem(branch: Any) -> str | None:
    """Why ``branch`` cannot be enforced, or ``None`` when it is well formed."""
    if not isinstance(branch, dict):
        return f"branch must be a mapping, got `{branch!r}`"
    unknown = sorted(str(k) for k in branch if k not in BRANCH_KEYS)
    if unknown:
        allowed = ", ".join(f"`{k}`" for k in sorted(BRANCH_KEYS))
        return f"unknown key(s) {', '.join(f'`{k}`' for k in unknown)} (allowed: {allowed})"
    problem = _conditions_problem(branch.get("required_conditions"))
    if problem:
        return problem
    if "effect" in branch and (problem := _effect_problem(branch["effect"])):
        return problem
    for key in ("resource", "not_resource"):
        if key in branch and (problem := _regex_problem(key, branch[key])):
            return problem
    severity = branch.get("severity")
    if "severity" in branch and not (isinstance(severity, str) and severity in VALID_SEVERITIES):
        return f"`severity` must be one of {', '.join(sorted(VALID_SEVERITIES))}, got `{severity!r}`"
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
    for index, branch in enumerate(raw):
        problem = branch_problem(branch)
        if problem:
            problems.append(f"`if[{index}]`: {problem}")
        else:
            branches.append(branch)
    if "required_conditions" in requirement:
        top_level = requirement["required_conditions"]
        problem = _conditions_problem(top_level)
        if problem:
            problems.append(f"top-level {problem}")
        else:
            branches.append({"required_conditions": top_level})
    return branches, problems


def branch_effects(branch: dict[str, Any], *, policy_wide: bool) -> frozenset[str]:
    """Statement effects ``branch`` applies to; omitted means both per statement, ``Allow`` policy-wide."""
    if "effect" not in branch:
        return POLICY_WIDE_DEFAULT_EFFECTS if policy_wide else PER_STATEMENT_DEFAULT_EFFECTS
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
    return "Allow" in branch_effects(branch, policy_wide=True)

"""Condition-operator semantics shared by checks that assert a condition is enforced."""

from typing import Any

from iam_validator.core.models import Statement

#: Operators that exclude a value rather than constrain to one. On an ``Allow`` these
#: do not satisfy a "this key must be constrained" requirement; on a ``Deny`` they do.
NEGATED_OPERATORS: frozenset[str] = frozenset(
    {
        "arnnotequals",
        "arnnotlike",
        "datenotequals",
        "notipaddress",
        "numericnotequals",
        "stringnotequals",
        "stringnotequalsignorecase",
        "stringnotlike",
    }
)


def base_operator(operator: str) -> str:
    """Lowercase operator without set prefix (ForAnyValue:/ForAllValues:) or IfExists suffix."""
    return operator.strip().lower().rsplit(":", 1)[-1].removesuffix("ifexists")


def is_negated_operator(operator: str) -> bool:
    """True if the operator excludes values instead of constraining them."""
    return base_operator(operator) in NEGATED_OPERATORS


def is_deny(statement: Statement) -> bool:
    """True only for an unambiguous Deny, so a malformed Effect is still checked."""
    return isinstance(statement.effect, str) and statement.effect.strip().lower() == "deny"


def _value_matches(actual_value: Any, expected_value: Any) -> bool:
    if isinstance(expected_value, bool):
        if isinstance(actual_value, bool):
            return actual_value == expected_value
        if isinstance(actual_value, str):
            return actual_value.lower() == str(expected_value).lower()
    if actual_value == expected_value:
        return True
    if isinstance(expected_value, list):
        if isinstance(actual_value, list):
            return set(expected_value) == set(actual_value)
        if actual_value in expected_value:
            return True
    return str(actual_value) == str(expected_value)


def has_condition_key(
    statement: Statement,
    condition_key: str,
    operator: str | None = None,
    expected_value: Any = None,
    *,
    accept_negated: bool | None = None,
) -> bool:
    """True if the statement constrains ``condition_key`` in a way that satisfies a requirement.

    ``accept_negated`` defaults to ``is_deny(statement)``: a negated operator is a real
    guard on a Deny and a non-guard on an Allow.
    """
    if not statement.condition:
        return False

    if accept_negated is None:
        accept_negated = is_deny(statement)

    if operator:
        wanted = operator.strip().lower()
        operators_to_check = [op for op in statement.condition if op.strip().lower() == wanted]
    else:
        operators_to_check = [
            op
            for op in statement.condition
            if base_operator(op) != "null" and (accept_negated or not is_negated_operator(op))
        ]

    key_lower = condition_key.lower()

    for op in operators_to_check:
        conditions = statement.condition[op]
        if not isinstance(conditions, dict):
            continue
        actual_key = next((k for k in conditions if k.lower() == key_lower), None)
        if actual_key is None:
            continue
        if expected_value is None:
            return True
        if _value_matches(conditions[actual_key], expected_value):
            return True

    return False

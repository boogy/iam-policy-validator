"""Stable ``finding_key`` digests and severity-aware deduplication for requirement findings."""

import hashlib
from collections.abc import Callable, Hashable
from typing import Any

from iam_validator.core.models import ValidationIssue

PRESENTATION_KEYS = frozenset({"severity", "description", "example", "message"})


def canonical_rule(value: Any) -> Any:
    """Key-order-independent form of a rule, without null keys or the keys that only change how it is reported."""
    if isinstance(value, dict):
        return tuple(
            sorted(
                (repr(k), canonical_rule(v)) for k, v in value.items() if k not in PRESENTATION_KEYS and v is not None
            )
        )
    if isinstance(value, (list, tuple)):
        return tuple(canonical_rule(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted(repr(canonical_rule(v)) for v in value))
    return repr(value)


def unordered(entries: Any) -> list[str]:
    """Order- and duplicate-independent form of ``entries`` (e.g. an ``any_of`` set) for ``rule_key``."""
    return sorted({repr(canonical_rule(e)) for e in entries})


def rule_key(*parts: Any) -> str:
    """A short stable digest of ``parts`` in canonical form, for use as a ``finding_key``."""
    return hashlib.sha256(repr(canonical_rule(parts)).encode()).hexdigest()[:16]


def severity_problem_key(node: dict[str, Any]) -> str:
    """Key-order-independent form of a config node without its presentation keys, identifying an invalid-severity problem."""
    return repr(canonical_rule(node))


def keep_most_severe(
    issues: list[ValidationIssue], key: Callable[[ValidationIssue], Hashable]
) -> list[ValidationIssue]:
    """``issues`` with one per ``key``, the most severe kept, in first-seen order."""
    kept: dict[Hashable, ValidationIssue] = {}
    for issue in issues:
        k = key(issue)
        current = kept.get(k)
        if current is None or issue.get_severity_rank() > current.get_severity_rank():
            kept[k] = issue
    return list(kept.values())

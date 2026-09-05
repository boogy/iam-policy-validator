"""Operator polarity and normalisation shared by condition-requirement checks."""

import pytest

from iam_validator.checks.utils.condition_matching import (
    NEGATED_OPERATORS,
    base_operator,
    has_condition_key,
    is_deny,
    is_negated_operator,
)
from iam_validator.core.condition_validators import CONDITION_OPERATORS
from iam_validator.core.models import Statement


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("StringEquals", "stringequals"),
        ("  StringEquals  ", "stringequals"),
        ("ForAnyValue:StringLike", "stringlike"),
        ("ForAllValues:StringEqualsIfExists", "stringequals"),
        ("StringNotEqualsIfExists", "stringnotequals"),
    ],
)
def test_base_operator_strips_prefix_suffix_and_case(raw, expected):
    assert base_operator(raw) == expected


@pytest.mark.parametrize(
    "operator",
    [
        "StringNotEquals",
        "ArnNotEquals",
        "ArnNotLike",
        "NotIpAddress",
        "StringNotLike",
        "StringNotEqualsIgnoreCase",
        "ForAnyValue:StringNotEquals",
        "NumericNotEquals",
        "DateNotEquals",
    ],
)
def test_negated_operators_are_recognised(operator):
    assert is_negated_operator(operator) is True


@pytest.mark.parametrize("operator", ["StringEquals", "ArnLike", "IpAddress", "Bool", "Null"])
def test_positive_operators_are_not_negated(operator):
    assert is_negated_operator(operator) is False


def test_negated_operators_is_subset_of_known_condition_operators():
    known = {base_operator(op) for op in CONDITION_OPERATORS}
    assert NEGATED_OPERATORS <= known


def test_negated_operator_does_not_satisfy_requirement_on_allow():
    statement = Statement(
        effect="Allow",
        action=["s3:GetObject"],
        resource=["*"],
        condition={"StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}},
    )
    assert has_condition_key(statement, "aws:PrincipalOrgID") is False


def test_positive_operator_satisfies_requirement_on_allow():
    statement = Statement(
        effect="Allow",
        action=["s3:GetObject"],
        resource=["*"],
        condition={"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
    )
    assert has_condition_key(statement, "aws:PrincipalOrgID") is True


def test_negated_operator_satisfies_requirement_on_deny():
    statement = Statement(
        effect="Deny",
        action=["s3:GetObject"],
        resource=["*"],
        condition={"StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}},
    )
    assert has_condition_key(statement, "aws:PrincipalOrgID") is True


def test_null_operator_never_satisfies_requirement():
    statement = Statement(
        effect="Allow",
        action=["s3:GetObject"],
        resource=["*"],
        condition={"Null": {"aws:PrincipalOrgID": "false"}},
    )
    assert has_condition_key(statement, "aws:PrincipalOrgID") is False


def test_explicit_operator_request_is_matched_case_insensitively():
    statement = Statement(
        effect="Allow",
        action=["s3:GetObject"],
        resource=["*"],
        condition={"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
    )
    assert has_condition_key(statement, "aws:principalorgid", operator="stringequals") is True


def test_accept_negated_override_wins_over_effect():
    statement = Statement(
        effect="Allow",
        action=["s3:GetObject"],
        resource=["*"],
        condition={"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/Admin"}},
    )
    assert has_condition_key(statement, "aws:PrincipalArn", accept_negated=True) is True


def test_is_deny_is_case_and_whitespace_insensitive():
    assert is_deny(Statement(effect=" deny ", action=["*"], resource=["*"])) is True
    assert is_deny(Statement(effect="Allow", action=["*"], resource=["*"])) is False

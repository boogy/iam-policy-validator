"""An operator-specific requirement must see through set prefixes and operator casing."""

import pytest

from iam_validator.checks.utils.condition_matching import has_condition_key
from iam_validator.core.models import Statement

KEY = "aws:PrincipalOrgID"


def _statement(condition, effect="Allow") -> Statement:
    return Statement(Effect=effect, Action=["s3:GetObject"], Resource=["*"], Condition=condition)


class TestSetPrefixInThePolicy:
    @pytest.mark.parametrize(
        "policy_operator",
        [
            "StringEquals",
            "stringequals",
            "ForAllValues:StringEquals",
            "ForAnyValue:StringEquals",
            "foranyvalue:stringequals",
        ],
    )
    def test_an_unprefixed_requirement_accepts_any_set_prefix(self, policy_operator):
        statement = _statement({policy_operator: {KEY: "o-abc123"}})

        assert has_condition_key(statement, KEY, "StringEquals", "o-abc123")

    def test_an_unrecognized_prefix_is_not_stripped(self):
        statement = _statement({"NotAPrefix:StringEquals": {KEY: "o-abc123"}})

        assert not has_condition_key(statement, KEY, "StringEquals")


class TestSetPrefixInTheRequirement:
    def test_a_prefixed_requirement_matches_the_same_prefix(self):
        statement = _statement({"ForAnyValue:StringLike": {"aws:ResourceOrgPaths": ["o-a/r-b/*"]}})

        assert has_condition_key(statement, "aws:ResourceOrgPaths", "ForAnyValue:StringLike")

    def test_a_prefixed_requirement_is_not_satisfied_without_the_prefix(self):
        statement = _statement({"StringLike": {"aws:ResourceOrgPaths": ["o-a/r-b/*"]}})

        assert not has_condition_key(statement, "aws:ResourceOrgPaths", "ForAnyValue:StringLike")

    def test_a_prefixed_requirement_is_not_satisfied_by_the_other_set_prefix(self):
        statement = _statement({"ForAllValues:StringLike": {"aws:ResourceOrgPaths": ["o-a/r-b/*"]}})

        assert not has_condition_key(statement, "aws:ResourceOrgPaths", "ForAnyValue:StringLike")

    def test_a_prefixed_requirement_ignores_only_casing(self):
        statement = _statement({"foranyvalue:stringlike": {"aws:ResourceOrgPaths": ["o-a/r-b/*"]}})

        assert has_condition_key(statement, "aws:ResourceOrgPaths", "ForAnyValue:StringLike")


class TestIfExistsStaysDistinct:
    def test_an_ifexists_policy_operator_does_not_satisfy_a_plain_requirement(self):
        statement = _statement({"StringEqualsIfExists": {KEY: "o-abc123"}})

        assert not has_condition_key(statement, KEY, "StringEquals")

    def test_a_plain_policy_operator_does_not_satisfy_an_ifexists_requirement(self):
        statement = _statement({"StringEquals": {KEY: "o-abc123"}})

        assert not has_condition_key(statement, KEY, "StringEqualsIfExists")

    def test_a_prefixed_ifexists_operator_satisfies_an_ifexists_requirement(self):
        statement = _statement({"ForAnyValue:StringEqualsIfExists": {KEY: "o-abc123"}})

        assert has_condition_key(statement, KEY, "StringEqualsIfExists")


class TestOperatorSpecificMatchingStillChecksTheRest:
    def test_a_matching_operator_with_the_wrong_value_does_not_satisfy(self):
        statement = _statement({"ForAnyValue:StringEquals": {KEY: "o-other"}})

        assert not has_condition_key(statement, KEY, "StringEquals", "o-abc123")

    def test_a_matching_operator_without_the_key_does_not_satisfy(self):
        statement = _statement({"ForAnyValue:StringEquals": {"aws:SourceIp": "10.0.0.0/8"}})

        assert not has_condition_key(statement, KEY, "StringEquals")

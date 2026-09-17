"""MFA anti-patterns must be detected through set-operator prefixes and operator casing."""

import pytest

from iam_validator.checks.mfa_condition_check import MFAConditionCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
def check():
    return MFAConditionCheck()


@pytest.fixture
def config():
    return CheckConfig(check_id="mfa_condition_antipattern", enabled=True)


def _statement(condition, effect="Allow") -> Statement:
    return Statement(Effect=effect, Action=["s3:GetObject"], Resource=["*"], Condition=condition)


MFA_KEY = "aws:MultiFactorAuthPresent"


class TestSetPrefixedOperators:
    @pytest.mark.parametrize("operator", ["Bool", "ForAllValues:Bool", "ForAnyValue:Bool", "forallvalues:bool"])
    async def test_bool_false_is_flagged_through_any_set_prefix(self, check, config, operator):
        issues = await check.execute(_statement({operator: {MFA_KEY: "false"}}), 0, None, config)

        assert [i.issue_type for i in issues] == ["mfa_antipattern_bool_false"]

    @pytest.mark.parametrize("operator", ["BoolIfExists", "ForAnyValue:BoolIfExists", "foranyvalue:boolifexists"])
    async def test_bool_if_exists_false_is_flagged_through_any_set_prefix(self, check, config, operator):
        issues = await check.execute(_statement({operator: {MFA_KEY: "false"}}), 0, None, config)

        assert [i.issue_type for i in issues] == ["mfa_antipattern_boolif_exists_false"]

    @pytest.mark.parametrize("operator", ["Null", "ForAnyValue:Null"])
    async def test_null_true_is_flagged_through_any_set_prefix(self, check, config, operator):
        issues = await check.execute(_statement({operator: {MFA_KEY: "true"}}), 0, None, config)

        assert [i.issue_type for i in issues] == ["mfa_antipattern_null_true"]


class TestIfExistsStaysDistinctFromBool:
    async def test_bool_if_exists_is_not_reported_as_bool(self, check, config):
        issues = await check.execute(_statement({"BoolIfExists": {MFA_KEY: "false"}}), 0, None, config)

        assert "mfa_antipattern_bool_false" not in {i.issue_type for i in issues}

    async def test_bool_is_not_reported_as_bool_if_exists(self, check, config):
        issues = await check.execute(_statement({"Bool": {MFA_KEY: "false"}}), 0, None, config)

        assert "mfa_antipattern_boolif_exists_false" not in {i.issue_type for i in issues}

    async def test_bool_if_exists_false_under_deny_stays_unflagged(self, check, config):
        issues = await check.execute(
            _statement({"ForAnyValue:BoolIfExists": {MFA_KEY: "false"}}, effect="Deny"), 0, None, config
        )

        assert issues == []

    async def test_null_if_exists_does_not_match_null(self, check, config):
        issues = await check.execute(_statement({"NullIfExists": {MFA_KEY: "true"}}), 0, None, config)

        assert issues == []


class TestUnrecognizedPrefixIsNotStripped:
    async def test_bogus_prefix_is_not_treated_as_bool(self, check, config):
        issues = await check.execute(_statement({"NotAPrefix:Bool": {MFA_KEY: "false"}}), 0, None, config)

        assert issues == []


class TestMultipleMatchingOperatorBlocks:
    async def test_both_plain_and_prefixed_blocks_are_reported(self, check, config):
        issues = await check.execute(
            _statement({"Bool": {MFA_KEY: "false"}, "ForAnyValue:Bool": {MFA_KEY: "false"}}), 0, None, config
        )

        assert [i.issue_type for i in issues] == ["mfa_antipattern_bool_false"] * 2

    async def test_a_safe_prefixed_block_does_not_mask_an_unsafe_plain_block(self, check, config):
        issues = await check.execute(
            _statement({"Bool": {MFA_KEY: "false"}, "ForAnyValue:Bool": {MFA_KEY: "true"}}), 0, None, config
        )

        assert [i.issue_type for i in issues] == ["mfa_antipattern_bool_false"]

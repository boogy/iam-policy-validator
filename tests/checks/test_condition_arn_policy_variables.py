"""A policy variable in an ARN condition value resolves at request time, so it is not a format error."""

import pytest

from iam_validator.checks.condition_type_mismatch import ConditionTypeMismatchCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.condition_validators import validate_value_for_type
from iam_validator.core.models import Statement


@pytest.fixture
def check():
    return ConditionTypeMismatchCheck()


@pytest.fixture
def config():
    return CheckConfig(check_id="condition_type_mismatch", enabled=True)


POLICY_VARIABLE_ARNS = [
    "${aws:PrincipalArn}",
    "arn:aws:iam::${aws:PrincipalAccount}:role/App",
    "arn:aws:s3:::bucket/${aws:username}/*",
    "${aws:PrincipalArn}/extra",
]


class TestValidateValueForType:
    @pytest.mark.parametrize("value", POLICY_VARIABLE_ARNS)
    def test_a_policy_variable_is_accepted(self, value):
        assert validate_value_for_type("ARN", [value]) == (True, None)

    @pytest.mark.parametrize("value", ["*", "arn:aws:iam::123456789012:role/App"])
    def test_literal_arns_are_still_accepted(self, value):
        assert validate_value_for_type("ARN", [value]) == (True, None)

    @pytest.mark.parametrize("value", ["not-an-arn", "arn:aws:iam", ""])
    def test_a_malformed_literal_is_still_rejected(self, value):
        is_valid, error = validate_value_for_type("ARN", [value])

        assert not is_valid
        assert error

    def test_a_variable_in_one_value_does_not_excuse_a_sibling(self):
        is_valid, _ = validate_value_for_type("ARN", ["${aws:PrincipalArn}", "not-an-arn"])

        assert not is_valid

    @pytest.mark.parametrize(
        ("value_type", "value"),
        [("Bool", "${aws:username}"), ("Date", "${aws:CurrentTime}"), ("Numeric", "${x}")],
    )
    def test_other_types_do_not_gain_variable_tolerance(self, value_type, value):
        is_valid, _ = validate_value_for_type(value_type, [value])

        assert not is_valid


class TestTheCheckDoesNotFlagPolicyVariables:
    @pytest.mark.parametrize("value", POLICY_VARIABLE_ARNS)
    async def test_arn_typed_key_with_a_policy_variable_is_clean(self, check, config, mock_fetcher, value):
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Condition={"ArnLike": {"aws:PrincipalArn": value}},
        )

        issues = await check.execute(statement, 0, mock_fetcher, config)

        assert [i.issue_type for i in issues if i.issue_type == "invalid_value_format"] == []

    async def test_a_malformed_literal_is_still_reported(self, check, config, mock_fetcher):
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Condition={"ArnLike": {"aws:PrincipalArn": "not-an-arn"}},
        )

        issues = await check.execute(statement, 0, mock_fetcher, config)

        assert "invalid_value_format" in {i.issue_type for i in issues}

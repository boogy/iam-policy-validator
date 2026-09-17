"""Dedup against action_condition_enforcement must match the way that check matches actions."""

import pytest

from iam_validator.checks.sensitive_action import SensitiveActionCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement

SENSITIVE_ACTION = "iam:PassRole"


@pytest.fixture
def check():
    return SensitiveActionCheck()


def _config(covered_actions) -> CheckConfig:
    return CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        root_config={
            "action_condition_enforcement": {"requirements": [{"actions": covered_actions, "required_conditions": []}]}
        },
    )


async def _run(check, mock_fetcher, covered_actions, action=SENSITIVE_ACTION):
    statement = Statement(Effect="Allow", Action=[action], Resource=["*"])
    return await check.execute(statement, 0, mock_fetcher, _config(covered_actions))


class TestCoveredActionsSuppressTheFinding:
    @pytest.mark.parametrize(
        "covered",
        [
            [SENSITIVE_ACTION],
            ["iam:Pass*"],
            ["iam:*"],
            ["*"],
            ["iam:passrole"],
            ["s3:GetObject", "iam:Pass*"],
        ],
    )
    async def test_a_requirement_covering_the_action_dedups(self, check, mock_fetcher, covered):
        assert await _run(check, mock_fetcher, covered) == []


class TestUncoveredActionsAreStillFlagged:
    @pytest.mark.parametrize("covered", [[], ["s3:GetObject"], ["iam:CreateUser"], ["ec2:*"]])
    async def test_an_unrelated_requirement_does_not_dedup(self, check, mock_fetcher, covered):
        issues = await _run(check, mock_fetcher, covered)

        assert [i.issue_type for i in issues] == ["missing_condition"]

    async def test_no_ace_config_at_all_still_reports(self, check, mock_fetcher):
        statement = Statement(Effect="Allow", Action=[SENSITIVE_ACTION], Resource=["*"])
        config = CheckConfig(check_id="sensitive_action", enabled=True)

        issues = await check.execute(statement, 0, mock_fetcher, config)

        assert [i.issue_type for i in issues] == ["missing_condition"]

    async def test_a_statement_with_conditions_is_never_flagged(self, check, mock_fetcher):
        statement = Statement(
            Effect="Allow",
            Action=[SENSITIVE_ACTION],
            Resource=["*"],
            Condition={"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
        )

        issues = await check.execute(statement, 0, mock_fetcher, _config([]))

        assert issues == []

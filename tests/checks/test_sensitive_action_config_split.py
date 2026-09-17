"""`sensitive_action.sensitive_actions` is a user-only config key."""

import pytest

from iam_validator.checks.sensitive_action import SensitiveActionCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.config.defaults import get_default_config
from iam_validator.core.models import IAMPolicy, Statement

SECRET_ARN = "arn:aws:secretsmanager:us-east-1:111111111111:secret:foo"


@pytest.fixture
def check():
    return SensitiveActionCheck()


@pytest.fixture
def default_sensitive_action_config():
    return CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config=get_default_config()["sensitive_action"],
    )


def _policy(actions_by_statement: list[list[str]]) -> IAMPolicy:
    statements = [Statement(Effect="Allow", Action=actions, Resource=SECRET_ARN) for actions in actions_by_statement]
    return IAMPolicy(Version="2012-10-17", Statement=statements)


def _combo_issues(issues, *actions):
    return [i for i in issues if all(a in i.message for a in actions)]


class TestDefaultConfigStatementLevelDetection:
    async def test_single_sensitive_action_without_condition_is_flagged(
        self, check, default_sensitive_action_config, mock_fetcher
    ):
        statement = Statement(
            effect="Allow",
            action=["secretsmanager:GetSecretValue"],
            resource=[SECRET_ARN],
        )

        issues = await check.execute(statement, 0, mock_fetcher, default_sensitive_action_config)

        missing_condition = [i for i in issues if i.issue_type == "missing_condition"]
        assert len(missing_condition) == 1

    async def test_default_privesc_combo_still_fires_across_statements(
        self, check, default_sensitive_action_config, mock_fetcher
    ):
        policy = _policy([["iam:CreateUser"], ["iam:AttachUserPolicy"]])

        issues = await check.execute_policy(policy, "test.json", mock_fetcher, default_sensitive_action_config)

        assert _combo_issues(issues, "iam:CreateUser", "iam:AttachUserPolicy")


class TestMergeStrategiesForUserCombos:
    def _config(self, merge_strategy: str) -> CheckConfig:
        return CheckConfig(
            check_id="sensitive_action",
            enabled=True,
            config={
                **get_default_config()["sensitive_action"],
                "merge_strategy": merge_strategy,
                "sensitive_actions": [{"all_of": ["custom:ActionA", "custom:ActionB"]}],
            },
        )

    async def test_append_keeps_user_combo_and_defaults(self, check, mock_fetcher):
        policy = _policy([["custom:ActionA"], ["custom:ActionB"], ["iam:CreateUser"], ["iam:AttachUserPolicy"]])

        issues = await check.execute_policy(policy, "test.json", mock_fetcher, self._config("append"))

        assert _combo_issues(issues, "custom:ActionA", "custom:ActionB")
        assert _combo_issues(issues, "iam:CreateUser", "iam:AttachUserPolicy")

    async def test_user_only_fires_user_combo_but_not_defaults(self, check, mock_fetcher):
        policy = _policy([["custom:ActionA"], ["custom:ActionB"], ["iam:CreateUser"], ["iam:AttachUserPolicy"]])

        issues = await check.execute_policy(policy, "test.json", mock_fetcher, self._config("user_only"))

        assert _combo_issues(issues, "custom:ActionA", "custom:ActionB")
        assert not _combo_issues(issues, "iam:CreateUser", "iam:AttachUserPolicy")

    async def test_defaults_only_ignores_user_combo(self, check, mock_fetcher):
        policy = _policy([["custom:ActionA"], ["custom:ActionB"], ["iam:CreateUser"], ["iam:AttachUserPolicy"]])

        issues = await check.execute_policy(policy, "test.json", mock_fetcher, self._config("defaults_only"))

        assert not _combo_issues(issues, "custom:ActionA", "custom:ActionB")
        assert _combo_issues(issues, "iam:CreateUser", "iam:AttachUserPolicy")

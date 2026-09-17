"""Dedup must track what action_condition_enforcement actually enforces, not what is configured."""

from unittest.mock import AsyncMock

import pytest

from iam_validator.checks.action_condition_enforcement import ActionConditionEnforcementCheck
from iam_validator.checks.sensitive_action import SensitiveActionCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.config.config_loader import ValidatorConfig
from iam_validator.core.models import Statement

PASS_ROLE_REQUIREMENT = {
    "actions": ["iam:PassRole"],
    "required_conditions": [{"condition_key": "iam:PassedToService", "operator": "StringEquals"}],
}


@pytest.fixture
def check():
    return SensitiveActionCheck()


def _config(ace_config):
    return CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        root_config={"action_condition_enforcement": ace_config},
    )


async def _run(check, config, action="iam:PassRole"):
    statement = Statement(Effect="Allow", Action=[action], Resource=["*"])
    fetcher = AsyncMock()
    fetcher.expand_wildcard_action = AsyncMock(return_value=[action])
    return await check.execute(statement, 0, fetcher, config)


class TestSuppressionRequiresActualEnforcement:
    async def test_a_plain_requirement_still_suppresses(self, check):
        config = _config({"requirements": [PASS_ROLE_REQUIREMENT]})

        assert await _run(check, config) == []

    async def test_user_only_drops_defaults_so_nothing_is_suppressed(self, check):
        config = _config(
            {
                "requirements": [PASS_ROLE_REQUIREMENT],
                "merge_strategy": "user_only",
                "action_condition_requirements": [],
            }
        )

        issues = await _run(check, config)

        assert [i.issue_type for i in issues] == ["missing_condition"]

    async def test_replace_all_with_other_actions_does_not_suppress(self, check):
        config = _config(
            {
                "requirements": [PASS_ROLE_REQUIREMENT],
                "merge_strategy": "replace_all",
                "action_condition_requirements": [{"actions": ["s3:GetObject"], "required_conditions": []}],
            }
        )

        issues = await _run(check, config)

        assert [i.issue_type for i in issues] == ["missing_condition"]

    async def test_a_disabled_enforcement_check_suppresses_nothing(self, check):
        config = _config({"enabled": False, "requirements": [PASS_ROLE_REQUIREMENT]})

        issues = await _run(check, config)

        assert [i.issue_type for i in issues] == ["missing_condition"]

    async def test_a_user_requirement_also_suppresses(self, check):
        config = _config(
            {
                "requirements": [],
                "action_condition_requirements": [PASS_ROLE_REQUIREMENT],
            }
        )

        assert await _run(check, config) == []

    async def test_a_filepath_scoped_requirement_does_not_suppress(self, check):
        config = _config(
            {
                "requirements": [],
                "action_condition_requirements": [{**PASS_ROLE_REQUIREMENT, "ignore_patterns": [{"filepath": ".*"}]}],
            }
        )

        issues = await _run(check, config)

        assert [i.issue_type for i in issues] == ["missing_condition"]


class TestEnforcedActions:
    def test_it_reads_a_checks_nested_config(self):
        root = {"checks": {"action_condition_enforcement": {"requirements": [PASS_ROLE_REQUIREMENT]}}}

        assert ActionConditionEnforcementCheck.enforced_actions(root) == {"iam:PassRole"}

    def test_a_checks_key_wins_over_a_top_level_key(self):
        root = {
            "checks": {},
            "action_condition_enforcement": {"requirements": [PASS_ROLE_REQUIREMENT]},
        }

        assert ActionConditionEnforcementCheck.enforced_actions(root) == set()

    def test_a_suffixed_top_level_key_is_read(self):
        root = {"action_condition_enforcement_check": {"requirements": [PASS_ROLE_REQUIREMENT]}}

        assert ActionConditionEnforcementCheck.enforced_actions(root) == {"iam:PassRole"}

    def test_key_precedence_matches_validator_config(self):
        """Both spellings present: whichever `ValidatorConfig` picks is the one enforced."""
        root = {
            "action_condition_enforcement": {"requirements": [{"actions": ["s3:GetObject"]}]},
            "action_condition_enforcement_check": {"requirements": [PASS_ROLE_REQUIREMENT]},
        }
        loaded = ValidatorConfig(config_dict=dict(root), use_defaults=False).get_check_config(
            ActionConditionEnforcementCheck.check_id
        )
        expected = {action for requirement in loaded["requirements"] for action in requirement["actions"]}

        assert ActionConditionEnforcementCheck.enforced_actions(root) == expected

    def test_a_string_actions_value_is_accepted(self):
        root = {"action_condition_enforcement": {"requirements": [{"actions": "iam:PassRole"}]}}

        assert ActionConditionEnforcementCheck.enforced_actions(root) == {"iam:PassRole"}

    def test_an_empty_config_enforces_nothing(self):
        assert ActionConditionEnforcementCheck.enforced_actions({}) == set()

    def test_a_named_file_resolves_ignore_patterns_instead_of_assuming_them(self):
        root = {
            "action_condition_enforcement": {
                "requirements": [],
                "action_condition_requirements": [
                    {**PASS_ROLE_REQUIREMENT, "ignore_patterns": [{"filepath": "^tests/"}]}
                ],
            }
        }

        assert ActionConditionEnforcementCheck.enforced_actions(root, "prod/policy.json") == {"iam:PassRole"}
        assert ActionConditionEnforcementCheck.enforced_actions(root, "tests/policy.json") == set()

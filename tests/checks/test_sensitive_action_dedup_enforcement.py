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

    @pytest.mark.parametrize("actions", [{"any_of": ["iam:PassRole"]}, {"all_of": ["iam:PassRole"]}])
    async def test_a_mapping_form_requirement_suppresses(self, check, actions):
        requirement = {**PASS_ROLE_REQUIREMENT, "actions": actions}
        config = _config({"merge_strategy": "user_only", "action_condition_requirements": [requirement]})

        assert await _run(check, config) == []

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

    @pytest.mark.parametrize(
        "required_conditions",
        [
            {"none_of": [{"condition_key": "aws:SourceIp"}]},
            {"all_of": [], "none_of": [{"condition_key": "aws:SourceIp"}]},
        ],
    )
    def test_a_none_of_only_requirement_enforces_nothing(self, required_conditions):
        requirement = {"actions": ["iam:PassRole"], "required_conditions": required_conditions}
        root = {
            "action_condition_enforcement": {
                "merge_strategy": "user_only",
                "action_condition_requirements": [requirement],
            }
        }

        assert ActionConditionEnforcementCheck.enforced_actions(root) == set()

    def test_a_none_of_only_if_branch_enforces_nothing(self):
        branch = {"required_conditions": {"none_of": [{"condition_key": "aws:SourceIp"}]}}
        requirement = {"actions": ["iam:PassRole"], "if": [branch]}
        root = {
            "action_condition_enforcement": {
                "merge_strategy": "user_only",
                "action_condition_requirements": [requirement],
            }
        }

        assert ActionConditionEnforcementCheck.enforced_actions(root) == set()

    def test_a_none_of_requirement_with_any_of_still_enforces(self):
        required_conditions = {
            "any_of": [{"condition_key": "iam:PassedToService"}],
            "none_of": [{"condition_key": "aws:SourceIp"}],
        }
        requirement = {"actions": ["iam:PassRole"], "required_conditions": required_conditions}
        root = {
            "action_condition_enforcement": {
                "merge_strategy": "user_only",
                "action_condition_requirements": [requirement],
            }
        }

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


class TestCoverageTracksTheLiveConfig:
    async def test_a_new_root_config_is_recomputed(self, check):
        assert await _run(check, _config({"requirements": [PASS_ROLE_REQUIREMENT]})) == []

        issues = await _run(check, _config({"enabled": False, "requirements": [PASS_ROLE_REQUIREMENT]}))

        assert [i.issue_type for i in issues] == ["missing_condition"]

    async def test_a_requirement_added_in_place_is_seen(self, check):
        requirements: list = []
        config = _config({"requirements": requirements})
        assert [i.issue_type for i in await _run(check, config)] == ["missing_condition"]

        requirements.append(PASS_ROLE_REQUIREMENT)

        assert await _run(check, config) == []


class TestMalformedRequirementListsDoNotCrash:
    @pytest.mark.parametrize("key", ["requirements", "policy_level_requirements", "action_condition_requirements"])
    @pytest.mark.parametrize("value", [["iam:PassRole", 5], {"actions": ["iam:PassRole"]}, "iam:PassRole", 5])
    async def test_malformed_entries_are_dropped(self, check, key, value):
        config = _config({"requirements": [PASS_ROLE_REQUIREMENT], key: value})

        issues = await _run(check, config)

        expected = ["missing_condition"] if key == "requirements" else []
        assert [i.issue_type for i in issues] == expected

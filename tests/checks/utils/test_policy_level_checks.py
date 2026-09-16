"""Cross-statement `all_of` combo matching (`check_policy_level_actions`).

Covers case-insensitivity and count-vs-coverage correctness for both the
exact-action (`sensitive_actions`) and regex (`sensitive_action_patterns`)
branches.
"""

import logging

import pytest

from iam_validator.checks.utils.policy_level_checks import check_policy_level_actions
from iam_validator.core.check_registry import CheckConfig


@pytest.fixture
def config():
    return CheckConfig(check_id="sensitive_action", enabled=True)


def _severity(_config: CheckConfig) -> str:
    return "high"


def _combo(all_of: list[str]) -> dict:
    return {"all_of": all_of}


class TestActionsAllOfCaseInsensitivity:
    def test_lowercase_actions_satisfy_the_combo(self, config):
        all_actions = ["iam:createuser", "iam:attachuserpolicy"]
        statement_map = {
            "iam:createuser": [(0, None)],
            "iam:attachuserpolicy": [(1, None)],
        }
        combo = _combo(["iam:CreateUser", "iam:AttachUserPolicy"])

        issues = check_policy_level_actions(all_actions, statement_map, combo, config, "actions", _severity)

        assert len(issues) == 1
        assert issues[0].issue_type == "privilege_escalation"

    def test_two_case_variants_of_one_action_do_not_satisfy_a_two_action_combo(self, config):
        all_actions = ["iam:CreateUser", "iam:createuser"]
        statement_map = {
            "iam:CreateUser": [(0, None)],
            "iam:createuser": [(1, None)],
        }
        combo = _combo(["iam:CreateUser", "iam:AttachUserPolicy"])

        issues = check_policy_level_actions(all_actions, statement_map, combo, config, "actions", _severity)

        assert issues == []

    def test_matched_actions_deduplicated_preserving_order(self, config):
        all_actions = ["iam:CreateUser", "iam:AttachUserPolicy"]
        statement_map = {
            "iam:CreateUser": [(0, None)],
            "iam:AttachUserPolicy": [(1, None)],
        }
        combo = _combo(["iam:Create*", "iam:CreateUser", "iam:AttachUserPolicy"])

        issues = check_policy_level_actions(all_actions, statement_map, combo, config, "actions", _severity)

        assert len(issues) == 1
        action_list = issues[0].message.split("[")[1].split("]")[0]
        assert action_list.count("iam:CreateUser") == 1


class TestPatternsAllOfCaseInsensitivity:
    def test_lowercase_action_matches_pattern_combo(self, config):
        all_actions = ["iam:createuser", "iam:attachuserpolicy"]
        statement_map = {
            "iam:createuser": [(0, None)],
            "iam:attachuserpolicy": [(1, None)],
        }
        combo = _combo(["^iam:Create.*", "^iam:Attach.*"])

        issues = check_policy_level_actions(all_actions, statement_map, combo, config, "patterns", _severity)

        assert len(issues) == 1

    def test_invalid_regex_is_logged_with_source_and_never_matches(self, config, caplog):
        all_actions = ["iam:createuser", "iam:attachuserpolicy"]
        statement_map = {
            "iam:createuser": [(0, None)],
            "iam:attachuserpolicy": [(1, None)],
        }
        combo = _combo(["^iam:Create[", "^iam:Attach.*"])

        with caplog.at_level(logging.WARNING):
            issues = check_policy_level_actions(all_actions, statement_map, combo, config, "patterns", _severity)

        assert issues == []
        assert any(
            "sensitive_action_patterns" in record.message and "^iam:Create[" in record.message
            for record in caplog.records
        )

    def test_matched_actions_deduplicated_when_two_patterns_match_the_same_action(self, config):
        all_actions = ["iam:createuser"]
        statement_map = {"iam:createuser": [(0, None)]}
        combo = _combo(["^iam:Create.*", "^iam:.*User$"])

        issues = check_policy_level_actions(all_actions, statement_map, combo, config, "patterns", _severity)

        assert len(issues) == 1
        action_list = issues[0].message.split("[")[1].split("]")[0]
        assert action_list.count("iam:createuser") == 1


def test_returns_empty_when_actions_string_case_differs_only_by_count_not_coverage(config):
    all_actions = ["s3:GetObject", "s3:getobject"]
    statement_map = {
        "s3:GetObject": [(0, None)],
        "s3:getobject": [(1, None)],
    }
    combo = _combo(["s3:GetObject", "s3:PutObject"])

    issues = check_policy_level_actions(all_actions, statement_map, combo, config, "actions", _severity)

    assert issues == []

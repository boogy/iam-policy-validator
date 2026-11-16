"""Malformed `action_condition_requirements` config is reported once per policy and never crashes the check."""

from typing import Any

import pytest

from iam_validator.checks.action_condition_enforcement import ActionConditionEnforcementCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement

ACTION = "iam:PassRole"
KEY = "aws:SourceVpc"


@pytest.fixture
def check() -> ActionConditionEnforcementCheck:
    return ActionConditionEnforcementCheck()


def _config(*requirements: dict[str, Any]) -> CheckConfig:
    return CheckConfig(
        check_id="action_condition_enforcement",
        enabled=True,
        config={"merge_strategy": "user_only", "action_condition_requirements": list(requirements)},
    )


def _stmt(sid: str, action: str = ACTION, effect: str = "Allow", condition: dict | None = None) -> Statement:
    return Statement(sid=sid, effect=effect, action=action, resource="*", condition=condition)


async def _run(check, config, *statements: Statement):
    policy = IAMPolicy(version="2012-10-17", statement=list(statements or [_stmt("One")]))
    return await check.execute_policy(policy, "policy.json", None, config)


def _types(issues) -> list[tuple[str, int]]:
    return sorted((i.issue_type, i.statement_index) for i in issues)


class TestNullRequirementSeverity:
    @pytest.mark.parametrize(
        ("actions", "issue_type"),
        [([ACTION], "action_detected"), ({"none_of": [ACTION]}, "forbidden_action")],
    )
    async def test_detection_only_falls_back_to_check_severity(self, check, actions, issue_type):
        issues = await _run(check, _config({"actions": actions, "severity": None}))

        assert [(i.issue_type, i.severity) for i in issues] == [(issue_type, "high")]

    async def test_policy_wide_detection_falls_back_to_check_severity(self, check):
        issues = await _run(check, _config({"actions": {"any_of": [ACTION]}, "severity": None}))

        assert [(i.issue_type, i.severity) for i in issues] == [("action_detected", "high")]


class TestNullActionGroup:
    @pytest.mark.parametrize("required_conditions", [None, [{"condition_key": KEY}]])
    async def test_null_group_beside_a_list_is_empty(self, check, required_conditions):
        requirement = {"actions": {"any_of": [ACTION], "all_of": None}, "required_conditions": required_conditions}

        issues = await _run(check, _config(requirement))

        assert [i.issue_type for i in issues] in (["action_detected"], ["missing_required_condition"])


class TestInvalidEntrySeverity:
    @pytest.mark.parametrize(
        "required_conditions",
        [
            [{"condition_key": KEY, "severity": "urgent"}],
            {"all_of": [{"condition_key": KEY, "severity": "urgent"}]},
            [{"all_of": [{"condition_key": KEY, "severity": "urgent"}]}],
        ],
    )
    async def test_reported_once_and_entry_still_enforced(self, check, required_conditions):
        config = _config({"actions": [ACTION], "severity": "low", "required_conditions": required_conditions})

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert [(i.statement_index, i.severity) for i in invalid] == [(-1, "error")]
        assert "urgent" in invalid[0].message
        missing = [i for i in issues if i.issue_type == "missing_required_condition"]
        assert [(i.statement_index, i.severity) for i in missing] == [(0, "low"), (1, "low")]

    async def test_any_of_entry_still_enforced(self, check):
        config = _config(
            {"actions": [ACTION], "required_conditions": {"any_of": [{"condition_key": KEY, "severity": 5}]}}
        )

        issues = await _run(check, config)

        assert _types(issues) == [("invalid_condition_requirement", -1), ("missing_required_condition_any_of", 0)]


class TestInvalidBranchSeverity:
    async def test_reported_once_and_branch_still_enforced(self, check):
        config = _config(
            {
                "actions": [ACTION],
                "severity": "low",
                "if": [{"severity": "urgent", "required_conditions": [{"condition_key": KEY}]}],
            }
        )

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len(invalid) == 1
        assert invalid[0].statement_index == -1
        assert "if[0]" in invalid[0].message
        missing = [i for i in issues if i.issue_type == "missing_required_condition"]
        assert [(i.statement_index, i.severity) for i in missing] == [(0, "low"), (1, "low")]

    async def test_invalid_entry_severity_in_branch_is_reported_once(self, check):
        branch = {"required_conditions": {"all_of": [{"condition_key": KEY, "severity": "urgent"}]}}
        config = _config({"actions": [ACTION], "if": [branch]})

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        assert _types(issues) == [
            ("invalid_condition_requirement", -1),
            ("missing_required_condition", 0),
            ("missing_required_condition", 1),
        ]

    def test_branch_with_invalid_severity_counts_as_enforced(self):
        root = {
            "action_condition_enforcement": {
                "action_condition_requirements": [
                    {
                        "actions": [ACTION],
                        "if": [{"severity": "urgent", "required_conditions": [{"condition_key": KEY}]}],
                    }
                ]
            }
        }

        assert ACTION in ActionConditionEnforcementCheck.enforced_actions(root)


class TestMalformedConfigReportedOncePerPolicy:
    @pytest.mark.parametrize(
        "required_conditions",
        [
            "aws:SourceIp",
            {"allof": [{"condition_key": KEY}]},
            {"all_of": "aws:SourceIp"},
            ["x"],
            [{"condition_key": 5}],
            [{"description": "no key"}],
            {"any_of": [{"conditon_key": KEY}]},
        ],
    )
    @pytest.mark.parametrize("actions", [[ACTION], {"any_of": [ACTION]}])
    async def test_not_per_statement(self, check, required_conditions, actions):
        config = _config({"actions": actions, "required_conditions": required_conditions})

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        assert _types(issues) == [("invalid_condition_requirement", -1)]
        assert issues[0].statement_sid is None
        assert ACTION in issues[0].message
        assert issues[0].action == ACTION

    async def test_valid_sibling_is_still_enforced(self, check):
        config = _config({"actions": [ACTION], "required_conditions": ["x", {"condition_key": KEY}]})

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        assert _types(issues) == [
            ("invalid_condition_requirement", -1),
            ("missing_required_condition", 0),
            ("missing_required_condition", 1),
        ]

    async def test_malformed_branch_entry_is_reported_once(self, check):
        config = _config({"actions": [ACTION], "if": [{"required_conditions": ["x", {"condition_key": KEY}]}]})

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        assert _types(issues) == [
            ("invalid_condition_requirement", -1),
            ("missing_required_condition", 0),
            ("missing_required_condition", 1),
        ]

    async def test_reported_on_every_policy_sharing_the_config(self, check):
        config = _config(
            {"actions": [ACTION], "severity": "urgent", "required_conditions": [{"condition_key": KEY, "severity": 1}]}
        )

        for _ in range(2):
            issues = await _run(check, config)
            assert [i.issue_type for i in issues].count("invalid_condition_requirement") == 2


class TestNestedNullOverride:
    async def test_null_leaf_severity_and_example_inherit_from_enclosing_entry(self, check):
        entry = {
            "severity": "critical",
            "example": "EX",
            "all_of": [{"condition_key": KEY, "severity": None, "example": None}],
        }
        config = _config({"actions": [ACTION], "required_conditions": [entry]})

        issues = await _run(check, config)

        assert [(i.issue_type, i.severity, i.example) for i in issues] == [
            ("missing_required_condition", "critical", "EX")
        ]

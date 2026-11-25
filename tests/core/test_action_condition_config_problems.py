"""Malformed `action_condition_requirements` config is reported once per policy and never crashes the check."""

from typing import Any

import pytest

from iam_validator.checks.action_condition_enforcement import ActionConditionEnforcementCheck
from iam_validator.checks.utils.finding_identity import rule_key, unordered
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.finding_fingerprint import compute_finding_hash
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


class TestPolicyLevelFindingIdentity:
    async def test_config_problems_of_one_requirement_have_distinct_ids(self, check):
        config = _config(
            {"actions": [ACTION], "severity": "urgent", "required_conditions": [{"condition_key": KEY, "severity": 1}]}
        )

        issues = await _run(check, config)

        ids = {
            compute_finding_hash(
                "policy.json",
                "action_condition_enforcement",
                i.issue_type,
                i.statement_sid,
                i.statement_index,
                i.action,
                i.resource,
                i.condition_key,
                i.finding_key,
            )
            for i in issues
        }
        assert len(issues) >= 2
        assert len(ids) == len(issues)

    async def test_config_problem_id_does_not_depend_on_message_wording(self, check, monkeypatch):
        config = _config({"actions": [ACTION], "severity": "urgent", "required_conditions": [{"condition_key": KEY}]})
        before = [i.finding_key for i in await _run(check, config)]
        monkeypatch.setattr(
            ActionConditionEnforcementCheck, "_actions_label", lambda self, requirement: ("`reworded`", ACTION)
        )

        after = await _run(check, config)

        assert "reworded" in after[0].message
        assert [i.finding_key for i in after] == before


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


def _root(*requirements: dict[str, Any]) -> dict[str, Any]:
    return {
        "action_condition_enforcement": {
            "merge_strategy": "user_only",
            "action_condition_requirements": list(requirements),
        }
    }


class TestEnforcedActionsNeedAnEvaluableEntry:
    @pytest.mark.parametrize(
        "required_conditions",
        [
            {"allof": [{"condition_key": KEY}]},
            {"all_of": "aws:SourceIp"},
            [{"condition_key": 5}],
            [{"description": "no key"}],
            [{"condition_key": KEY, "operator": 5}],
            {"any_of": [{"conditon_key": KEY}]},
            [{"all_of": []}],
        ],
    )
    def test_requirement_without_evaluable_entry_is_not_enforced(self, required_conditions):
        root = _root({"actions": [ACTION], "required_conditions": required_conditions})

        assert ActionConditionEnforcementCheck.enforced_actions(root) == set()

    def test_if_branch_without_evaluable_entry_is_not_enforced(self):
        root = _root({"actions": [ACTION], "if": [{"required_conditions": [{"description": "no key"}]}]})

        assert ActionConditionEnforcementCheck.enforced_actions(root) == set()

    def test_one_evaluable_entry_is_enough(self):
        root = _root({"actions": [ACTION], "required_conditions": ["x", {"condition_key": KEY}]})

        assert ActionConditionEnforcementCheck.enforced_actions(root) == {ACTION}

    @pytest.mark.parametrize(
        ("actions", "expected"),
        [
            ({"any_of": [ACTION, None]}, {ACTION}),
            ({"all_of": [ACTION, "iam:CreateRole"]}, set()),
            ({"all_of": [ACTION]}, {ACTION}),
            ({"any_of": ["iam:CreateRole"], "all_of": [ACTION]}, {"iam:CreateRole", ACTION}),
            ({"any_of": [ACTION], "all_of": ["iam:CreateRole", "iam:DeleteRole"]}, {ACTION}),
            ({"none_of": [ACTION]}, set()),
        ],
    )
    def test_mapping_actions_count_any_of_and_single_all_of(self, actions, expected):
        root = _root({"actions": actions, "required_conditions": [{"condition_key": KEY}]})

        assert ActionConditionEnforcementCheck.enforced_actions(root) == expected


class TestConfigProblemsNeedAMatchingStatement:
    @pytest.mark.parametrize(
        "requirement",
        [
            {"actions": [ACTION], "required_conditions": ["x"]},
            {"actions": [ACTION], "severity": "urgent", "required_conditions": [{"condition_key": KEY}]},
            {"actions": {"any_of": [ACTION]}, "required_conditions": {"allof": []}},
            {"actions": [ACTION], "if": [{"required_conditions": "x"}]},
            {"actions": [ACTION], "if": [{"severity": "urgent", "required_conditions": [{"condition_key": KEY}]}]},
        ],
    )
    async def test_not_reported_for_a_policy_without_the_action(self, check, requirement):
        issues = await _run(check, _config(requirement), _stmt("One", action="s3:GetObject"))

        assert issues == []

    async def test_reported_when_a_deny_statement_matches(self, check):
        config = _config({"actions": [ACTION], "required_conditions": ["x"]})

        issues = await _run(check, config, _stmt("One", effect="Deny"))

        assert _types(issues) == [("invalid_condition_requirement", -1)]


class TestConfigProblemsIgnoreRequirementIgnorePatterns:
    @pytest.mark.parametrize(
        "ignore_patterns",
        [[{"action": "iam:.*"}], [{"filepath_regex": "policy"}]],
    )
    async def test_config_problem_is_not_hidden(self, check, ignore_patterns):
        requirement = {
            "actions": [ACTION],
            "severity": "urgent",
            "required_conditions": ["x"],
            "ignore_patterns": ignore_patterns,
        }
        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={"merge_strategy": "append", "requirements": [requirement]},
        )

        issues = await _run(check, config)

        assert _types(issues) == [("invalid_condition_requirement", -1)] * 2

    async def test_malformed_branch_is_not_hidden(self, check):
        requirement = {
            "actions": [ACTION],
            "ignore_patterns": [{"action": ACTION}],
            "if": [{"effect": "Nope", "required_conditions": [{"condition_key": KEY}]}],
        }

        issues = await _run(check, _config(requirement))

        assert _types(issues) == [("invalid_condition_requirement", -1)]


class TestMalformedMessages:
    async def test_non_list_group_names_required_conditions(self, check):
        config = _config({"actions": [ACTION], "required_conditions": {"all_of": "x"}})

        issues = await _run(check, config)

        assert "`required_conditions.all_of` must be a list" in issues[0].message

    async def test_malformed_nested_all_of_is_described(self, check):
        config = _config({"actions": [ACTION], "required_conditions": [{"all_of": [{"description": "x"}]}]})

        issues = await _run(check, config)

        assert "has an empty, non-list or malformed nested `all_of`" in issues[0].message
        assert issues[0].suggestion == "Give `all_of` a non-empty list of entries, each with a string `condition_key`."


class TestMalformedActions:
    @pytest.mark.parametrize(
        ("actions", "fragment"),
        [
            ({"allof": [ACTION]}, "`actions.allof` is not"),
            ({"all_of": ACTION}, "`actions.all_of` must be a list"),
            (5, "`actions` must be"),
        ],
    )
    async def test_reported_once_per_policy(self, check, actions, fragment):
        config = _config({"actions": actions, "required_conditions": [{"condition_key": KEY}]})

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        assert _types(issues) == [("invalid_condition_requirement", -1)]
        assert fragment in issues[0].message

    async def test_unknown_group_beside_a_valid_one_is_reported_and_valid_one_enforced(self, check):
        config = _config(
            {"actions": {"any_of": [ACTION], "nonof": [ACTION]}, "required_conditions": [{"condition_key": KEY}]}
        )

        issues = await _run(check, config)

        assert _types(issues) == [("invalid_condition_requirement", -1), ("missing_required_condition", 0)]

    @pytest.mark.parametrize("actions", [{"allof": [ACTION]}, {"all_of": ACTION}])
    async def test_not_reported_for_a_policy_without_the_named_action(self, check, actions):
        config = _config({"actions": actions, "required_conditions": [{"condition_key": KEY}]})

        assert await _run(check, config, _stmt("One", action="s3:GetObject")) == []

    async def test_unsalvageable_actions_are_reported_for_any_policy(self, check):
        config = _config({"actions": 5, "required_conditions": [{"condition_key": KEY}]})

        issues = await _run(check, config, _stmt("One", action="s3:GetObject"))

        assert _types(issues) == [("invalid_condition_requirement", -1)]

    @pytest.mark.parametrize("actions", [{"allof": [ACTION]}, {"all_of": ACTION}, 5])
    def test_malformed_actions_are_not_enforced(self, actions):
        root = _root({"actions": actions, "required_conditions": [{"condition_key": KEY}]})

        assert ActionConditionEnforcementCheck.enforced_actions(root) == set()

    async def test_bare_string_actions_still_enforced(self, check):
        config = _config({"actions": ACTION, "required_conditions": [{"condition_key": KEY}]})

        issues = await _run(check, config)

        assert _types(issues) == [("missing_required_condition", 0)]
        assert ActionConditionEnforcementCheck.enforced_actions(
            _root({"actions": ACTION, "required_conditions": [{"condition_key": KEY}]})
        ) == {ACTION}


class TestActionPatternsShape:
    async def test_bare_string_pattern_matches_like_a_list(self, check):
        requirement = {"actions": [], "action_patterns": "^iam:Pass.*", "required_conditions": [{"condition_key": KEY}]}

        unrelated = await _run(check, _config(requirement), _stmt("One", action="s3:GetObject"))
        matching = await _run(check, _config(requirement))

        assert unrelated == []
        assert _types(matching) == [("missing_required_condition", 0)]

    @pytest.mark.parametrize("effect", ["Allow", "Deny"])
    async def test_config_problem_is_reported_for_a_not_action_statement(self, check, effect):
        requirement = {
            "actions": [],
            "action_patterns": ["^iam:Pass.*"],
            "required_conditions": [{"condition_key": KEY, "operator": 5}],
        }
        statement = Statement(Effect=effect, NotAction=["s3:*"], Resource=["*"])

        issues = await _run(check, _config(requirement), statement)

        assert ("invalid_condition_requirement", -1) in _types(issues)

    async def test_pattern_only_requirement_fires_on_a_full_wildcard(self, check):
        requirement = {
            "actions": [],
            "action_patterns": ["^iam:PassRole$"],
            "required_conditions": [{"condition_key": KEY}],
        }

        issues = await _run(check, _config(requirement), _stmt("All", action="*"))

        assert _types(issues) == [("missing_required_condition", 0)]

    @pytest.mark.parametrize("patterns", [5, {"a": "^iam:.*"}, [5, "^iam:Pass.*"]])
    async def test_non_string_patterns_are_reported_and_dropped(self, check, patterns):
        requirement = {
            "actions": [ACTION],
            "action_patterns": patterns,
            "required_conditions": [{"condition_key": KEY}],
        }

        issues = await _run(check, _config(requirement))

        assert _types(issues) == [("invalid_condition_requirement", -1), ("missing_required_condition", 0)]

    async def test_uncompilable_pattern_is_reported_and_dropped(self, check):
        requirement = {
            "actions": [],
            "action_patterns": ["^iam:(Create", "^iam:Pass.*"],
            "required_conditions": [{"condition_key": KEY}],
        }

        issues = await _run(check, _config(requirement))

        assert _types(issues) == [("invalid_condition_requirement", -1), ("missing_required_condition", 0)]
        assert "not a valid regex" in issues[0].message

    @pytest.mark.parametrize("branched", [False, True])
    async def test_pattern_does_not_fill_every_all_of_slot(self, check, branched):
        conditions = [{"condition_key": KEY}]
        requirement: dict[str, Any] = {
            "actions": {"all_of": [ACTION, "iam:CreateRole"]},
            "action_patterns": ["^iam:Pass.*"],
        }
        requirement.update(
            {"if": [{"required_conditions": conditions}]} if branched else {"required_conditions": conditions}
        )

        only_pass = await _run(check, _config(requirement))
        both = await _run(check, _config(requirement), _multi("Both", ACTION, "iam:CreateRole"))

        assert only_pass == []
        assert [i.issue_type for i in both] == ["missing_required_condition"]


class TestNullOperator:
    async def test_example_renders_default_operator(self, check):
        config = _config({"actions": [ACTION], "required_conditions": [{"condition_key": KEY, "operator": None}]})

        issues = await _run(check, config)

        assert [i.issue_type for i in issues] == ["missing_required_condition"]
        assert '"StringEquals"' in issues[0].example
        assert "None" not in issues[0].example


class TestNonStringActionElements:
    @pytest.mark.parametrize(
        "actions",
        [[None], [ACTION, 5], {"any_of": [ACTION, 5]}, {"all_of": [None]}, {"none_of": [ACTION, {"x": 1}]}],
    )
    async def test_reported_once_without_crashing(self, check, actions):
        config = _config({"actions": actions, "required_conditions": [{"condition_key": KEY}]})

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert [(i.statement_index, i.severity) for i in invalid] == [(-1, "error")]
        assert "must be an action string" in invalid[0].message

    @pytest.mark.parametrize("actions", [[ACTION, 5], {"any_of": [ACTION, 5]}])
    async def test_string_elements_still_enforced(self, check, actions):
        config = _config({"actions": actions, "required_conditions": [{"condition_key": KEY}]})

        issues = await _run(check, config)

        assert _types(issues) == [("invalid_condition_requirement", -1), ("missing_required_condition", 0)]

    def test_only_string_elements_are_enforced(self):
        root = _root({"actions": [ACTION, 5], "required_conditions": [{"condition_key": KEY}]})

        assert ActionConditionEnforcementCheck.enforced_actions(root) == {ACTION}

    async def test_unhashable_element_is_reported_under_per_action_override(self, check):
        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "merge_strategy": "per_action_override",
                "action_condition_requirements": [
                    {"actions": [ACTION, ["nested"]], "required_conditions": [{"condition_key": KEY}]}
                ],
            },
        )

        issues = await _run(check, config)

        assert ("invalid_condition_requirement", -1) in _types(issues)


def _override_merge(check, user_actions):
    default = {"actions": [ACTION], "required_conditions": [{"condition_key": "iam:PassedToService"}]}
    user = {"actions": user_actions, "required_conditions": [{"condition_key": KEY}]}
    config = CheckConfig(
        check_id="action_condition_enforcement",
        enabled=True,
        config={
            "merge_strategy": "per_action_override",
            "requirements": [default],
            "action_condition_requirements": [user],
        },
    )
    return default, check._get_merged_requirements(config, "policy.json")


class TestPerActionOverrideMappingActions:
    @pytest.mark.parametrize("group", ["any_of", "all_of"])
    async def test_a_mapping_requirement_replaces_the_default(self, check, group):
        default, merged = _override_merge(check, {group: [ACTION]})

        assert default not in merged

    @pytest.mark.parametrize(
        "user_actions",
        [
            {"all_of": [ACTION], "any_of": ["ec2:RunInstances"]},
            {"any_of": [ACTION], "all_of": ["ec2:RunInstances"]},
            {"any_of": [ACTION], "all_of": ["s3:GetObject", "s3:PutObject"]},
        ],
    )
    async def test_each_group_of_a_two_group_rule_replaces_the_default(self, check, user_actions):
        default, merged = _override_merge(check, user_actions)

        assert default not in merged


class TestTwoGroupActionsOwnership:
    REQUIREMENT: dict[str, Any] = {
        "actions": {"all_of": ["s3:GetObject", "s3:PutObject"], "any_of": [ACTION]},
        "required_conditions": [{"condition_key": KEY}],
    }

    async def test_any_of_group_is_enforced_alone(self, check):
        issues = await _run(check, _config(self.REQUIREMENT))

        assert [i.issue_type for i in issues] == ["missing_required_condition"]

    def test_enforced_actions_match_what_is_enforced(self):
        root = {"action_condition_enforcement": {"action_condition_requirements": [self.REQUIREMENT]}}

        assert ACTION in ActionConditionEnforcementCheck.enforced_actions(root)

    @pytest.mark.parametrize(
        "user_actions",
        [
            {"all_of": [ACTION, "lambda:CreateFunction"]},
            {"none_of": [ACTION]},
            {"all_of": [ACTION, "lambda:CreateFunction"], "any_of": ["ec2:RunInstances"]},
        ],
    )
    async def test_narrower_or_forbid_rule_keeps_the_default(self, check, user_actions):
        default, merged = _override_merge(check, user_actions)

        assert default in merged


class TestPerActionOverrideMatching:
    @pytest.mark.parametrize("user_action", [ACTION.upper(), ACTION.split(":")[0] + ":*"])
    async def test_user_pattern_covering_the_default_action_replaces_it(self, check, user_action):
        default, merged = _override_merge(check, [user_action])

        assert default not in merged

    @pytest.mark.parametrize(
        "branch",
        [{"effect": "Deny"}, {"resource": "arn:aws:iam::*:role/admin/*"}],
    )
    async def test_user_rule_scoped_by_if_keeps_the_default(self, check, branch):
        default = {"actions": [ACTION], "required_conditions": [{"condition_key": "iam:PassedToService"}]}
        user = {"actions": [ACTION], "if": [{**branch, "required_conditions": [{"condition_key": KEY}]}]}
        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "merge_strategy": "per_action_override",
                "requirements": [default],
                "action_condition_requirements": [user],
            },
        )

        assert default in check._get_merged_requirements(config, "policy.json")

    async def test_mapping_form_default_is_replaced(self, check):
        default = {"actions": {"any_of": [ACTION]}, "required_conditions": [{"condition_key": "iam:PassedToService"}]}
        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "merge_strategy": "per_action_override",
                "requirements": [default],
                "action_condition_requirements": [
                    {"actions": [ACTION], "required_conditions": [{"condition_key": KEY}]}
                ],
            },
        )

        assert default not in check._get_merged_requirements(config, "policy.json")

    async def test_user_action_narrower_than_default_glob_keeps_it(self, check):
        default = {"actions": ["iam:Pass*"], "required_conditions": [{"condition_key": "iam:PassedToService"}]}
        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "merge_strategy": "per_action_override",
                "requirements": [default],
                "action_condition_requirements": [
                    {"actions": ["iam:PassRole"], "required_conditions": [{"condition_key": KEY}]}
                ],
            },
        )

        assert default in check._get_merged_requirements(config, "policy.json")


def _override_config(user: dict[str, Any]) -> tuple[dict[str, Any], CheckConfig]:
    default = {"actions": [ACTION], "required_conditions": [{"condition_key": "iam:PassedToService"}]}
    return default, CheckConfig(
        check_id="action_condition_enforcement",
        enabled=True,
        config={
            "merge_strategy": "per_action_override",
            "requirements": [default],
            "action_condition_requirements": [user],
        },
    )


class TestPerActionOverrideSilencingUserRule:
    @pytest.mark.parametrize(
        "user",
        [
            {"actions": [ACTION], "severity": "none", "required_conditions": [{"condition_key": KEY}]},
            {"actions": [ACTION], "required_conditions": [{"condition_key": KEY, "severity": "none"}]},
        ],
        ids=["requirement", "entry"],
    )
    async def test_a_severity_none_user_rule_replaces_the_default(self, check, user):
        default, config = _override_config(user)

        assert default not in check._get_merged_requirements(config, "policy.json")
        issues = await _run(check, config, _stmt("S", condition=None))

        assert [i.severity for i in issues] == ["none"]


class TestPerActionOverrideNonEnforcingUserRule:
    @pytest.mark.parametrize(
        "user",
        [
            {"actions": [ACTION], "required_conditions": {"none_of": [{"condition_key": KEY}]}},
            {"actions": [ACTION], "required_conditions": [{"operator": "Bool"}]},
            {
                "actions": [ACTION],
                "required_conditions": [{"condition_key": KEY, "all_of": [{"condition_key": "aws:SourceIp"}]}],
            },
            {"actions": [ACTION], "if": [{"required_conditions": {"none_of": [{"condition_key": KEY}]}}]},
        ],
    )
    async def test_keeps_the_default_and_matches_enforced_actions(self, check, user):
        default, config = _override_config(user)

        assert default in check._get_merged_requirements(config, "policy.json")
        assert check._owned_enforced_actions(user, config) == []

    async def test_none_of_only_user_rule_still_reports_the_default_requirement(self, check):
        _, config = _override_config(
            {"actions": [ACTION], "required_conditions": {"none_of": [{"condition_key": KEY}]}}
        )

        issues = await _run(check, config)

        assert [i.condition_key for i in issues if i.issue_type == "missing_required_condition"] == [
            "iam:PassedToService"
        ]


class TestAnyOfIdentityIgnoresOrder:
    async def test_reordered_any_of_in_overlapping_branches_is_reported_once(self, check):
        keys = [{"condition_key": "aws:SourceIp"}, {"condition_key": KEY}]
        config = _config(
            {
                "actions": [ACTION],
                "if": [
                    {"required_conditions": {"any_of": keys}},
                    {"severity": "critical", "required_conditions": {"any_of": keys[::-1]}},
                ],
            }
        )

        issues = await _run(check, config)

        assert [(i.issue_type, i.severity) for i in issues] == [("missing_required_condition_any_of", "critical")]


class TestFalsyScalarRequiredConditions:
    @pytest.mark.parametrize("required_conditions", [False, 0, ""])
    async def test_reported_as_malformed(self, check, required_conditions):
        config = _config({"actions": [ACTION], "required_conditions": required_conditions})

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        assert _types(issues) == [("invalid_condition_requirement", -1)]
        assert "must be a list or a mapping" in issues[0].message

    @pytest.mark.parametrize("required_conditions", [None, [], {}])
    async def test_empty_is_detection_only(self, check, required_conditions):
        config = _config({"actions": [ACTION], "required_conditions": required_conditions})

        issues = await _run(check, config)

        assert [i.issue_type for i in issues] == ["action_detected"]

    @pytest.mark.parametrize("required_conditions", [False, 0, ""])
    def test_not_counted_as_enforced(self, required_conditions):
        root = _root({"actions": [ACTION], "required_conditions": required_conditions})

        assert ActionConditionEnforcementCheck.enforced_actions(root) == set()


class TestTopLevelShapeWording:
    @pytest.mark.parametrize(
        "required_conditions",
        [5, {"allof": [{"condition_key": KEY}]}, {"all_of": {"condition_key": KEY}}],
    )
    async def test_matches_if_branch_wording(self, check, required_conditions):
        top = await _run(check, _config({"actions": [ACTION], "required_conditions": required_conditions}))
        branch = await _run(check, _config({"actions": [ACTION], "if": [{"required_conditions": required_conditions}]}))

        assert len(top) == len(branch) == 1
        assert branch[0].message.split("`if[0]`: ", 1)[1] in top[0].message

    async def test_every_bad_group_is_reported(self, check):
        required_conditions = {"allof": [], "nonof": [], "any_of": "x"}

        issues = await _run(check, _config({"actions": [ACTION], "required_conditions": required_conditions}))

        assert len(issues) == 3


class TestMalformedRequirementLists:
    _VALID = {"actions": [ACTION], "required_conditions": [{"condition_key": KEY}]}

    @pytest.mark.parametrize("key", ["requirements", "policy_level_requirements", "action_condition_requirements"])
    async def test_non_dict_entries_reported_once_and_valid_entries_enforced(self, check, key):
        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={"merge_strategy": "append", key: ["iam:PassRole", 5, self._VALID]},
        )

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        assert _types(issues) == [
            ("invalid_condition_requirement", -1),
            ("invalid_condition_requirement", -1),
            ("missing_required_condition", 0),
            ("missing_required_condition", 1),
        ]
        assert key in issues[0].message

    @pytest.mark.parametrize("key", ["requirements", "policy_level_requirements", "action_condition_requirements"])
    @pytest.mark.parametrize("value", [{"actions": [ACTION]}, "iam:PassRole", 5])
    async def test_non_list_value_reported_once(self, check, key, value):
        config = CheckConfig(check_id="action_condition_enforcement", enabled=True, config={key: value})

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        assert _types(issues) == [("invalid_condition_requirement", -1)]
        assert key in issues[0].message


class TestPatternOnlyRequirementOnFullWildcard:
    async def test_config_error_reported_for_action_star(self, check):
        config = _config({"action_patterns": ["^iam:Pass.*"], "required_conditions": [{"condition_key": 5}]})

        issues = await _run(check, config, _stmt("One", action="*"))

        assert ("invalid_condition_requirement", -1) in _types(issues)


class TestNullKeysShareRuleIdentity:
    MFA = "aws:MultiFactorAuthPresent"

    @pytest.mark.parametrize(
        "requirement",
        [
            {
                "actions": [ACTION],
                "if": [
                    {"required_conditions": [{"condition_key": MFA, "expected_value": None}]},
                    {"required_conditions": [{"all_of": [{"condition_key": MFA, "expected_value": None}]}]},
                ],
            },
            {
                "actions": [ACTION],
                "required_conditions": [{"condition_key": MFA, "expected_value": None}],
                "if": [{"required_conditions": [{"all_of": [{"condition_key": MFA, "expected_value": None}]}]}],
            },
        ],
    )
    async def test_flat_and_nested_entry_reported_once(self, check, requirement):
        issues = await _run(check, _config(requirement))

        assert _types(issues) == [("missing_required_condition", 0)]


class TestNullConditionKeyBesideAllOf:
    async def test_enforced_and_not_reported(self, check):
        entry = {"condition_key": None, "all_of": [{"condition_key": KEY}]}

        issues = await _run(check, _config({"actions": [ACTION], "required_conditions": [entry]}))

        assert _types(issues) == [("missing_required_condition", 0)]

    async def test_non_null_condition_key_beside_all_of_still_reported(self, check):
        entry = {"condition_key": KEY, "all_of": [{"condition_key": KEY}]}

        issues = await _run(check, _config({"actions": [ACTION], "required_conditions": [entry]}))

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len(invalid) == 1
        assert "has both `condition_key` and `all_of`" in invalid[0].message

    async def test_null_condition_key_beside_empty_all_of_reports_all_of(self, check):
        entry = {"condition_key": None, "all_of": []}

        issues = await _run(check, _config({"actions": [ACTION], "required_conditions": [entry]}))

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len(invalid) == 1
        assert "nested `all_of`" in invalid[0].message


class TestNullAllOfBesideConditionKey:
    MFA = "aws:MultiFactorAuthPresent"

    @pytest.mark.parametrize(
        ("required_conditions", "issue_type"),
        [
            ([{"condition_key": MFA, "all_of": None}], "missing_required_condition"),
            ([{"all_of": [{"condition_key": MFA, "all_of": None}]}], "missing_required_condition"),
            ({"any_of": [{"condition_key": MFA, "all_of": None}]}, "missing_required_condition_any_of"),
        ],
    )
    async def test_enforced_as_plain_entry(self, check, required_conditions, issue_type):
        config = _config({"actions": [ACTION], "required_conditions": required_conditions})

        issues = await _run(check, config)

        assert _types(issues) == [(issue_type, 0)]

    async def test_satisfied_by_the_key(self, check):
        config = _config({"actions": [ACTION], "required_conditions": [{"condition_key": self.MFA, "all_of": None}]})
        condition = {"Bool": {self.MFA: "true"}}

        assert await _run(check, config, _stmt("One", condition=condition)) == []

    @pytest.mark.parametrize(
        "entry", [{"all_of": None}, {"condition_key": None, "all_of": None}, {"condition_key": "", "all_of": None}]
    )
    async def test_without_key_reports_all_of(self, check, entry):
        issues = await _run(check, _config({"actions": [ACTION], "required_conditions": [entry]}))

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len(invalid) == 1
        assert "nested `all_of`" in invalid[0].message


class TestDuplicateFindingsReportedOnce:
    async def test_flat_and_nested_entry_without_if(self, check):
        required_conditions = [{"condition_key": KEY}, {"all_of": [{"condition_key": KEY}]}]

        issues = await _run(check, _config({"actions": [ACTION], "required_conditions": required_conditions}))

        assert _types(issues) == [("missing_required_condition", 0)]

    async def test_repeated_bad_action(self, check):
        config = _config({"actions": [ACTION, None, None], "required_conditions": [{"condition_key": KEY}]})

        issues = await _run(check, config, _stmt("One", condition={"StringEquals": {KEY: "vpc-1"}}))

        assert _types(issues) == [("invalid_condition_requirement", -1)]

    async def test_repeated_malformed_entry(self, check):
        config = _config({"actions": [ACTION], "required_conditions": [{"condition_key": 1}, {"condition_key": 1}]})

        issues = await _run(check, config)

        assert _types(issues) == [("invalid_condition_requirement", -1)]

    async def test_distinct_statements_and_bad_values_kept(self, check):
        config = _config({"actions": [ACTION, None, 1], "required_conditions": [{"condition_key": KEY}]})

        issues = await _run(check, config, _stmt("One"), _stmt("Two"))

        assert _types(issues) == [
            ("invalid_condition_requirement", -1),
            ("invalid_condition_requirement", -1),
            ("missing_required_condition", 0),
            ("missing_required_condition", 1),
        ]


class TestEveryNonStringActionReported:
    async def test_one_issue_per_bad_entry(self, check):
        config = _config({"actions": ["s3:GetObject", 1, True], "required_conditions": [{"condition_key": KEY}]})

        issues = await _run(check, config, _stmt("One", action="s3:GetObject"))

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len(invalid) == 2
        assert {"`1`", "`True`"} == {i.message.rsplit(": ", 1)[1] for i in invalid}


class TestConfigProblemsDifferingInPresentationKept:
    async def test_malformed_entries_differing_in_description(self, check):
        required_conditions = [{"condition_key": 5, "description": "a"}, {"condition_key": 5, "description": "b"}]

        issues = await _run(check, _config({"actions": [ACTION], "required_conditions": required_conditions}))

        assert _types(issues) == [("invalid_condition_requirement", -1), ("invalid_condition_requirement", -1)]

    async def test_non_mapping_requirement_entries_differing_in_description(self, check):
        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "merge_strategy": "user_only",
                "action_condition_requirements": [[{"description": "a"}], [{"description": "b"}]],
            },
        )

        issues = await _run(check, config)

        assert _types(issues) == [("invalid_condition_requirement", -1), ("invalid_condition_requirement", -1)]


class TestInvalidSeverityFindingIdentity:
    async def test_entries_with_the_same_invalid_severity_are_reported_separately(self, check):
        config = _config(
            {
                "actions": [ACTION],
                "required_conditions": {
                    "all_of": [
                        {"condition_key": KEY, "severity": "urgent"},
                        {"condition_key": "aws:SourceIp", "severity": "urgent"},
                    ]
                },
            }
        )

        issues = await _run(check, config)

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len({i.finding_key for i in invalid}) == 2

    async def test_entries_differing_only_in_key_order_are_reported_once(self, check):
        entry = {"condition_key": KEY, "severity": "urgent", "expected_value": "ec2"}
        reordered = dict(reversed(entry.items()))
        config = _config({"actions": [ACTION], "required_conditions": {"all_of": [entry, reordered]}})

        issues = await _run(check, config)

        assert [i.issue_type for i in issues].count("invalid_condition_requirement") == 1


def _ace_ids(issues) -> list[str]:
    return [
        compute_finding_hash(
            "policy.json",
            "action_condition_enforcement",
            i.issue_type,
            i.statement_sid,
            i.statement_index,
            i.action,
            i.resource,
            i.condition_key,
            i.finding_key,
        )
        for i in issues
    ]


class TestRequirementFindingIds:
    PASSED_TO = "iam:PassedToService"

    def _requirement(self, value: str, **presentation: Any) -> dict[str, Any]:
        entry = {"condition_key": self.PASSED_TO, "expected_value": value, **presentation}
        return {"actions": [ACTION], "required_conditions": [entry]}

    async def test_rules_differing_in_expected_value_have_distinct_ids(self, check):
        issues = await _run(check, _config(self._requirement("ec2"), self._requirement("lambda")))

        assert len(issues) == 2
        assert len(set(_ace_ids(issues))) == 2

    async def test_id_ignores_severity_and_description(self, check):
        plain = await _run(check, _config(self._requirement("ec2")))
        reworded = await _run(check, _config(self._requirement("ec2", severity="critical", description="other")))

        assert _ace_ids(plain) == _ace_ids(reworded)

    async def test_id_ignores_custom_message(self, check):
        first = await _run(check, _config(self._requirement("ec2", message="Pass only to EC2")))
        reworded = await _run(check, _config(self._requirement("ec2", message="EC2 only, please")))

        assert _ace_ids(first) == _ace_ids(reworded)


class TestPerActionOverrideStringActions:
    async def test_string_actions_user_rule_replaces_the_default(self, check):
        default, config = _override_config({"actions": ACTION, "required_conditions": [{"condition_key": KEY}]})

        assert default not in check._get_merged_requirements(config, "policy.json")
        assert [i.condition_key for i in await _run(check, config)] == [KEY]


class TestForbiddenActionRuleIdentity:
    async def test_distinct_forbidden_sets_get_distinct_finding_ids(self, check):
        config = _config(
            {"actions": {"none_of": [ACTION]}, "severity": "high", "description": "A"},
            {"actions": {"none_of": [ACTION, "iam:DeleteUser"]}, "severity": "low", "description": "B"},
        )

        issues = await _run(check, config)

        assert [i.issue_type for i in issues] == ["forbidden_action", "forbidden_action"]
        assert len(set(_ace_ids(issues))) == 2

    async def test_same_forbidden_set_in_any_order_is_reported_once(self, check):
        config = _config(
            {"actions": {"none_of": [ACTION, "iam:DeleteUser"]}, "description": "A"},
            {"actions": {"none_of": ["iam:DeleteUser", ACTION]}, "severity": "critical", "description": "B"},
        )

        issues = await _run(check, config)

        assert [(i.issue_type, i.severity) for i in issues] == [("forbidden_action", "critical")]


GRANTED = ["iam:PassRole", "iam:GetRole", "iam:DeleteRole", "iam:CreateRole", "iam:TagRole", "iam:ListRoles"]


class TestPolicyWideActionOrder:
    async def test_glob_any_of_lists_actions_in_statement_order(self, check):
        config = _config({"actions": {"any_of": ["iam:*"]}, "required_conditions": [{"condition_key": KEY}]})

        issues = await _run(check, config, Statement(sid="One", effect="Allow", action=GRANTED, resource="*"))

        assert [i.action for i in issues] == [", ".join(GRANTED)]

    async def test_glob_none_of_lists_actions_in_statement_order(self, check):
        config = _config({"actions": {"none_of": ["iam:*"]}})

        issues = await _run(check, config, Statement(sid="One", effect="Allow", action=GRANTED, resource="*"))

        assert [i.action for i in issues] == [", ".join(GRANTED)]

    async def test_list_and_any_of_over_same_actions_reported_once(self, check):
        required_conditions = [{"condition_key": KEY}]
        config = _config(
            {"actions": GRANTED[:2], "required_conditions": required_conditions},
            {"actions": {"any_of": GRANTED[1::-1]}, "required_conditions": required_conditions},
        )

        issues = await _run(check, config, Statement(sid="One", effect="Allow", action=GRANTED[:2], resource="*"))

        assert _types(issues) == [("missing_required_condition", 0)]


class TestPerActionOverrideKeepsUncoveredDefaultActions:
    async def test_list_default_keeps_actions_the_user_rule_does_not_cover(self, check):
        default = {"actions": ["s3:GetObject", "s3:PutObject"], "required_conditions": [{"condition_key": KEY}]}
        user = {"actions": ["s3:Put*"], "required_conditions": [{"condition_key": KEY}]}
        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "merge_strategy": "per_action_override",
                "requirements": [default],
                "action_condition_requirements": [user],
            },
        )

        merged = check._get_merged_requirements(config, "policy.json")

        assert [r["actions"] for r in merged] == [["s3:Put*"], ["s3:GetObject"]]

    async def test_fully_covered_list_default_is_dropped(self, check):
        default, merged = _override_merge(check, ["iam:Pass*"])

        assert [r["actions"] for r in merged] == [["iam:Pass*"]]


def _override_with_default(check, default: dict[str, Any]) -> list[dict[str, Any]]:
    config = CheckConfig(
        check_id="action_condition_enforcement",
        enabled=True,
        config={
            "merge_strategy": "per_action_override",
            "requirements": [default],
            "action_condition_requirements": [{"actions": [ACTION], "required_conditions": [{"condition_key": KEY}]}],
        },
    )
    return check._get_merged_requirements(config, "policy.json")


class TestPerActionOverrideTrimsOverlappingDefaults:
    async def test_mapping_default_keeps_uncovered_any_of_actions(self, check):
        default = {
            "actions": {"any_of": [ACTION, "iam:CreateRole"]},
            "required_conditions": [{"condition_key": "iam:PassedToService"}],
        }

        merged = _override_with_default(check, default)

        assert [r["actions"] for r in merged] == [[ACTION], {"any_of": ["iam:CreateRole"]}]

    async def test_default_with_action_patterns_is_dropped_on_overlap(self, check):
        default = {
            "actions": [ACTION, "iam:CreateRole"],
            "action_patterns": ["^iam:Pass.*"],
            "required_conditions": [{"condition_key": "iam:PassedToService"}],
        }

        merged = _override_with_default(check, default)

        assert [r["actions"] for r in merged] == [[ACTION]]


class TestForbiddenActionIdIgnoresConfigOrder:
    async def test_none_of_order_does_not_change_finding_id(self, check):
        statement = Statement(sid="S", effect="Allow", action=["s3:PutObject", "s3:GetObject"], resource="*")

        ids = [
            _ace_ids(await _run(check, _config({"actions": {"none_of": none_of}}), statement))
            for none_of in (["s3:PutObject", "s3:GetObject"], ["s3:GetObject", "s3:PutObject"])
        ]

        assert ids[0] == ids[1] and ids[0]


class TestActionDetectedPerStatement:
    @pytest.mark.parametrize("actions", [[ACTION], {"any_of": [ACTION]}])
    async def test_each_matching_statement_gets_its_own_finding(self, check, actions):
        issues = await _run(
            check,
            _config({"actions": actions}),
            _stmt("Read", action="s3:GetObject"),
            _stmt("PassA"),
            _stmt("PassB"),
        )

        detected = [(i.statement_index, i.statement_sid, i.action) for i in issues if i.issue_type == "action_detected"]
        assert detected == [(1, "PassA", ACTION), (2, "PassB", ACTION)]


def _multi(sid: str, *actions: str) -> Statement:
    return Statement(sid=sid, effect="Allow", action=list(actions), resource="*")


class TestPolicyWideFindingsFollowStatements:
    async def test_none_of_action_order_ignores_other_statements(self, check):
        config = _config({"actions": {"none_of": ["iam:CreateUser", "iam:DeleteUser"]}})
        target = _multi("Target", "iam:CreateUser", "iam:DeleteUser")

        alone = await _run(check, config, target)
        after_insert = await _run(check, config, _multi("First", "iam:DeleteUser"), target)

        assert alone[0].action == after_insert[1].action == "iam:CreateUser, iam:DeleteUser"
        assert _ace_ids(alone)[0] == _ace_ids(after_insert)[1]

    async def test_none_of_findings_and_refs_in_statement_order(self, check):
        config = _config({"actions": {"none_of": ["iam:CreateUser", "iam:DeleteUser"]}})

        issues = await _run(
            check,
            config,
            _multi("A", "iam:CreateUser"),
            _multi("B", "iam:DeleteUser"),
            _multi("C", "iam:CreateUser"),
        )

        assert [i.statement_index for i in issues] == [0, 1, 2]
        assert "Statement #1 (SID: A), Statement #2 (SID: B), Statement #3 (SID: C)" in issues[0].suggestion

    async def test_none_of_finding_id_ignores_config_case(self, check):
        statement = _multi("S", ACTION)

        ids = [
            _ace_ids(await _run(check, _config({"actions": {"none_of": [action]}}), statement))
            for action in (ACTION, ACTION.upper())
        ]

        assert ids[0] == ids[1] and ids[0]

    async def test_any_of_action_order_ignores_config_order(self, check):
        statement = _multi("S", "s3:PutObject", "s3:GetObject")

        actions = [
            [
                i.action
                for i in await _run(
                    check,
                    _config({"actions": {"any_of": any_of}, "required_conditions": [{"condition_key": KEY}]}),
                    statement,
                )
            ]
            for any_of in (["s3:GetObject", "s3:PutObject"], ["s3:PutObject", "s3:GetObject"])
        ]

        assert actions[0] == actions[1] == ["s3:PutObject, s3:GetObject"]

    async def test_all_of_findings_in_statement_order(self, check):
        config = _config(
            {"actions": {"all_of": ["s3:Get*", "s3:Put*"]}, "required_conditions": [{"condition_key": KEY}]}
        )

        issues = await _run(
            check,
            config,
            _multi("GetOnly", "s3:GetObject"),
            _multi("Both", "s3:GetObjectAcl", "s3:PutObject"),
            _multi("BothAgain", "s3:GetObject", "s3:PutObject"),
        )

        assert [i.statement_index for i in issues] == [1, 2]


class TestActionDetectedFollowsStatementOrder:
    @pytest.mark.parametrize(
        "actions",
        [
            ["iam:PassRole", "s3:PutObject"],
            {"any_of": ["iam:PassRole", "s3:PutObject"]},
            {"all_of": ["iam:PassRole", "s3:PutObject"]},
        ],
    )
    async def test_actions_listed_in_statement_order(self, check, actions):
        issues = await _run(check, _config({"actions": actions}), _multi("S", "s3:PutObject", "iam:PassRole"))

        assert [i.action for i in issues if i.issue_type == "action_detected"] == ["s3:PutObject, iam:PassRole"]


class TestForbiddenActionIdIncludesPatterns:
    async def test_same_none_of_with_different_patterns_gets_distinct_ids(self, check):
        statement = _multi("S", "s3:DeleteBucket", "s3:DeleteObject")
        plain = {"actions": {"none_of": ["s3:DeleteBucket"]}, "description": "A"}
        patterned = {**plain, "action_patterns": ["^s3:Delete.*"], "description": "B"}

        issues = await _run(check, _config(plain, patterned), statement)

        forbidden = [i for i in issues if i.issue_type == "forbidden_action"]
        assert len(forbidden) == 2
        assert len({i.finding_key for i in forbidden}) == 2

    async def test_id_without_patterns_is_unchanged(self, check):
        issues = await _run(
            check, _config({"actions": {"none_of": ["s3:DeleteBucket"]}}), _multi("S", "s3:DeleteBucket")
        )

        assert issues[0].finding_key == rule_key("none_of", unordered(["s3:deletebucket"]))


class TestActionDetectedRuleIdentity:
    async def test_same_detection_rule_reported_once_at_highest_severity(self, check):
        low = {"actions": ["iam:PassRole"], "severity": "low", "description": "A"}
        high = {"actions": ["IAM:PassRole"], "severity": "high", "description": "B"}

        issues = await _run(check, _config(low, high), _multi("S", "iam:PassRole"))

        detected = [i for i in issues if i.issue_type == "action_detected"]
        assert [(i.severity, i.message.endswith("B")) for i in detected] == [("high", True)]

    async def test_different_detection_rules_get_distinct_ids(self, check):
        listed = {"actions": ["iam:PassRole"], "description": "A"}
        grouped = {"actions": {"any_of": ["iam:PassRole", "s3:PutObject"]}, "description": "B"}

        issues = await _run(check, _config(listed, grouped), _multi("S", "iam:PassRole"))

        detected = [i for i in issues if i.issue_type == "action_detected"]
        assert len(detected) == 2
        assert len(set(_ace_ids(detected))) == 2


class TestMalformedIgnorePatterns:
    @pytest.mark.parametrize(
        ("ignore_patterns", "bad_count"),
        [({"filepath": "tests/.*"}, 1), ("tests/.*", 1), ([5, {"filepath": "nomatch"}, "x"], 2)],
    )
    async def test_reported_and_requirement_still_enforced(self, check, ignore_patterns, bad_count):
        config = _config(
            {"actions": [ACTION], "required_conditions": [{"condition_key": KEY}], "ignore_patterns": ignore_patterns}
        )

        issues = await _run(check, config)

        problems = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len(problems) == bad_count
        assert all("`ignore_patterns`" in i.message for i in problems)
        assert [i.statement_index for i in issues if i.issue_type == "missing_required_condition"] == [0]

    async def test_enforced_actions_does_not_crash_with_a_policy_file(self, check):
        root = {
            "action_condition_enforcement": {
                "merge_strategy": "user_only",
                "action_condition_requirements": [
                    {
                        "actions": [ACTION],
                        "required_conditions": [{"condition_key": KEY}],
                        "ignore_patterns": {"filepath": "nomatch"},
                    }
                ],
            }
        }

        assert ACTION in ActionConditionEnforcementCheck.enforced_actions(root, "policy.json")


class TestMalformedBranchesOfDistinctRequirementsKept:
    async def test_two_requirements_with_same_branch_problem_both_reported(self, check):
        config = _config(
            {"actions": [ACTION], "if": [{"effect": "Permit", "required_conditions": [{"condition_key": "aws:A"}]}]},
            {"actions": [ACTION], "if": [{"effect": "Permit", "required_conditions": [{"condition_key": "aws:B"}]}]},
        )

        issues = await _run(check, config)

        assert [i.issue_type for i in issues].count("invalid_condition_requirement") == 2


class TestActionPatternsWithoutServiceData:
    @pytest.fixture
    def failing_fetcher(self):
        from unittest.mock import MagicMock

        fetcher = MagicMock()
        fetcher.parse_action.side_effect = ValueError("no service data")
        return fetcher

    @pytest.mark.parametrize(
        ("pattern", "action", "flagged"),
        [
            ("^iam:Create.*", "iam:*", True),
            ("^iam:Create.*", "iam:C*", True),
            ("^iam:Create.*", "IAM:Cr*", True),
            ("^iam:Create.*", "iam:D*", False),
            ("^iam:Create.*", "s3:*", False),
            ("^iam:Ab?", "iam:Ac*", True),
            ("^s3:Get.*|^iam:Create.*", "iam:*", True),
        ],
    )
    async def test_wildcard_statement_matches_compatible_pattern(
        self, check, failing_fetcher, pattern, action, flagged
    ):
        config = _config({"action_patterns": [pattern], "required_conditions": [{"condition_key": KEY}]})
        policy = IAMPolicy(version="2012-10-17", statement=[_stmt("One", action=action)])

        issues = await check.execute_policy(policy, "policy.json", failing_fetcher, config)

        assert any(i.issue_type == "missing_required_condition" for i in issues) is flagged

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
            ({"any_of": ["iam:CreateRole"], "all_of": [ACTION]}, {ACTION, "iam:CreateRole"}),
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


class TestPerActionOverrideMappingActions:
    @pytest.mark.parametrize("group", ["any_of", "all_of", "none_of"])
    async def test_a_mapping_requirement_replaces_the_default(self, check, group):
        default = {"actions": [ACTION], "required_conditions": [{"condition_key": "iam:PassedToService"}]}
        user = {"actions": {group: [ACTION]}, "required_conditions": [{"condition_key": KEY}]}
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

        assert default not in merged


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

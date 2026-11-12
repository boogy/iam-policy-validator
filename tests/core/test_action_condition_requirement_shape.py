"""A condition requirement that names no key must never read as satisfied."""

import pytest

from iam_validator.checks.action_condition_enforcement import ActionConditionEnforcementCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement


@pytest.fixture
def check():
    return ActionConditionEnforcementCheck()


def _config(required_conditions) -> CheckConfig:
    return CheckConfig(
        check_id="action_condition_enforcement",
        enabled=True,
        config={
            "merge_strategy": "user_only",
            "action_condition_requirements": [
                {"actions": ["iam:PassRole"], "required_conditions": required_conditions}
            ],
        },
    )


def _policy(condition=None) -> IAMPolicy:
    statement = Statement(
        Sid="Test",
        Effect="Allow",
        Action=["iam:PassRole"],
        Resource="*",
        Condition=condition,
    )
    return IAMPolicy(Version="2012-10-17", Statement=[statement])


async def _run(check, mock_fetcher, required_conditions, condition=None):
    return await check.execute_policy(_policy(condition), "test.json", mock_fetcher, _config(required_conditions))


class TestMalformedEntryIsReported:
    @pytest.mark.parametrize(
        ("required_conditions", "label"),
        [
            ({"all_of": [{"description": "typo, no condition_key"}]}, "all_of"),
            ({"any_of": [{"description": "typo, no condition_key"}]}, "any_of"),
            ({"none_of": [{"description": "typo, no condition_key"}]}, "none_of"),
            ([{"description": "typo, no condition_key"}], "required_conditions"),
        ],
    )
    async def test_entry_without_condition_key_is_flagged(self, check, mock_fetcher, required_conditions, label):
        issues = await _run(check, mock_fetcher, required_conditions)

        malformed = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len(malformed) == 1
        assert label in malformed[0].message
        assert malformed[0].severity == "error"

    async def test_a_declared_severity_cannot_downgrade_the_notice(self, check, mock_fetcher):
        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "merge_strategy": "user_only",
                "action_condition_requirements": [
                    {
                        "actions": ["iam:PassRole"],
                        "severity": "low",
                        "required_conditions": {"all_of": [{"description": "no key"}]},
                    }
                ],
            },
        )

        issues = await check.execute_policy(_policy(), "test.json", mock_fetcher, config)

        assert [(i.issue_type, i.severity) for i in issues] == [("invalid_condition_requirement", "error")]

    async def test_malformed_all_of_entry_does_not_also_claim_a_missing_condition(self, check, mock_fetcher):
        issues = await _run(check, mock_fetcher, {"all_of": [{"description": "no key"}]})

        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]

    async def test_malformed_none_of_entry_does_not_report_a_forbidden_condition(self, check, mock_fetcher):
        issues = await _run(check, mock_fetcher, {"none_of": [{"description": "no key"}]})

        assert "forbidden_condition_present" not in {i.issue_type for i in issues}

    @pytest.mark.parametrize(
        "required_conditions",
        [
            {"any_of": [{"all_of": "aws:PrincipalOrgID"}]},
            {"any_of": [{"all_of": ["aws:PrincipalOrgID"]}]},
            [{"all_of": "aws:PrincipalOrgID"}],
            [{"all_of": {"condition_key": "aws:PrincipalOrgID"}}],
            {"all_of": [{"all_of": [{"condition_key": "aws:PrincipalOrgID"}, "typo"]}]},
            {"none_of": [{"all_of": ["typo"]}]},
            {"any_of": [{"condition_key": "aws:PrincipalOrgID", "all_of": None}]},
            {"any_of": [{"condition_key": "aws:PrincipalOrgID", "all_of": []}]},
        ],
    )
    async def test_malformed_nested_all_of_is_flagged_without_raising(self, check, mock_fetcher, required_conditions):
        issues = await _run(check, mock_fetcher, required_conditions)

        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]

    async def test_keyless_any_of_entry_is_left_out_of_the_missing_condition_message(self, check, mock_fetcher):
        issues = await _run(check, mock_fetcher, {"any_of": [{}, {"condition_key": "aws:PrincipalOrgID"}]})

        missing = [i for i in issues if i.issue_type == "missing_required_condition_any_of"]
        assert len(missing) == 1
        assert "unknown" not in missing[0].message

    async def test_non_mapping_any_of_entry_is_flagged_without_raising(self, check, mock_fetcher):
        issues = await _run(check, mock_fetcher, {"any_of": ["aws:PrincipalOrgID"]})

        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]

    async def test_non_mapping_any_of_entry_beside_a_wellformed_one_still_enforces_it(self, check, mock_fetcher):
        issues = await _run(check, mock_fetcher, {"any_of": ["typo", {"condition_key": "aws:PrincipalOrgID"}]})

        assert {i.issue_type for i in issues} == {"invalid_condition_requirement", "missing_required_condition_any_of"}

    async def test_a_wellformed_entry_alongside_a_malformed_one_is_still_enforced(self, check, mock_fetcher):
        issues = await _run(
            check,
            mock_fetcher,
            {"all_of": [{"description": "no key"}, {"condition_key": "aws:PrincipalOrgID"}]},
        )

        assert {i.issue_type for i in issues} == {"invalid_condition_requirement", "missing_required_condition"}


class TestNonListGroupIsReported:
    @pytest.mark.parametrize(
        ("required_conditions", "label"),
        [
            ({"all_of": "aws:PrincipalOrgID"}, "all_of"),
            ({"any_of": "aws:PrincipalOrgID"}, "any_of"),
            ({"none_of": "aws:PrincipalOrgID"}, "none_of"),
            ({"all_of": 5}, "all_of"),
            ("aws:PrincipalOrgID", "required_conditions"),
        ],
    )
    async def test_flagged_without_raising(self, check, mock_fetcher, required_conditions, label):
        issues = await _run(check, mock_fetcher, required_conditions)

        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]
        assert f"`{label}`" in issues[0].message

    async def test_a_wellformed_group_beside_it_is_still_enforced(self, check, mock_fetcher):
        issues = await _run(
            check, mock_fetcher, {"all_of": "typo", "any_of": [{"condition_key": "aws:PrincipalOrgID"}]}
        )

        assert {i.issue_type for i in issues} == {"invalid_condition_requirement", "missing_required_condition_any_of"}


class TestNestedAllOfInsideAnyOf:
    NESTED = {
        "any_of": [
            {"all_of": [{"condition_key": "aws:SourceArn"}, {"condition_key": "aws:SourceAccount"}]},
            {"condition_key": "aws:PrincipalOrgID"},
        ]
    }

    async def test_nested_all_of_no_longer_satisfies_any_of_unconditionally(self, check, mock_fetcher):
        issues = await _run(check, mock_fetcher, self.NESTED)

        assert [i.issue_type for i in issues] == ["missing_required_condition_any_of"]

    async def test_a_fully_satisfied_nested_all_of_satisfies_any_of(self, check, mock_fetcher):
        condition = {
            "StringEquals": {
                "aws:SourceArn": "arn:aws:s3:::bucket",
                "aws:SourceAccount": "123456789012",
            }
        }

        issues = await _run(check, mock_fetcher, self.NESTED, condition=condition)

        assert issues == []

    async def test_a_partially_satisfied_nested_all_of_does_not_satisfy_any_of(self, check, mock_fetcher):
        condition = {"StringEquals": {"aws:SourceArn": "arn:aws:s3:::bucket"}}

        issues = await _run(check, mock_fetcher, self.NESTED, condition=condition)

        assert [i.issue_type for i in issues] == ["missing_required_condition_any_of"]

    async def test_the_sibling_alternative_still_satisfies_any_of(self, check, mock_fetcher):
        condition = {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}

        issues = await _run(check, mock_fetcher, self.NESTED, condition=condition)

        assert issues == []

    async def test_a_nested_all_of_is_not_reported_as_malformed(self, check, mock_fetcher):
        issues = await _run(check, mock_fetcher, self.NESTED)

        assert "invalid_condition_requirement" not in {i.issue_type for i in issues}


async def test_deeply_nested_all_of_keys_are_named_in_the_any_of_message(check, mock_fetcher):
    required_conditions = {"any_of": [{"all_of": [{"all_of": [{"condition_key": "aws:SourceArn"}]}]}]}

    issues = await _run(check, mock_fetcher, required_conditions)

    assert [i.issue_type for i in issues] == ["missing_required_condition_any_of"]
    assert "unknown" not in issues[0].message + (issues[0].suggestion or "")
    assert "aws:SourceArn" in issues[0].message


async def test_entry_with_mixed_type_keys_is_still_enforced(check, mock_fetcher):
    issues = await _run(check, mock_fetcher, [{"condition_key": "iam:PassedToService", True: "yaml on", 2: "x"}])

    assert [i.issue_type for i in issues] == ["missing_required_condition"]


async def test_malformed_branch_with_string_actions_names_the_action(check, mock_fetcher):
    config = CheckConfig(
        check_id="action_condition_enforcement",
        enabled=True,
        config={
            "merge_strategy": "user_only",
            "action_condition_requirements": [{"actions": "iam:PassRole", "if": [{"effect": "Allow"}]}],
        },
    )

    issues = await check.execute_policy(_policy(), "test.json", mock_fetcher, config)

    malformed = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
    assert malformed
    assert malformed[0].action == "iam:PassRole"
    assert "`iam:PassRole`" in malformed[0].message


VPC_CONDITION = {"StringEquals": {"aws:SourceVpc": "vpc-1"}}


@pytest.mark.parametrize(
    "entry",
    [
        {"condition_key": ["aws:SourceVpc", "aws:SourceIp"]},
        {"condition_key": "aws:SourceVpc", "operator": 5},
    ],
)
async def test_non_string_key_or_operator_is_reported_not_raised(check, mock_fetcher, entry):
    issues = await _run(check, mock_fetcher, [entry], condition=VPC_CONDITION)

    assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]


async def test_single_string_actions_is_enforced(check, mock_fetcher):
    config = CheckConfig(
        check_id="action_condition_enforcement",
        enabled=True,
        config={
            "merge_strategy": "user_only",
            "action_condition_requirements": [
                {"actions": "iam:PassRole", "required_conditions": [{"condition_key": "iam:PassedToService"}]}
            ],
        },
    )

    issues = await check.execute_policy(_policy(), "test.json", mock_fetcher, config)

    assert [i.issue_type for i in issues] == ["missing_required_condition"]


@pytest.mark.parametrize(
    "required_conditions",
    [
        [{"all_of": [{"condition_key": "aws:SourceVpc"}, {"condition_key": "aws:SourceIp"}]}],
        {"all_of": [{"all_of": [{"condition_key": "aws:SourceVpc"}, {"condition_key": "aws:SourceIp"}]}]},
    ],
)
async def test_nested_all_of_reports_each_missing_key_by_name(check, mock_fetcher, required_conditions):
    issues = await _run(check, mock_fetcher, required_conditions, condition=VPC_CONDITION)

    assert [i.condition_key for i in issues] == ["aws:SourceIp"]


async def test_nested_all_of_under_none_of_is_named(check, mock_fetcher):
    condition = {"StringEquals": {"aws:SourceVpc": "vpc-1", "aws:SourceIp": "1.2.3.4"}}
    required = {"none_of": [{"all_of": [{"condition_key": "aws:SourceVpc"}, {"condition_key": "aws:SourceIp"}]}]}

    issues = await _run(check, mock_fetcher, required, condition=condition)

    assert len(issues) == 1
    assert "unknown" not in issues[0].message
    assert "`aws:SourceVpc` + `aws:SourceIp`" in issues[0].message


async def test_misspelled_group_is_reported(check, mock_fetcher):
    issues = await _run(check, mock_fetcher, {"allof": [{"condition_key": "aws:SourceVpc"}]})

    assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]
    assert "allof" in issues[0].message


async def test_null_group_is_treated_as_empty(check, mock_fetcher):
    issues = await _run(check, mock_fetcher, {"all_of": [{"condition_key": "aws:SourceVpc"}], "none_of": None})

    assert [i.issue_type for i in issues] == ["missing_required_condition"]


async def test_nested_all_of_passes_its_example_to_each_missing_key(check, mock_fetcher):
    group = {"all_of": [{"condition_key": "aws:SourceVpc"}, {"condition_key": "aws:SourceIp"}], "example": "GROUP"}

    issues = await _run(check, mock_fetcher, [group], condition=VPC_CONDITION)

    assert [(i.condition_key, i.example) for i in issues] == [("aws:SourceIp", "GROUP")]


async def test_nested_all_of_under_any_of_keeps_its_example(check, mock_fetcher):
    group = {"all_of": [{"condition_key": "aws:SourceIp"}], "example": "GROUP"}

    issues = await _run(check, mock_fetcher, {"any_of": [group]}, condition=VPC_CONDITION)

    assert [i.example for i in issues] == ["GROUP"]

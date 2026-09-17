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

    async def test_a_wellformed_entry_alongside_a_malformed_one_is_still_enforced(self, check, mock_fetcher):
        issues = await _run(
            check,
            mock_fetcher,
            {"all_of": [{"description": "no key"}, {"condition_key": "aws:PrincipalOrgID"}]},
        )

        assert {i.issue_type for i in issues} == {"invalid_condition_requirement", "missing_required_condition"}


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

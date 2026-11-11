"""Behaviour of `if:` branches in action_condition_enforcement requirements."""

import copy
from typing import Any
from unittest.mock import AsyncMock

import pytest

from iam_validator.checks.action_condition_enforcement import ActionConditionEnforcementCheck
from iam_validator.checks.sensitive_action import SensitiveActionCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement

ACTION = "bedrock:CallWithBearerToken"
KEY = "bedrock:bearerTokenType"

ALLOW_BRANCH = {
    "effect": "Allow",
    "required_conditions": [{"condition_key": KEY, "operator": "StringEquals", "expected_value": "SHORT_TERM"}],
}
DENY_BRANCH = {
    "effect": "Deny",
    "severity": "high",
    "required_conditions": [{"condition_key": KEY, "operator": "StringNotEquals", "expected_value": "SHORT_TERM"}],
}
BEDROCK = {"actions": [ACTION], "severity": "critical", "if": [ALLOW_BRANCH, DENY_BRANCH]}


@pytest.fixture
def check() -> ActionConditionEnforcementCheck:
    return ActionConditionEnforcementCheck()


def _config(*requirements: dict[str, Any], severity: str | None = None) -> CheckConfig:
    return CheckConfig(
        check_id="action_condition_enforcement",
        enabled=True,
        severity=severity,
        config={"action_condition_requirements": [copy.deepcopy(r) for r in requirements]},
    )


def _stmt(effect: str = "Allow", condition: dict | None = None, **kwargs: Any) -> Statement:
    fields: dict[str, Any] = {"action": ACTION, "resource": "*"} | kwargs
    if "not_resource" in kwargs:
        fields.pop("resource")
    if "not_action" in kwargs:
        fields.pop("action")
    return Statement(effect=effect, condition=condition, **fields)


async def _run(check, config, *statements: Statement, policy_file: str = "policy.json"):
    policy = IAMPolicy(version="2012-10-17", statement=list(statements))
    return await check.execute_policy(policy, policy_file, None, config)


def _token(operator: str, value: str) -> dict:
    return {operator: {KEY: value}}


def _branch(**kwargs: Any) -> dict:
    return {"required_conditions": [{"condition_key": KEY}], **kwargs}


class TestAllowBranch:
    async def test_missing_key_is_one_critical_finding(self, check):
        issues = await _run(check, _config(BEDROCK), _stmt())

        assert len(issues) == 1
        issue = issues[0]
        assert issue.issue_type == "missing_required_condition"
        assert issue.condition_key == KEY
        assert issue.severity == "critical"
        assert issue.statement_index == 0

    async def test_short_term_passes(self, check):
        assert await _run(check, _config(BEDROCK), _stmt(condition=_token("StringEquals", "SHORT_TERM"))) == []

    async def test_long_term_is_flagged(self, check):
        issues = await _run(check, _config(BEDROCK), _stmt(condition=_token("StringEquals", "LONG_TERM")))

        assert len(issues) == 1


class TestDenyBranch:
    async def test_missing_key_uses_branch_severity(self, check):
        issues = await _run(check, _config(BEDROCK), _stmt("Deny"))

        assert [(i.issue_type, i.severity) for i in issues] == [("missing_required_condition", "high")]

    async def test_string_not_equals_passes(self, check):
        assert await _run(check, _config(BEDROCK), _stmt("Deny", _token("StringNotEquals", "SHORT_TERM"))) == []


class TestEffectGating:
    async def test_deny_only_branch_skips_allow_statement(self, check):
        config = _config({"actions": [ACTION], "if": [DENY_BRANCH]})

        assert await _run(check, config, _stmt()) == []

    async def test_explicit_allow_branch_skips_deny_statement(self, check):
        config = _config({"actions": [ACTION], "if": [ALLOW_BRANCH]})

        assert await _run(check, config, _stmt("Deny")) == []

    async def test_list_effect_flags_deny_per_statement(self, check):
        config = _config({"actions": [ACTION], "if": [_branch(effect=["Allow", "Deny"])]})

        assert len(await _run(check, config, _stmt("Deny"))) == 1

    async def test_omitted_effect_skips_deny_per_statement(self, check):
        assert await _run(check, _config({"actions": [ACTION], "if": [_branch()]}), _stmt("Deny")) == []

    async def test_effect_is_case_insensitive(self, check):
        issues = await _run(check, _config({"actions": [ACTION], "if": [_branch(effect="allow")]}), _stmt())

        assert len(issues) == 1


class TestPolicyWideEffects:
    @pytest.mark.parametrize(
        ("branch", "expected"),
        [(_branch(), 0), (_branch(effect="Deny"), 1), (_branch(effect=["Allow", "Deny"]), 1)],
    )
    async def test_deny_statement(self, check, branch, expected):
        config = _config({"actions": {"any_of": [ACTION]}, "if": [branch]})

        assert len(await _run(check, config, _stmt("Deny"))) == expected

    async def test_omitted_effect_still_sees_allow(self, check):
        config = _config({"actions": {"any_of": [ACTION]}, "if": [_branch()]})

        assert len(await _run(check, config, _stmt())) == 1

    async def test_resource_filter_applies_policy_wide(self, check):
        config = _config({"actions": {"any_of": [ACTION]}, "if": [_branch(resource="arn:aws:s3:::prod")]})

        assert await _run(check, config, _stmt(resource="arn:aws:s3:::dev")) == []
        assert len(await _run(check, config, _stmt(resource="arn:aws:s3:::prod"))) == 1


class TestResourceMatching:
    @pytest.mark.parametrize(
        ("pattern", "resource", "expected"),
        [
            ("arn:aws:s3:::prod", "arn:aws:s3:::prod", 1),
            ("arn:aws:s3:::prod", "arn:aws:s3:::prod-backup", 0),
            ("arn:aws:s3:::prod/.*", ["arn:aws:s3:::dev/x", "arn:aws:s3:::prod/x"], 1),
            ("arn:aws:s3:::prod/.*", "*", 0),
            (".*", "*", 1),
            ("arn:aws:s3:::prod/.*", "arn:aws:s3:::PROD/x", 0),
        ],
    )
    async def test_resource_pattern(self, check, pattern, resource, expected):
        config = _config({"actions": [ACTION], "if": [_branch(resource=pattern)]})

        assert len(await _run(check, config, _stmt(resource=resource))) == expected

    async def test_resource_only_branch_skips_not_resource_statement(self, check):
        config = _config({"actions": [ACTION], "if": [_branch(resource=".*")]})

        assert await _run(check, config, _stmt(not_resource="arn:aws:s3:::prod/x")) == []

    async def test_not_resource_branch_targets_not_resource_statements(self, check):
        config = _config({"actions": [ACTION], "if": [_branch(not_resource="arn:aws:s3:::prod/.*")]})

        assert len(await _run(check, config, _stmt(not_resource="arn:aws:s3:::prod/x"))) == 1
        assert await _run(check, config, _stmt(resource="arn:aws:s3:::prod/x")) == []

    async def test_both_resource_keys_must_match(self, check):
        stmt = _stmt(resource="arn:a")
        stmt.not_resource = "arn:b"
        matching = _config({"actions": [ACTION], "if": [_branch(resource="arn:a", not_resource="arn:b")]})
        partial = _config({"actions": [ACTION], "if": [_branch(resource="arn:a", not_resource="arn:c")]})

        assert len(await _run(check, matching, stmt)) == 1
        assert await _run(check, partial, stmt) == []

    async def test_unanchored_pattern_cannot_match_longer_string(self, check):
        config = _config({"actions": [ACTION], "if": [_branch(resource="prod")]})

        assert await _run(check, config, _stmt(resource="arn:aws:s3:::prod")) == []


class TestComposition:
    async def test_two_matching_branches_report_independently(self, check):
        other = {"required_conditions": [{"condition_key": "aws:SourceVpc"}]}
        config = _config({"actions": [ACTION], "if": [_branch(), other]})

        assert len(await _run(check, config, _stmt())) == 2

    async def test_overlapping_branches_report_an_identical_finding_once(self, check):
        config = _config({"actions": [ACTION], "if": [_branch(), _branch(effect="Allow")]})

        assert len(await _run(check, config, _stmt())) == 1

    async def test_overlap_differing_in_note_and_severity_reports_most_severe_once(self, check):
        requirement = {
            "actions": [ACTION],
            "severity": "low",
            "required_conditions": [{"condition_key": "aws:RequestedRegion"}],
            "if": [
                {
                    "effect": ["Allow", "Deny"],
                    "severity": "high",
                    "required_conditions": [{"condition_key": "aws:RequestedRegion"}],
                }
            ],
        }

        issues = await _run(check, _config(requirement), _stmt(), _stmt("Deny"))

        assert sorted((i.statement_index, i.severity) for i in issues) == [(0, "high"), (1, "high")]

    @pytest.mark.parametrize(
        ("operator", "issue_type"), [("none_of", "forbidden_action"), ("any_of", "missing_required_condition")]
    )
    async def test_policy_wide_overlap_reports_most_severe_once(self, check, operator, issue_type):
        requirement = {"actions": {operator: [ACTION]}, "if": [_branch(severity="low"), _branch(severity="high")]}

        issues = await _run(check, _config(requirement), _stmt())

        assert [(i.issue_type, i.severity) for i in issues] == [(issue_type, "high")]

    async def test_none_of_skips_deny_statements(self, check):
        requirement = {"actions": {"none_of": [ACTION]}, "if": [_branch(effect=["Allow", "Deny"])]}

        issues = await _run(check, _config(requirement), _stmt("Deny"), _stmt())

        assert [(i.issue_type, i.statement_index) for i in issues] == [("forbidden_action", 1)]

    async def test_no_matching_branch_reports_nothing(self, check):
        config = _config({"actions": [ACTION], "if": [_branch(effect="Deny", resource="arn:x")]})

        assert await _run(check, config, _stmt("Deny")) == []

    async def test_top_level_required_conditions_stays_allow_only_beside_branches(self, check):
        requirement = {
            "actions": [ACTION],
            "required_conditions": [{"condition_key": "aws:SourceVpc"}],
            "if": [DENY_BRANCH],
        }

        allow_keys = [i.condition_key for i in await _run(check, _config(requirement), _stmt())]
        deny_keys = sorted(i.condition_key for i in await _run(check, _config(requirement), _stmt("Deny")))

        assert allow_keys == ["aws:SourceVpc"]
        assert deny_keys == [KEY]

    async def test_allow_not_action_counts_as_granting(self, check):
        config = _config({"actions": [ACTION], "if": [ALLOW_BRANCH]})

        assert len(await _run(check, config, _stmt(not_action="s3:*"))) == 1
        assert await _run(check, config, _stmt(not_action="bedrock:*")) == []


class TestSeverityPrecedence:
    @pytest.mark.parametrize(
        ("entry", "branch", "requirement", "expected"),
        [
            ("low", "high", "critical", "low"),
            (None, "high", "critical", "high"),
            (None, None, "critical", "critical"),
            (None, None, None, "medium"),
        ],
    )
    async def test_precedence(self, check, entry, branch, requirement, expected):
        cond: dict[str, Any] = {"condition_key": KEY}
        if entry:
            cond["severity"] = entry
        branch_cfg: dict[str, Any] = {"required_conditions": [cond]}
        if branch:
            branch_cfg["severity"] = branch
        req: dict[str, Any] = {"actions": [ACTION], "if": [branch_cfg]}
        if requirement:
            req["severity"] = requirement

        issues = await _run(check, _config(req, severity="medium"), _stmt())

        assert [i.severity for i in issues] == [expected]


class TestCompoundTagKey:
    async def test_compound_tag_key(self, check):
        config = _config(
            {"actions": [ACTION], "if": [{"required_conditions": [{"condition_key": "aws:ResourceTag/team/owner"}]}]}
        )

        satisfied = _stmt(condition={"StringEquals": {"aws:ResourceTag/team/owner": "x"}})
        assert await _run(check, config, satisfied) == []
        assert len(await _run(check, config, _stmt())) == 1


class TestIgnorePatterns:
    async def test_requirement_ignore_patterns_suppress_branch_findings(self, check):
        requirement = {**BEDROCK, "ignore_patterns": [{"action": "bedrock:.*"}]}

        assert await _run(check, _config(requirement), _stmt()) == []


class TestMalformedBranches:
    @pytest.mark.parametrize(
        ("if_value", "fragment"),
        [
            ("Allow", "`if` must be a non-empty list"),
            ([], "`if` must be a non-empty list"),
            (None, "`if` must be a non-empty list"),
            (["Allow"], "`if[0]`: branch must be a mapping"),
            ([{"effect": "Allow"}], "`if[0]`: `required_conditions` is missing or empty"),
            ([{"required_conditions": []}], "`if[0]`: `required_conditions` is missing or empty"),
            ([_branch(effect="Permit")], "`if[0]`: `effect` must be"),
            ([_branch(resource="arn:(")], "`if[0]`: `resource` is not a valid regex"),
            ([_branch(resource=["arn:.*"])], "`if[0]`: `resource` must be a regex string"),
            ([_branch(resources="arn:.*")], "`if[0]`: unknown key(s) `resources`"),
            ([_branch(severity="urgent")], "`if[0]`: `severity` must be"),
        ],
    )
    async def test_reported_once_without_raising(self, check, if_value, fragment):
        issues = await _run(check, _config({"actions": [ACTION], "if": if_value}), _stmt())

        assert len(issues) == 1
        issue = issues[0]
        assert issue.issue_type == "invalid_condition_requirement"
        assert issue.severity == "error"
        assert issue.statement_index == -1
        assert fragment in issue.message
        assert ACTION in issue.message
        assert issue.action == ACTION

    async def test_reported_even_when_no_statement_grants_the_action(self, check):
        issues = await _run(check, _config({"actions": [ACTION], "if": []}), _stmt(action="s3:GetObject"))

        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]

    async def test_valid_branch_still_runs_beside_malformed_one(self, check):
        config = _config({"actions": [ACTION], "if": [_branch(resources=".*"), ALLOW_BRANCH]})

        issues = await _run(check, config, _stmt("Deny"), _stmt())

        assert sorted((i.issue_type, i.statement_index) for i in issues) == [
            ("invalid_condition_requirement", -1),
            ("missing_required_condition", 1),
        ]


class TestBackwardCompatibility:
    async def test_plain_requirement_skips_deny_per_statement(self, check):
        config = _config({"actions": [ACTION], "required_conditions": [{"condition_key": KEY}]})

        assert await _run(check, config, _stmt("Deny")) == []

    async def test_plain_requirement_skips_deny_policy_wide(self, check):
        config = _config({"actions": {"any_of": [ACTION]}, "required_conditions": [{"condition_key": KEY}]})

        assert await _run(check, config, _stmt("Deny")) == []


def _root(*requirements: dict[str, Any]) -> dict[str, Any]:
    return {
        "action_condition_enforcement": {
            "merge_strategy": "user_only",
            "action_condition_requirements": [copy.deepcopy(r) for r in requirements],
        }
    }


class TestEnforcedActions:
    @pytest.mark.parametrize(
        "if_value",
        [
            [DENY_BRANCH],
            [_branch(resource=".*")],
            [_branch(effect="Allow", not_resource=".*")],
            [_branch(resources=".*")],
            [],
        ],
    )
    def test_excludes_requirement_without_unscoped_allow_branch(self, if_value):
        root = _root({"actions": [ACTION], "if": if_value})

        assert ActionConditionEnforcementCheck.enforced_actions(root) == set()

    @pytest.mark.parametrize(
        "requirement",
        [
            {"actions": [ACTION], "if": [DENY_BRANCH, ALLOW_BRANCH]},
            {"actions": [ACTION], "if": [_branch()]},
            {"actions": [ACTION], "if": [DENY_BRANCH], "required_conditions": [{"condition_key": KEY}]},
        ],
    )
    def test_includes_requirement_with_unscoped_allow_branch(self, requirement):
        assert ActionConditionEnforcementCheck.enforced_actions(_root(requirement)) == {ACTION}

    async def test_sensitive_action_still_reports_action_only_a_deny_branch_covers(self):
        check = SensitiveActionCheck()
        config = CheckConfig(
            check_id="sensitive_action",
            enabled=True,
            config={"sensitive_actions": ["iam:PassRole"]},
            root_config=_root({"actions": ["iam:PassRole"], "if": [DENY_BRANCH]}),
        )
        fetcher = AsyncMock()
        fetcher.expand_wildcard_action = AsyncMock(return_value=["iam:PassRole"])

        issues = await check.execute(
            Statement(Effect="Allow", Action=["iam:PassRole"], Resource=["*"]), 0, fetcher, config
        )

        assert [i.issue_type for i in issues] == ["missing_condition"]

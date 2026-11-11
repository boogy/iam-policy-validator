"""Unit tests for iam_validator.checks.utils.requirement_branches."""

import pytest

from iam_validator.checks.utils.requirement_branches import (
    branch_effects,
    branch_enforces_allow_everywhere,
    branch_matches_resources,
    branch_problem,
    requirement_branches,
)
from iam_validator.core.models import Statement

CONDS = [{"condition_key": "bedrock:bearerTokenType"}]


def _stmt(**kwargs) -> Statement:
    return Statement(effect="Allow", action="s3:GetObject", **kwargs)


def test_well_formed_branch_has_no_problem():
    branch = {
        "effect": ["allow", "Deny"],
        "resource": "arn:.*",
        "not_resource": "x",
        "severity": "high",
        "required_conditions": CONDS,
    }
    assert branch_problem(branch) is None


@pytest.mark.parametrize(
    ("branch", "fragment"),
    [
        ("Allow", "must be a mapping"),
        ({"resources": "x", "required_conditions": CONDS}, "unknown key(s) `resources`"),
        ({"effect": "Allow"}, "`required_conditions` is missing or empty"),
        ({"required_conditions": []}, "`required_conditions` is missing or empty"),
        ({"required_conditions": {}}, "`required_conditions` is missing or empty"),
        ({"required_conditions": {"all_of": []}}, "`required_conditions` is missing or empty"),
        ({"effect": "Permit", "required_conditions": CONDS}, "`effect` must be"),
        ({"effect": [], "required_conditions": CONDS}, "`effect` must be"),
        ({"resource": "arn:(", "required_conditions": CONDS}, "not a valid regex"),
        ({"resource": ["arn:.*"], "required_conditions": CONDS}, "must be a regex string"),
        ({"not_resource": 5, "required_conditions": CONDS}, "must be a regex string"),
        ({"severity": "urgent", "required_conditions": CONDS}, "`severity` must be"),
    ],
)
def test_branch_problem_reports(branch, fragment):
    problem = branch_problem(branch)
    assert problem is not None
    assert fragment in problem


@pytest.mark.parametrize("raw", [None, "Allow", {}, []])
def test_requirement_branches_rejects_non_list_or_empty_if(raw):
    branches, problems = requirement_branches({"if": raw})
    assert branches == []
    assert len(problems) == 1
    assert "`if` must be a non-empty list" in problems[0]


def test_requirement_branches_names_the_bad_branch_and_keeps_good_ones():
    good = {"effect": "Allow", "required_conditions": CONDS}
    branches, problems = requirement_branches({"if": [good, {"resources": "x", "required_conditions": CONDS}]})
    assert branches == [good]
    assert len(problems) == 1
    assert problems[0].startswith("`if[1]`")


def test_requirement_branches_adds_top_level_required_conditions_as_unscoped_branch():
    branches, problems = requirement_branches(
        {"if": [{"effect": "Deny", "required_conditions": CONDS}], "required_conditions": CONDS}
    )
    assert problems == []
    assert branches[-1] == {"required_conditions": CONDS}


def test_branch_effects_defaults_to_allow():
    assert branch_effects({}) == {"Allow"}
    assert branch_effects({"effect": "deny"}) == {"Deny"}
    assert branch_effects({"effect": ["ALLOW", "deny"]}) == {"Allow", "Deny"}


def test_resource_match_is_anchored():
    branch = {"resource": "arn:aws:s3:::prod"}
    assert branch_matches_resources(branch, _stmt(resource="arn:aws:s3:::prod"))
    assert not branch_matches_resources(branch, _stmt(resource="arn:aws:s3:::prod-backup"))
    assert not branch_matches_resources(branch, _stmt(resource="xarn:aws:s3:::prod"))


def test_resource_match_any_entry_and_case_sensitive():
    branch = {"resource": "arn:aws:s3:::prod/.*"}
    assert branch_matches_resources(branch, _stmt(resource=["arn:aws:s3:::dev/x", "arn:aws:s3:::prod/x"]))
    assert not branch_matches_resources(branch, _stmt(resource="arn:aws:s3:::PROD/x"))


def test_wildcard_resource_is_not_special_cased():
    assert not branch_matches_resources({"resource": "arn:aws:s3:::prod/.*"}, _stmt(resource="*"))
    assert branch_matches_resources({"resource": ".*"}, _stmt(resource="*"))


def test_resource_and_not_resource_target_their_own_field():
    assert not branch_matches_resources({"resource": ".*"}, _stmt(not_resource="arn:aws:s3:::prod/x"))
    assert branch_matches_resources({"not_resource": "arn:aws:s3:::prod/.*"}, _stmt(not_resource="arn:aws:s3:::prod/x"))
    assert not branch_matches_resources({"not_resource": ".*"}, _stmt(resource="arn:aws:s3:::prod/x"))


def test_resource_and_not_resource_both_must_match():
    stmt = _stmt(resource="arn:a", not_resource="arn:b")
    assert branch_matches_resources({"resource": "arn:a", "not_resource": "arn:b"}, stmt)
    assert not branch_matches_resources({"resource": "arn:a", "not_resource": "arn:c"}, stmt)


def test_branch_without_resource_keys_matches_any_statement():
    assert branch_matches_resources({}, _stmt(resource="anything"))


def test_branch_enforces_allow_everywhere():
    assert branch_enforces_allow_everywhere({})
    assert branch_enforces_allow_everywhere({"effect": ["Deny", "allow"]})
    assert not branch_enforces_allow_everywhere({"effect": "Deny"})
    assert not branch_enforces_allow_everywhere({"effect": "Allow", "resource": ".*"})
    assert not branch_enforces_allow_everywhere({"not_resource": ".*"})

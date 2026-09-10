"""Sensitive-action membership must follow AWS case-insensitivity."""

from iam_validator.checks.utils.sensitive_action_matcher import check_actions_config

DEFAULTS = frozenset({"iam:AttachRolePolicy", "iam:PassRole"})


def test_exact_case_matches():
    matched, actions = check_actions_config(["iam:AttachRolePolicy"], None, DEFAULTS)
    assert matched is True
    assert actions == ["iam:AttachRolePolicy"]


def test_lowercase_action_matches_default():
    matched, actions = check_actions_config(["iam:attachrolepolicy"], None, DEFAULTS)
    assert matched is True
    assert actions == ["iam:attachrolepolicy"]


def test_lowercase_action_matches_configured_list():
    matched, actions = check_actions_config(["iam:passrole"], ["iam:PassRole"], DEFAULTS)
    assert matched is True


def test_any_of_is_case_insensitive():
    matched, _ = check_actions_config(["IAM:PASSROLE"], {"any_of": ["iam:PassRole"]}, DEFAULTS)
    assert matched is True


def test_all_of_requires_every_action_case_insensitively():
    config = {"all_of": ["iam:PassRole", "iam:AttachRolePolicy"]}
    assert check_actions_config(["iam:passrole"], config, DEFAULTS)[0] is False
    assert check_actions_config(["iam:passrole", "iam:attachrolepolicy"], config, DEFAULTS)[0] is True


def test_unrelated_action_does_not_match():
    assert check_actions_config(["s3:GetObject"], None, DEFAULTS)[0] is False


def test_wildcard_candidate_matches_default():
    matched, actions = check_actions_config(["iam:PassRoleExtra"], ["iam:PassRole*"], DEFAULTS)
    assert matched is True
    assert actions == ["iam:PassRoleExtra"]


def test_question_mark_candidate_matches_default():
    matched, actions = check_actions_config(["iam:PassRolz"], ["iam:PassRol?"], DEFAULTS)
    assert matched is True
    assert actions == ["iam:PassRolz"]


def test_wildcard_action_matches_literal_default_candidate():
    """The fast literal-membership path must not swallow this direction: a wildcard
    action (e.g. from Action: "iam:*") still needs to match literal candidates
    since action_matches() is bidirectional."""
    matched, actions = check_actions_config(["iam:*"], None, DEFAULTS)
    assert matched is True
    assert actions == ["iam:*"]


def test_wildcard_action_matches_literal_any_of_candidate():
    matched, actions = check_actions_config(["iam:*"], {"any_of": ["iam:PassRole"]}, DEFAULTS)
    assert matched is True
    assert actions == ["iam:*"]


def test_wildcard_action_does_not_match_unrelated_literal_candidate():
    matched, _ = check_actions_config(["s3:*"], None, DEFAULTS)
    assert matched is False

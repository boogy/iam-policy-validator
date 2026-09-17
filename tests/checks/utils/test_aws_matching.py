"""AWS identifiers are case-insensitive and support '*' and '?' globs."""

import pytest

from iam_validator.checks.utils.aws_matching import (
    action_matches,
    compile_iam_glob,
    iam_glob_match,
    matches_all_of,
)


@pytest.mark.parametrize(
    "pattern,value",
    [
        ("s3:GetObject", "s3:getobject"),
        ("s3:getobject", "S3:GetObject"),
        ("iam:Get*", "iam:getrole"),
        ("s3:PutObjec?", "s3:PutObject"),
        ("iam:???ateRole", "iam:CreateRole"),
        ("s3:*", "s3:DeleteBucket"),
    ],
)
def test_glob_matches_case_insensitively(pattern, value):
    assert iam_glob_match(pattern, value) is True


@pytest.mark.parametrize(
    "pattern,value",
    [
        ("s3:PutObjec?", "s3:PutObjectAcl"),
        ("s3:Get*", "s3:PutObject"),
        ("s3:GetObject", "s3:GetObjectAcl"),
    ],
)
def test_glob_rejects_non_matches(pattern, value):
    assert iam_glob_match(pattern, value) is False


def test_compile_is_cached():
    assert compile_iam_glob("s3:Get*") is compile_iam_glob("s3:Get*")


@pytest.mark.parametrize(
    "statement_action,target",
    [
        ("*", "iam:AttachRolePolicy"),
        ("iam:attachrolepolicy", "iam:AttachRolePolicy"),
        ("iam:Attach*", "iam:AttachRolePolicy"),
        ("iam:AttachRolePolicy", "iam:Attach*"),
        ("iam:AttachRolePolic?", "iam:AttachRolePolicy"),
    ],
)
def test_action_matches_is_bidirectional_and_case_insensitive(statement_action, target):
    assert action_matches(statement_action, target) is True


def test_action_matches_rejects_unrelated():
    assert action_matches("s3:GetObject", "iam:AttachRolePolicy") is False


def test_matches_all_of_is_case_insensitive():
    required = ["iam:CreateUser", "iam:AttachUserPolicy"]
    assert matches_all_of(required, ["iam:createuser", "iam:attachuserpolicy"]) is True


def test_matches_all_of_rejects_case_variants_of_one_required_action():
    required = ["iam:CreateUser", "iam:AttachUserPolicy"]
    assert matches_all_of(required, ["iam:CreateUser", "iam:createuser"]) is False

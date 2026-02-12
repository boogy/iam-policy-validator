"""Tests for SDK policy utility functions."""

import json

import pytest

from iam_validator.core.models import IAMPolicy, Statement
from iam_validator.sdk.policy_utils import (
    extract_actions,
    extract_condition_keys,
    extract_condition_keys_from_statement,
    extract_resources,
    find_statements_with_action,
    find_statements_with_resource,
    get_policy_summary,
    has_public_access,
    is_resource_policy,
    merge_policies,
    normalize_policy,
    parse_policy,
    policy_to_dict,
    policy_to_json,
)

# ---------------------------------------------------------------------------
# parse_policy
# ---------------------------------------------------------------------------


class TestParsePolicy:
    """Tests for parse_policy()."""

    def test_parse_from_dict(self, valid_policy_dict):
        policy = parse_policy(valid_policy_dict)
        assert isinstance(policy, IAMPolicy)
        assert policy.version == "2012-10-17"
        assert len(policy.statement) == 1

    def test_parse_from_json_string(self, valid_policy_dict):
        json_str = json.dumps(valid_policy_dict)
        policy = parse_policy(json_str)
        assert isinstance(policy, IAMPolicy)
        assert policy.version == "2012-10-17"

    def test_parse_invalid_json_raises(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_policy("{not valid json}")

    def test_parse_empty_dict(self):
        # Empty dict is valid — policy fields are optional
        policy = parse_policy({})
        assert isinstance(policy, IAMPolicy)
        assert policy.statement is None

    def test_parse_policy_with_id(self):
        policy = parse_policy(
            {
                "Version": "2012-10-17",
                "Id": "MyPolicy",
                "Statement": [],
            }
        )
        assert policy.id == "MyPolicy"


# ---------------------------------------------------------------------------
# normalize_policy
# ---------------------------------------------------------------------------


class TestNormalizePolicy:
    """Tests for normalize_policy()."""

    def test_already_list(self, valid_policy):
        normalized = normalize_policy(valid_policy)
        assert isinstance(normalized.statement, list)
        assert len(normalized.statement) == 1

    def test_none_statement(self):
        policy = IAMPolicy(Version="2012-10-17", Statement=None)
        normalized = normalize_policy(policy)
        assert normalized.statement == []

    def test_string_action_wrapped(self):
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Allow", Action="s3:GetObject", Resource="*")],
        )
        normalized = normalize_policy(policy)
        stmt = normalized.statement[0]
        assert isinstance(stmt.action, list)
        assert stmt.action == ["s3:GetObject"]

    def test_string_resource_wrapped(self):
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Allow", Action=["s3:GetObject"], Resource="*")],
        )
        normalized = normalize_policy(policy)
        assert normalized.statement[0].resource == ["*"]

    def test_not_action_not_resource_wrapped(self, not_action_policy_dict):
        policy = parse_policy(not_action_policy_dict)
        normalized = normalize_policy(policy)
        stmt = normalized.statement[0]
        assert isinstance(stmt.not_action, list)
        assert isinstance(stmt.not_resource, list)

    def test_version_preserved(self, valid_policy):
        normalized = normalize_policy(valid_policy)
        assert normalized.version == valid_policy.version


# ---------------------------------------------------------------------------
# extract_actions
# ---------------------------------------------------------------------------


class TestExtractActions:
    """Tests for extract_actions()."""

    def test_single_action(self, valid_policy):
        actions = extract_actions(valid_policy)
        assert actions == ["s3:GetObject"]

    def test_multiple_actions(self, multi_statement_policy_dict):
        policy = parse_policy(multi_statement_policy_dict)
        actions = extract_actions(policy)
        assert "s3:GetObject" in actions
        assert "s3:ListBucket" in actions
        assert "s3:DeleteObject" in actions

    def test_deduplication(self):
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
            ],
        )
        actions = extract_actions(policy)
        assert actions.count("s3:GetObject") == 1

    def test_sorted_output(self):
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Action=["zzz:Action", "aaa:Action"],
                    Resource=["*"],
                )
            ],
        )
        actions = extract_actions(policy)
        assert actions == sorted(actions)

    def test_not_action_included(self, not_action_policy_dict):
        policy = parse_policy(not_action_policy_dict)
        actions = extract_actions(policy)
        assert "iam:ChangePassword" in actions
        assert "iam:GetUser" in actions

    def test_none_statement(self):
        policy = IAMPolicy(Version="2012-10-17", Statement=None)
        assert extract_actions(policy) == []


# ---------------------------------------------------------------------------
# extract_resources
# ---------------------------------------------------------------------------


class TestExtractResources:
    """Tests for extract_resources()."""

    def test_single_resource(self, valid_policy):
        resources = extract_resources(valid_policy)
        assert resources == ["arn:aws:s3:::my-bucket/*"]

    def test_multiple_resources(self, multi_statement_policy_dict):
        policy = parse_policy(multi_statement_policy_dict)
        resources = extract_resources(policy)
        assert "arn:aws:s3:::my-bucket" in resources
        assert "arn:aws:s3:::my-bucket/*" in resources

    def test_not_resource_included(self, not_action_policy_dict):
        policy = parse_policy(not_action_policy_dict)
        resources = extract_resources(policy)
        assert len(resources) == 1

    def test_none_statement(self):
        policy = IAMPolicy(Version="2012-10-17", Statement=None)
        assert extract_resources(policy) == []


# ---------------------------------------------------------------------------
# extract_condition_keys
# ---------------------------------------------------------------------------


class TestExtractConditionKeys:
    """Tests for extract_condition_keys and extract_condition_keys_from_statement."""

    def test_from_statement(self):
        stmt = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:SourceVpc": "vpc-1"}},
        )
        keys = extract_condition_keys_from_statement(stmt)
        assert keys == {"aws:SourceVpc"}

    def test_multiple_operators(self, condition_policy_dict):
        policy = parse_policy(condition_policy_dict)
        keys = extract_condition_keys(policy)
        assert "aws:SourceVpc" in keys
        assert "aws:SourceIp" in keys

    def test_no_conditions(self, valid_policy):
        keys = extract_condition_keys(valid_policy)
        assert keys == []

    def test_none_statement(self):
        policy = IAMPolicy(Version="2012-10-17", Statement=None)
        assert extract_condition_keys(policy) == []

    def test_empty_condition(self):
        stmt = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition=None,
        )
        keys = extract_condition_keys_from_statement(stmt)
        assert keys == set()


# ---------------------------------------------------------------------------
# find_statements_with_action
# ---------------------------------------------------------------------------


class TestFindStatementsWithAction:
    """Tests for find_statements_with_action()."""

    def test_exact_match(self, multi_statement_policy_dict):
        policy = parse_policy(multi_statement_policy_dict)
        stmts = find_statements_with_action(policy, "s3:DeleteObject")
        assert len(stmts) == 1
        assert stmts[0].sid == "DenyDelete"

    def test_wildcard_pattern(self, multi_statement_policy_dict):
        policy = parse_policy(multi_statement_policy_dict)
        stmts = find_statements_with_action(policy, "s3:*")
        # Both statements have s3: actions, wildcard should match
        assert len(stmts) == 2

    def test_no_match(self, valid_policy):
        stmts = find_statements_with_action(valid_policy, "ec2:RunInstances")
        assert stmts == []

    def test_none_statement(self):
        policy = IAMPolicy(Version="2012-10-17", Statement=None)
        assert find_statements_with_action(policy, "s3:GetObject") == []


# ---------------------------------------------------------------------------
# find_statements_with_resource
# ---------------------------------------------------------------------------


class TestFindStatementsWithResource:
    """Tests for find_statements_with_resource()."""

    def test_exact_match(self, valid_policy):
        stmts = find_statements_with_resource(valid_policy, "arn:aws:s3:::my-bucket/*")
        assert len(stmts) == 1

    def test_wildcard_match(self, multi_statement_policy_dict):
        policy = parse_policy(multi_statement_policy_dict)
        stmts = find_statements_with_resource(policy, "arn:aws:s3:::*")
        assert len(stmts) >= 1

    def test_no_match(self, valid_policy):
        stmts = find_statements_with_resource(valid_policy, "arn:aws:ec2:*:*:instance/*")
        assert stmts == []

    def test_none_statement(self):
        policy = IAMPolicy(Version="2012-10-17", Statement=None)
        assert find_statements_with_resource(policy, "*") == []


# ---------------------------------------------------------------------------
# merge_policies
# ---------------------------------------------------------------------------


class TestMergePolicies:
    """Tests for merge_policies()."""

    def test_merge_two_policies(self, valid_policy_dict, wildcard_policy_dict):
        p1 = parse_policy(valid_policy_dict)
        p2 = parse_policy(wildcard_policy_dict)
        merged = merge_policies(p1, p2)
        assert len(merged.statement) == 2

    def test_merge_preserves_version(self, valid_policy_dict):
        p1 = parse_policy(valid_policy_dict)
        p2 = parse_policy(valid_policy_dict)
        merged = merge_policies(p1, p2)
        assert merged.version == "2012-10-17"

    def test_merge_clears_id(self):
        p1 = parse_policy({"Version": "2012-10-17", "Id": "A", "Statement": []})
        p2 = parse_policy({"Version": "2012-10-17", "Id": "B", "Statement": []})
        merged = merge_policies(p1, p2)
        assert merged.id is None

    def test_merge_no_policies_raises(self):
        with pytest.raises(ValueError, match="At least one policy"):
            merge_policies()

    def test_merge_single_policy(self, valid_policy):
        merged = merge_policies(valid_policy)
        assert len(merged.statement) == 1

    def test_merge_with_none_statements(self):
        p1 = IAMPolicy(Version="2012-10-17", Statement=None)
        p2 = parse_policy(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        )
        merged = merge_policies(p1, p2)
        assert len(merged.statement) == 1


# ---------------------------------------------------------------------------
# get_policy_summary
# ---------------------------------------------------------------------------


class TestGetPolicySummary:
    """Tests for get_policy_summary()."""

    def test_basic_summary(self, valid_policy):
        summary = get_policy_summary(valid_policy)
        assert summary["version"] == "2012-10-17"
        assert summary["statement_count"] == 1
        assert summary["allow_statements"] == 1
        assert summary["deny_statements"] == 0
        assert summary["action_count"] == 1
        assert summary["resource_count"] == 1

    def test_wildcard_detection(self, wildcard_policy_dict):
        policy = parse_policy(wildcard_policy_dict)
        summary = get_policy_summary(policy)
        assert summary["has_wildcard_actions"] is True
        assert summary["has_wildcard_resources"] is True

    def test_no_wildcards(self, valid_policy):
        summary = get_policy_summary(valid_policy)
        assert summary["has_wildcard_actions"] is False

    def test_multi_statement_counts(self, multi_statement_policy_dict):
        policy = parse_policy(multi_statement_policy_dict)
        summary = get_policy_summary(policy)
        assert summary["statement_count"] == 2
        assert summary["allow_statements"] == 1
        assert summary["deny_statements"] == 1

    def test_condition_keys_counted(self, condition_policy_dict):
        policy = parse_policy(condition_policy_dict)
        summary = get_policy_summary(policy)
        assert summary["condition_key_count"] == 2


# ---------------------------------------------------------------------------
# policy_to_json / policy_to_dict
# ---------------------------------------------------------------------------


class TestPolicyConversion:
    """Tests for policy_to_json() and policy_to_dict()."""

    def test_to_json_valid(self, valid_policy):
        result = policy_to_json(valid_policy)
        parsed = json.loads(result)
        assert "Version" in parsed
        assert "Statement" in parsed

    def test_to_json_custom_indent(self, valid_policy):
        result = policy_to_json(valid_policy, indent=4)
        assert "    " in result

    def test_to_dict(self, valid_policy):
        d = policy_to_dict(valid_policy)
        assert isinstance(d, dict)
        assert d["Version"] == "2012-10-17"

    def test_to_dict_uses_aliases(self, valid_policy):
        d = policy_to_dict(valid_policy)
        # Should use AWS aliases (Version, Statement, Effect, Action, Resource)
        assert "Version" in d
        assert "Statement" in d
        stmt = d["Statement"][0]
        assert "Effect" in stmt

    def test_roundtrip(self, valid_policy_dict):
        policy = parse_policy(valid_policy_dict)
        d = policy_to_dict(policy)
        # Re-parse should work
        policy2 = parse_policy(d)
        assert policy2.version == policy.version


# ---------------------------------------------------------------------------
# is_resource_policy
# ---------------------------------------------------------------------------


class TestIsResourcePolicy:
    """Tests for is_resource_policy()."""

    def test_identity_policy(self, valid_policy):
        assert is_resource_policy(valid_policy) is False

    def test_resource_policy(self, resource_policy_dict):
        policy = parse_policy(resource_policy_dict)
        assert is_resource_policy(policy) is True

    def test_public_access_is_resource_policy(self, public_access_policy_dict):
        policy = parse_policy(public_access_policy_dict)
        assert is_resource_policy(policy) is True

    def test_none_statement(self):
        policy = IAMPolicy(Version="2012-10-17", Statement=None)
        assert is_resource_policy(policy) is False


# ---------------------------------------------------------------------------
# has_public_access
# ---------------------------------------------------------------------------


class TestHasPublicAccess:
    """Tests for has_public_access()."""

    def test_public_principal_star(self, public_access_policy_dict):
        policy = parse_policy(public_access_policy_dict)
        assert has_public_access(policy) is True

    def test_no_public_access(self, resource_policy_dict):
        policy = parse_policy(resource_policy_dict)
        assert has_public_access(policy) is False

    def test_identity_policy_no_public(self, valid_policy):
        assert has_public_access(valid_policy) is False

    def test_principal_aws_star(self):
        policy = parse_policy(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ],
            }
        )
        assert has_public_access(policy) is True

    def test_principal_list_with_star(self):
        policy = parse_policy(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": ["arn:aws:iam::123:root", "*"]},
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ],
            }
        )
        assert has_public_access(policy) is True

    def test_none_statement(self):
        policy = IAMPolicy(Version="2012-10-17", Statement=None)
        assert has_public_access(policy) is False

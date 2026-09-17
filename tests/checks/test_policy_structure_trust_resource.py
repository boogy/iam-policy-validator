"""AWS rejects a role trust policy that names a Resource or NotResource."""

import pytest

from iam_validator.checks.policy_structure import validate_statement_structure

TRUST_STATEMENT = {
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole",
}


def _issue_types(statement_dict, policy_type):
    return [i.issue_type for i in validate_statement_structure(statement_dict, 0, policy_type)]


class TestTrustPolicyRejectsResource:
    @pytest.mark.parametrize("field", ["Resource", "NotResource"])
    @pytest.mark.parametrize("value", ["*", "arn:aws:iam::123456789012:role/MyRole"])
    async def test_resource_field_is_an_error(self, field, value):
        issues = validate_statement_structure({**TRUST_STATEMENT, field: value}, 0, "TRUST_POLICY")

        resource_issues = [i for i in issues if i.issue_type == "unexpected_resource"]
        assert len(resource_issues) == 1
        assert resource_issues[0].severity == "error"
        assert f"`{field}`" in resource_issues[0].message

    async def test_both_fields_are_named_in_one_issue(self):
        issues = validate_statement_structure(
            {**TRUST_STATEMENT, "Resource": "*", "NotResource": "*"}, 0, "TRUST_POLICY"
        )

        resource_issues = [i for i in issues if i.issue_type == "unexpected_resource"]
        assert len(resource_issues) == 1
        assert "`Resource`" in resource_issues[0].message
        assert "`NotResource`" in resource_issues[0].message
        assert "resource_conflict" not in {i.issue_type for i in issues}

    async def test_a_trust_policy_without_resource_is_still_clean(self):
        assert _issue_types(TRUST_STATEMENT, "TRUST_POLICY") == []


class TestOtherPolicyTypesAreUnaffected:
    @pytest.mark.parametrize("policy_type", ["IDENTITY_POLICY", "RESOURCE_POLICY", "SERVICE_CONTROL_POLICY"])
    async def test_resource_is_not_flagged(self, policy_type):
        statement = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}

        assert "unexpected_resource" not in _issue_types(statement, policy_type)

    @pytest.mark.parametrize("policy_type", ["IDENTITY_POLICY", "RESOURCE_POLICY"])
    async def test_resource_and_not_resource_together_still_conflict(self, policy_type):
        statement = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "NotResource": "*"}

        assert "resource_conflict" in _issue_types(statement, policy_type)

    async def test_missing_resource_is_still_info_outside_trust_policies(self):
        statement = {"Effect": "Allow", "Action": "s3:GetObject"}

        assert "missing_resource" in _issue_types(statement, "IDENTITY_POLICY")

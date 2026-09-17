"""Severity precedence (condition > requirement > global) applies to any_of and none_of, not just all_of."""

from unittest.mock import AsyncMock

import pytest

from iam_validator.checks.action_condition_enforcement import ActionConditionEnforcementCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.config.condition_requirements import S3_ORG_BOUNDARY
from iam_validator.core.models import IAMPolicy, Statement

GLOBAL_SEVERITY = ActionConditionEnforcementCheck.default_severity


@pytest.fixture
def check():
    return ActionConditionEnforcementCheck()


async def _run(check, requirements, *statements):
    config = CheckConfig(
        check_id="action_condition_enforcement",
        enabled=True,
        config={"requirements": requirements},
    )
    policy = IAMPolicy(version="2012-10-17", statement=list(statements))
    return await check.execute_policy(policy, "policy.json", AsyncMock(), config)


def _missing(action):
    return Statement(Effect="Allow", Action=[action], Resource=["*"])


def _with_secure_transport(action):
    return Statement(
        Effect="Allow",
        Action=[action],
        Resource=["*"],
        Condition={"Bool": {"aws:SecureTransport": "true"}},
    )


class TestAnyOf:
    async def test_requirement_severity_is_honored(self, check):
        requirement = {
            "actions": ["s3:DeleteObject"],
            "severity": "critical",
            "required_conditions": {"any_of": [{"condition_key": "aws:PrincipalOrgID"}]},
        }

        issues = await _run(check, [requirement], _missing("s3:DeleteObject"))

        assert [(i.issue_type, i.severity) for i in issues] == [("missing_required_condition_any_of", "critical")]

    async def test_a_shipped_requirement_keeps_its_declared_severity(self, check):
        issues = await _run(check, [S3_ORG_BOUNDARY], _missing("s3:GetObject"))

        assert S3_ORG_BOUNDARY["severity"] != GLOBAL_SEVERITY
        assert [i.severity for i in issues] == [S3_ORG_BOUNDARY["severity"]]

    async def test_global_severity_is_the_fallback(self, check):
        requirement = {
            "actions": ["s3:DeleteObject"],
            "required_conditions": {"any_of": [{"condition_key": "aws:PrincipalOrgID"}]},
        }

        issues = await _run(check, [requirement], _missing("s3:DeleteObject"))

        assert [i.severity for i in issues] == [GLOBAL_SEVERITY]


class TestNoneOf:
    async def test_requirement_severity_is_honored(self, check):
        requirement = {
            "actions": ["s3:PutObject"],
            "severity": "low",
            "required_conditions": {"none_of": [{"condition_key": "aws:SecureTransport"}]},
        }

        issues = await _run(check, [requirement], _with_secure_transport("s3:PutObject"))

        assert [(i.issue_type, i.severity) for i in issues] == [("forbidden_condition_present", "low")]

    async def test_condition_severity_outranks_the_requirement(self, check):
        requirement = {
            "actions": ["s3:PutObject"],
            "severity": "low",
            "required_conditions": {"none_of": [{"condition_key": "aws:SecureTransport", "severity": "critical"}]},
        }

        issues = await _run(check, [requirement], _with_secure_transport("s3:PutObject"))

        assert [i.severity for i in issues] == ["critical"]

    async def test_global_severity_is_the_fallback(self, check):
        requirement = {
            "actions": ["s3:PutObject"],
            "required_conditions": {"none_of": [{"condition_key": "aws:SecureTransport"}]},
        }

        issues = await _run(check, [requirement], _with_secure_transport("s3:PutObject"))

        assert [i.severity for i in issues] == [GLOBAL_SEVERITY]


class TestAllOfKeepsItsBehavior:
    @pytest.mark.parametrize(
        ("requirement_severity", "condition_severity", "expected"),
        [
            ("low", None, "low"),
            ("low", "critical", "critical"),
            (None, None, GLOBAL_SEVERITY),
        ],
    )
    async def test_precedence(self, check, requirement_severity, condition_severity, expected):
        condition = {"condition_key": "aws:PrincipalOrgID"}
        if condition_severity:
            condition["severity"] = condition_severity
        requirement = {"actions": ["s3:GetObject"], "required_conditions": {"all_of": [condition]}}
        if requirement_severity:
            requirement["severity"] = requirement_severity

        issues = await _run(check, [requirement], _missing("s3:GetObject"))

        assert [i.severity for i in issues] == [expected]

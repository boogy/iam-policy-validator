"""Sensitive action detection must not depend on the action's letter casing."""

import pytest


async def test_lowercase_action_is_still_detected(mock_fetcher, default_config):
    from iam_validator.checks.sensitive_action import SensitiveActionCheck
    from iam_validator.core.models import Statement

    check = SensitiveActionCheck()
    upper = Statement(effect="Allow", action=["iam:AttachRolePolicy"], resource=["*"])
    lower = Statement(effect="Allow", action=["iam:attachrolepolicy"], resource=["*"])

    upper_issues = await check.execute(upper, 0, mock_fetcher, default_config)
    lower_issues = await check.execute(lower, 0, mock_fetcher, default_config)

    assert len(upper_issues) > 0
    assert len(lower_issues) == len(upper_issues)


@pytest.mark.parametrize(
    "condition",
    [
        {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
        {"Bool": {"aws:SecureTransport": "true"}},
        {"Bool": {"aws:SecureTransport": "true"}, "StringEquals": {"AWS:REQUESTEDREGION": "us-east-1"}},
    ],
)
async def test_non_restricting_condition_does_not_suppress_finding(mock_fetcher, default_config, condition):
    from iam_validator.checks.sensitive_action import SensitiveActionCheck
    from iam_validator.core.models import Statement

    check = SensitiveActionCheck()
    statement = Statement(effect="Allow", action=["iam:AttachRolePolicy"], resource=["*"], condition=condition)
    assert await check.execute(statement, 0, mock_fetcher, default_config)


@pytest.mark.parametrize(
    "condition",
    [
        {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        {"DateLessThan": {"aws:CurrentTime": "2030-01-01T00:00:00Z"}},
        {"StringEquals": {"aws:RequestedRegion": "us-east-1", "aws:PrincipalTag/team": "admins"}},
    ],
)
async def test_restricting_condition_suppresses_finding(mock_fetcher, default_config, condition):
    from iam_validator.checks.sensitive_action import SensitiveActionCheck
    from iam_validator.core.models import Statement

    check = SensitiveActionCheck()
    statement = Statement(effect="Allow", action=["iam:AttachRolePolicy"], resource=["*"], condition=condition)
    assert await check.execute(statement, 0, mock_fetcher, default_config) == []

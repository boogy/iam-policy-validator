"""Sensitive action detection must not depend on the action's letter casing."""

import pytest


@pytest.mark.xfail(reason="fixed in Task 8: sensitive_action_matcher case-insensitivity", strict=True)
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

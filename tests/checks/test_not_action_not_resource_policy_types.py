"""not_action_not_resource drops Allow-grant findings in SCPs/RCPs but keeps Deny findings."""

from unittest.mock import MagicMock

import pytest

from iam_validator.checks.not_action_not_resource import NotActionNotResourceCheck
from iam_validator.core.check_registry import CheckConfig, CheckRegistry
from iam_validator.core.models import Statement

ALLOW_NOT_ACTION = Statement(effect="Allow", not_action=["iam:*"], resource="*")
DENY_NOT_RESOURCE_STAR = Statement(effect="Deny", action=["s3:*"], not_resource=["*"])


def _registry() -> CheckRegistry:
    registry = CheckRegistry(enable_parallel=False)
    registry.register(NotActionNotResourceCheck())
    registry.configure_check("not_action_not_resource", CheckConfig(check_id="not_action_not_resource", enabled=True))
    return registry


async def _issue_types(statement: Statement, policy_type: str) -> set[str]:
    issues = await _registry().execute_checks_parallel(statement, 0, MagicMock(), policy_type=policy_type)
    return {issue.issue_type for issue in issues}


@pytest.mark.asyncio
async def test_allow_not_action_is_flagged_in_identity_policy():
    assert "not_action_allow_no_condition" in await _issue_types(ALLOW_NOT_ACTION, "IDENTITY_POLICY")


@pytest.mark.asyncio
@pytest.mark.parametrize("policy_type", ["SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"])
async def test_allow_not_action_is_not_a_grant_in_boundary_policies(policy_type):
    assert await _issue_types(ALLOW_NOT_ACTION, policy_type) == set()


@pytest.mark.asyncio
async def test_ineffective_deny_is_still_reported_in_scp():
    assert "not_resource_deny_ineffective" in await _issue_types(DENY_NOT_RESOURCE_STAR, "SERVICE_CONTROL_POLICY")

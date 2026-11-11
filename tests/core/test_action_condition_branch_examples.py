"""The `if:` examples in examples/configs/action-condition-branches.yaml behave as their comments say."""

from pathlib import Path
from typing import Any

import pytest

from iam_validator.checks.action_condition_enforcement import ActionConditionEnforcementCheck
from iam_validator.checks.utils.requirement_branches import requirement_branches
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.config.config_loader import ConfigLoader
from iam_validator.core.models import IAMPolicy, Statement

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "configs" / "action-condition-branches.yaml"
PROD_SECRET = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf"
DEV_SECRET = "arn:aws:secretsmanager:us-east-1:123456789012:secret:dev/db-AbCdEf"
PROD_ROLE = "arn:aws:iam::123456789012:role/prod-app"
DEV_ROLE = "arn:aws:iam::123456789012:role/dev-app"
MFA = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
VPCE_ALLOW = {"StringEquals": {"aws:SourceVpce": "vpce-1a2b3c4d"}}
VPCE_DENY = {"StringNotEquals": {"aws:SourceVpce": "vpce-1a2b3c4d"}}
PASSED_TO = {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}


@pytest.fixture(scope="module")
def config() -> CheckConfig:
    own = ConfigLoader.load_yaml(EXAMPLE)["action_condition_enforcement"]
    return CheckConfig(
        check_id="action_condition_enforcement",
        enabled=True,
        config={**own, "merge_strategy": "user_only"},
    )


async def _keys(config: CheckConfig, effect: str, action: str, condition: dict | None = None, **fields: Any):
    if "not_resource" not in fields:
        fields.setdefault("resource", "*")
    statement = Statement(effect=effect, action=action, condition=condition, **fields)
    policy = IAMPolicy(version="2012-10-17", statement=[statement])
    issues = await ActionConditionEnforcementCheck().execute_policy(policy, "policy.json", None, config)
    return sorted(i.condition_key for i in issues)


def test_example_branches_are_well_formed(config):
    for requirement in config.config["action_condition_requirements"]:
        assert requirement_branches(requirement)[1] == []


@pytest.mark.parametrize(
    ("effect", "condition", "expected"),
    [
        ("Allow", None, ["bedrock:bearerTokenType"]),
        ("Allow", {"StringEquals": {"bedrock:bearerTokenType": "SHORT_TERM"}}, []),
        ("Deny", None, ["bedrock:bearerTokenType"]),
        ("Deny", {"StringNotEquals": {"bedrock:bearerTokenType": "SHORT_TERM"}}, []),
    ],
)
async def test_effect_branches(config, effect, condition, expected):
    assert await _keys(config, effect, "bedrock:CallWithBearerToken", condition) == expected


@pytest.mark.parametrize(
    ("resource", "condition", "expected"),
    [
        ("arn:aws:s3:::prod-logs/*", None, ["aws:MultiFactorAuthPresent"]),
        ("arn:aws:s3:::prod*", None, ["aws:MultiFactorAuthPresent"]),
        ("*", None, ["aws:MultiFactorAuthPresent"]),
        ("arn:aws:s3:::prod-logs/*", MFA, []),
        ("arn:aws:s3:::dev-logs/*", None, []),
    ],
)
async def test_resource_only_branch(config, resource, condition, expected):
    assert await _keys(config, "Allow", "s3:DeleteObject", condition, resource=resource) == expected


async def test_resource_only_branch_skips_deny(config):
    assert await _keys(config, "Deny", "s3:DeleteObject", resource="arn:aws:s3:::prod-logs/*") == []


@pytest.mark.parametrize(
    ("effect", "resource", "condition", "expected"),
    [
        ("Allow", PROD_SECRET, None, ["aws:SourceVpce"]),
        ("Allow", PROD_SECRET, VPCE_ALLOW, []),
        ("Deny", PROD_SECRET, None, ["aws:SourceVpce"]),
        ("Deny", PROD_SECRET, VPCE_DENY, []),
        ("Allow", DEV_SECRET, None, []),
        ("Deny", DEV_SECRET, None, []),
    ],
)
async def test_effect_and_resource_branches(config, effect, resource, condition, expected):
    assert await _keys(config, effect, "secretsmanager:GetSecretValue", condition, resource=resource) == expected


async def test_not_resource_branch(config):
    assert await _keys(config, "Allow", "s3:GetObject", not_resource="arn:aws:s3:::secret/*") == ["s3:ResourceAccount"]
    assert await _keys(config, "Allow", "s3:GetObject", resource="arn:aws:s3:::logs/*") == []


@pytest.mark.parametrize("effect", ["Allow", "Deny"])
async def test_effect_list_branch(config, effect):
    assert await _keys(config, effect, "ec2:RunInstances") == ["aws:RequestedRegion"]


@pytest.mark.parametrize(
    ("effect", "resource", "condition", "expected"),
    [
        ("Allow", DEV_ROLE, None, ["iam:PassedToService"]),
        ("Allow", DEV_ROLE, PASSED_TO, []),
        ("Allow", PROD_ROLE, PASSED_TO, ["iam:AssociatedResourceArn"]),
        ("Deny", PROD_ROLE, None, []),
    ],
)
async def test_top_level_conditions_beside_branches(config, effect, resource, condition, expected):
    assert await _keys(config, effect, "iam:PassRole", condition, resource=resource) == expected

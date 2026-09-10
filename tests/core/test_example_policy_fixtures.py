"""The boundary-policy and web-identity example fixtures must validate clean."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.checks.policy_structure import detect_policy_type
from iam_validator.core.aws_service.validators import ConditionKeyValidationResult
from iam_validator.core.check_registry import create_default_registry
from iam_validator.core.config.config_loader import ConfigLoader, ValidatorConfig
from iam_validator.core.models import IAMPolicy
from iam_validator.core.policy_checks import _resolve_policy_type, _validate_policy_with_registry

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"

# (relative_path, policy_types glob mapping). SCP/RCP share the identity-policy
# shape and cannot be auto-detected (see root CLAUDE.md "Policy Type
# Resolution"), so they're driven the way a user would via a config glob. The
# trust-policy fixture gets an empty mapping so it goes through real
# auto-detection.
CLEAN_FIXTURES = [
    (
        "iam-test-policies/service-control-policies/full-aws-access.json",
        [{"pattern": "**/service-control-policies/*.json", "type": "SERVICE_CONTROL_POLICY"}],
    ),
    (
        "iam-test-policies/resource-control-policies/rcp-valid-full-aws-access.json",
        [{"pattern": "**/resource-control-policies/*.json", "type": "RESOURCE_CONTROL_POLICY"}],
    ),
    ("trust-policies/cognito-identity-pool-trust-policy.json", []),
]


@pytest.fixture
def offline_fetcher():
    fetcher = MagicMock()
    fetcher.validate_action = AsyncMock(return_value=(True, None, False))
    fetcher.expand_wildcard_action = AsyncMock(return_value=[])
    fetcher.fetch_service_by_name = AsyncMock(return_value=MagicMock())
    fetcher.validate_actions_batch = AsyncMock(return_value={})
    fetcher.validate_condition_key = AsyncMock(return_value=ConditionKeyValidationResult(is_valid=True))
    return fetcher


def _default_registry():
    """Registry built exactly as ``validate_policies`` builds it from the defaults."""
    config = ValidatorConfig()
    registry = create_default_registry(
        enable_parallel=config.get_setting("parallel_execution", True),
        include_builtin_checks=True,
        suppress_superseded=config.get_setting("suppress_superseded_findings", False),
    )
    ConfigLoader.apply_config_to_registry(config, registry)
    return registry


@pytest.mark.parametrize(("relative_path", "policy_types_config"), CLEAN_FIXTURES)
async def test_fixture_validates_clean(relative_path, policy_types_config, offline_fetcher):
    raw = json.loads((EXAMPLES / relative_path).read_text())
    policy = IAMPolicy.model_validate(raw)
    config = ValidatorConfig({"policy_types": policy_types_config})
    resolved_type, _source, _pattern = _resolve_policy_type(policy, relative_path, None, config)

    result = await _validate_policy_with_registry(
        policy=policy,
        policy_file=relative_path,
        registry=_default_registry(),
        fetcher=offline_fetcher,
        fail_on_severities=["error", "critical"],
        policy_type=resolved_type,
        raw_policy_dict=raw,
    )
    assert result.issues == []


async def test_rcp_full_aws_access_no_longer_autodetects_as_trust_policy():
    """Regression test: a bare ``"*"`` action is not evidence of role assumption.

    AWS's default RCP statement (``Principal: "*"``, ``Action: "*"``,
    ``Resource: "*"``) must not auto-detect as ``TRUST_POLICY``.
    """
    raw = json.loads(
        (EXAMPLES / "iam-test-policies/resource-control-policies/rcp-valid-full-aws-access.json").read_text()
    )
    detected = detect_policy_type(IAMPolicy.model_validate(raw))
    assert detected != "TRUST_POLICY"
    assert detected == "RESOURCE_POLICY"

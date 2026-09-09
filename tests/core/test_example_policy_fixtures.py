"""The boundary-policy and web-identity example fixtures must validate clean."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.aws_service.validators import ConditionKeyValidationResult
from iam_validator.core.check_registry import create_default_registry
from iam_validator.core.config.config_loader import ConfigLoader, ValidatorConfig
from iam_validator.core.models import IAMPolicy
from iam_validator.core.policy_checks import _validate_policy_with_registry

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"

CLEAN_FIXTURES = [
    ("iam-test-policies/service-control-policies/full-aws-access.json", "SERVICE_CONTROL_POLICY"),
    ("iam-test-policies/resource-control-policies/rcp-valid-full-aws-access.json", "RESOURCE_CONTROL_POLICY"),
    ("trust-policies/cognito-identity-pool-trust-policy.json", "TRUST_POLICY"),
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


@pytest.mark.parametrize(("relative_path", "policy_type"), CLEAN_FIXTURES)
async def test_fixture_validates_clean(relative_path, policy_type, offline_fetcher):
    raw = json.loads((EXAMPLES / relative_path).read_text())
    result = await _validate_policy_with_registry(
        policy=IAMPolicy.model_validate(raw),
        policy_file=relative_path,
        registry=_default_registry(),
        fetcher=offline_fetcher,
        fail_on_severities=["error", "critical"],
        policy_type=policy_type,
        raw_policy_dict=raw,
    )
    assert result.issues == []

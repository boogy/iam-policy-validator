"""Severity precedence for sensitive_action: user category > user severity > built-in category."""

import pytest

from iam_validator.checks.sensitive_action import SensitiveActionCheck
from iam_validator.core.check_registry import CheckConfig, create_default_registry
from iam_validator.core.config.config_loader import ConfigLoader, ValidatorConfig
from iam_validator.core.models import Statement

# credential_exposure → built-in "critical"
ACTION = "secretsmanager:GetSecretValue"


def _statement() -> Statement:
    return Statement(effect="Allow", action=[ACTION], resource=["arn:aws:secretsmanager:*:*:secret:app"])


async def _severity(config: CheckConfig, mock_fetcher) -> str:
    issues = await SensitiveActionCheck().execute(_statement(), 0, mock_fetcher, config)
    assert len(issues) == 1
    return issues[0].severity


@pytest.mark.asyncio
async def test_builtin_category_severity_applies_without_overrides(mock_fetcher):
    config = CheckConfig(check_id="sensitive_action")
    assert await _severity(config, mock_fetcher) == "critical"


@pytest.mark.asyncio
async def test_check_severity_overrides_builtin_categories(mock_fetcher):
    config = CheckConfig(check_id="sensitive_action", severity="low")
    assert await _severity(config, mock_fetcher) == "low"


@pytest.mark.asyncio
async def test_user_category_severity_wins_over_check_severity(mock_fetcher):
    config = CheckConfig(
        check_id="sensitive_action",
        severity="low",
        config={"category_severities": {"credential_exposure": "high"}},
    )
    assert await _severity(config, mock_fetcher) == "high"


def _scoped(action: str) -> Statement:
    return Statement(
        effect="Allow",
        action=[action],
        resource=["arn:aws:secretsmanager:us-east-1:123456789012:secret:app-AbCdEf"],
    )


async def _scoped_severity(action: str, config: CheckConfig, mock_fetcher) -> str:
    issues = await SensitiveActionCheck().execute(_scoped(action), 0, mock_fetcher, config)
    assert len(issues) == 1
    return issues[0].severity


@pytest.mark.asyncio
async def test_read_of_a_specific_resource_is_medium_by_default(mock_fetcher):
    """A least-privilege read of one named secret must not fail the default gate."""
    config = CheckConfig(check_id="sensitive_action")
    assert await _scoped_severity(ACTION, config, mock_fetcher) == "medium"


@pytest.mark.asyncio
async def test_priv_esc_on_a_specific_resource_keeps_its_severity(mock_fetcher):
    config = CheckConfig(check_id="sensitive_action")
    assert await _scoped_severity("iam:CreatePolicyVersion", config, mock_fetcher) == "critical"


@pytest.mark.asyncio
async def test_scoped_ceiling_can_be_disabled(mock_fetcher):
    config = CheckConfig(check_id="sensitive_action", config={"scoped_resource_severities": {}})
    assert await _scoped_severity(ACTION, config, mock_fetcher) == "critical"


@pytest.mark.asyncio
async def test_scoped_ceiling_never_lowers_a_user_severity(mock_fetcher):
    config = CheckConfig(check_id="sensitive_action", severity="critical")
    assert await _scoped_severity(ACTION, config, mock_fetcher) == "critical"


@pytest.mark.asyncio
async def test_severity_from_a_config_file_is_honoured(mock_fetcher):
    """End to end through the shipped defaults: `sensitive_action.severity` must not be ignored."""
    registry = create_default_registry()
    ConfigLoader.apply_config_to_registry(ValidatorConfig({"sensitive_action": {"severity": "low"}}), registry)
    config = registry.get_config("sensitive_action")
    assert config is not None
    assert await _severity(config, mock_fetcher) == "low"

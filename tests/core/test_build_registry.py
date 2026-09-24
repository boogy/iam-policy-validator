"""Unit tests for `build_registry` and `validate_policies(registry=...)`."""

from unittest.mock import MagicMock

from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.config.config_loader import ConfigLoader, ValidatorConfig
from iam_validator.core.models import IAMPolicy
from iam_validator.core.policy_checks import build_registry, validate_policies

_WILDCARD_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


def _registry_signature(registry):
    return {
        check_id: (config.enabled, config.severity)
        for check_id, config in ((c.check_id, registry.get_config(c.check_id)) for c in registry.get_all_checks())
    }


async def test_build_registry_matches_validate_policies_internal_registry(monkeypatch):
    config = ValidatorConfig()
    standalone_registry = build_registry(config)

    captured: list = []
    real = build_registry

    def spy(*args, **kwargs):
        registry = real(*args, **kwargs)
        captured.append(registry)
        return registry

    monkeypatch.setattr("iam_validator.core.policy_checks.build_registry", spy)

    policy = IAMPolicy.model_validate(_WILDCARD_POLICY)
    await validate_policies([("inline.json", policy, _WILDCARD_POLICY)], config=config)

    assert len(captured) == 1
    assert _registry_signature(captured[0]) == _registry_signature(standalone_registry)


async def test_validate_policies_with_registry_skips_construction(monkeypatch):
    config = ValidatorConfig()
    registry = build_registry(config)

    create_default_registry = MagicMock()
    monkeypatch.setattr("iam_validator.core.policy_checks.create_default_registry", create_default_registry)
    monkeypatch.setattr(ConfigLoader, "load_custom_checks", MagicMock())
    monkeypatch.setattr(ConfigLoader, "discover_checks_in_directory", MagicMock())

    policy = IAMPolicy.model_validate(_WILDCARD_POLICY)
    await validate_policies([("inline.json", policy, _WILDCARD_POLICY)], config=config, registry=registry)

    create_default_registry.assert_not_called()
    ConfigLoader.load_custom_checks.assert_not_called()
    ConfigLoader.discover_checks_in_directory.assert_not_called()


async def test_validate_policies_uses_the_given_registry_not_a_rebuilt_one():
    config = ValidatorConfig()

    baseline_registry = build_registry(config)
    baseline_results = await validate_policies(
        [("inline.json", IAMPolicy.model_validate(_WILDCARD_POLICY), _WILDCARD_POLICY)],
        config=config,
        registry=baseline_registry,
    )
    baseline_check_ids = {i.check_id for r in baseline_results for i in r.issues}
    assert "full_wildcard" in baseline_check_ids

    disabled_registry = build_registry(config)
    disabled_registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=False))
    disabled_results = await validate_policies(
        [("inline.json", IAMPolicy.model_validate(_WILDCARD_POLICY), _WILDCARD_POLICY)],
        config=config,
        registry=disabled_registry,
    )
    disabled_check_ids = {i.check_id for r in disabled_results for i in r.issues}
    assert "full_wildcard" not in disabled_check_ids

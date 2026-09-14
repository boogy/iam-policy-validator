"""Options from a `custom_checks:` module entry survive the orchestrator's config passes."""

import logging
import textwrap

import pytest

from iam_validator.core.check_registry import CheckRegistry
from iam_validator.core.config.config_loader import ConfigLoader, ValidatorConfig
from iam_validator.core.models import IAMPolicy
from iam_validator.core.policy_checks import validate_policies

_CHECK_SOURCE = textwrap.dedent(
    """
    from iam_validator.core.check_registry import PolicyCheck
    from iam_validator.core.models import ValidationIssue


    class RequireTag(PolicyCheck):
        check_id = "require_tag"
        description = "class description"
        default_severity = "low"

        async def execute(self, statement, statement_idx, fetcher, config):
            return [
                ValidationIssue(
                    severity=self.get_severity(config),
                    statement_index=statement_idx,
                    issue_type="require_tag_demo",
                    message=f"{config.config.get('required_tag')}|{config.config.get('mode')}|{config.description}",
                )
            ]
    """
)

_ENTRY = {
    "module": "cc_module_config_pkg.require_tag.RequireTag",
    "severity": "high",
    "description": "entry description",
    "config": {"required_tag": "Owner", "mode": "strict"},
}


@pytest.fixture
def check_module(tmp_path, monkeypatch):
    package = tmp_path / "cc_module_config_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "require_tag.py").write_text(_CHECK_SOURCE)
    monkeypatch.syspath_prepend(str(tmp_path))


def _load_and_apply(config: ValidatorConfig) -> CheckRegistry:
    registry = CheckRegistry()
    ConfigLoader.load_custom_checks(config, registry)
    ConfigLoader.apply_config_to_registry(config, registry)
    return registry


def test_module_entry_survives_apply_config_to_registry(check_module):
    registry = _load_and_apply(ValidatorConfig({"custom_checks": [_ENTRY]}, use_defaults=False))

    applied = registry.get_config("require_tag")
    assert applied.severity == "high"
    assert applied.description == "entry description"
    assert applied.config["required_tag"] == "Owner"
    assert applied.config["mode"] == "strict"


def test_module_entry_config_key_does_not_trigger_nested_options_warning(check_module, caplog):
    with caplog.at_level(logging.WARNING):
        _load_and_apply(ValidatorConfig({"custom_checks": [_ENTRY]}, use_defaults=False))

    assert not [r for r in caplog.records if "nested under `config:`" in r.getMessage()]


def test_top_level_section_overrides_module_entry_per_key(check_module):
    config = ValidatorConfig(
        {"custom_checks": [_ENTRY], "require_tag": {"severity": "medium", "mode": "lenient"}},
        use_defaults=False,
    )
    registry = _load_and_apply(config)

    applied = registry.get_config("require_tag")
    assert applied.severity == "medium"
    assert applied.config["mode"] == "lenient"
    assert applied.config["required_tag"] == "Owner"
    assert applied.description == "entry description"


def test_top_level_section_can_disable_a_module_check(check_module):
    config = ValidatorConfig({"custom_checks": [_ENTRY], "require_tag": {"enabled": False}}, use_defaults=False)

    assert _load_and_apply(config).is_enabled("require_tag") is False


async def test_validate_policies_runs_module_check_with_its_entry_config(check_module, tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        textwrap.dedent(
            """
            custom_checks:
              - module: cc_module_config_pkg.require_tag.RequireTag
                severity: high
                description: entry description
                config:
                  required_tag: Owner
                  mode: strict
            """
        )
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }

    results = await validate_policies(
        [("policy.json", IAMPolicy.model_validate(policy), policy)], config_path=str(config_file)
    )

    issues = [i for r in results for i in r.issues if i.issue_type == "require_tag_demo"]
    assert [(i.severity, i.message) for i in issues] == [("high", "Owner|strict|entry description")]

"""Unit tests for the validate_policies orchestrator."""

import asyncio
import logging

import pytest

from iam_validator.core import constants
from iam_validator.core.config.config_loader import SettingsSchema, ValidatorConfig
from iam_validator.core.config.defaults import DEFAULT_CONFIG
from iam_validator.core.models import IAMPolicy, PolicyValidationResult
from iam_validator.core.policy_checks import validate_policies

_CONCURRENCY_POLICY = IAMPolicy.model_validate(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
)


def _tracking_validate_policy(active: list[int], peak: list[int]):
    async def fake_validate(
        policy,
        policy_file,
        registry,
        fetcher,
        fail_on_severities=None,
        policy_type="IDENTITY_POLICY",
        raw_policy_dict=None,
    ):
        active[0] += 1
        peak[0] = max(peak[0], active[0])
        await asyncio.sleep(0)
        active[0] -= 1
        return PolicyValidationResult(policy_file=policy_file, is_valid=True, policy_type=policy_type)

    return fake_validate


async def test_critical_findings_fail_the_run_without_explicit_config():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    results = await validate_policies([("inline.json", IAMPolicy.model_validate(policy), policy)])
    assert any(i.severity == "critical" for r in results for i in r.issues)
    assert all(r.is_valid is False for r in results)


def test_fail_on_severity_default_agrees_across_all_three_sources():
    expected = set(constants.HIGH_SEVERITY_LEVELS)
    assert set(ValidatorConfig().get_setting("fail_on_severity")) == expected
    assert set(DEFAULT_CONFIG["settings"]["fail_on_severity"]) == expected
    assert set(SettingsSchema().fail_on_severity) == expected


async def test_statement_findings_stay_in_statement_order():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": f"S{i}", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"} for i in range(20)
        ],
    }
    results = await validate_policies([("inline.json", IAMPolicy.model_validate(policy), policy)])
    issues = results[0].issues
    assert {i.statement_sid for i in issues if i.statement_sid} == {f"S{i}" for i in range(20)}

    per_check: dict[str | None, list[int]] = {}
    for issue in issues:
        per_check.setdefault(issue.check_id, []).append(issue.statement_index)
    assert per_check
    for indices in per_check.values():
        assert indices == sorted(indices)


async def test_max_concurrency_bounds_concurrent_validations(monkeypatch):
    active = [0]
    peak = [0]
    monkeypatch.setattr(
        "iam_validator.core.policy_checks._validate_policy_with_registry", _tracking_validate_policy(active, peak)
    )
    policies = [(f"p{i}.json", _CONCURRENCY_POLICY, None) for i in range(10)]

    await validate_policies(policies, max_concurrency=2)

    assert peak[0] == 2


async def test_max_concurrency_none_resolves_from_config(tmp_path, monkeypatch):
    active = [0]
    peak = [0]
    monkeypatch.setattr(
        "iam_validator.core.policy_checks._validate_policy_with_registry", _tracking_validate_policy(active, peak)
    )
    config_file = tmp_path / "config.yaml"
    config_file.write_text("settings:\n  max_concurrency: 2\n")
    policies = [(f"p{i}.json", _CONCURRENCY_POLICY, None) for i in range(10)]

    await validate_policies(policies, config_path=str(config_file))

    assert peak[0] == 2


async def test_max_concurrency_explicit_argument_overrides_config(tmp_path, monkeypatch):
    active = [0]
    peak = [0]
    monkeypatch.setattr(
        "iam_validator.core.policy_checks._validate_policy_with_registry", _tracking_validate_policy(active, peak)
    )
    config_file = tmp_path / "config.yaml"
    config_file.write_text("settings:\n  max_concurrency: 9\n")
    policies = [(f"p{i}.json", _CONCURRENCY_POLICY, None) for i in range(10)]

    await validate_policies(policies, config_path=str(config_file), max_concurrency=3)

    assert peak[0] == 3


@pytest.mark.parametrize("supplied", [0, -1])
async def test_max_concurrency_below_one_is_clamped(monkeypatch, caplog, supplied):
    active = [0]
    peak = [0]
    monkeypatch.setattr(
        "iam_validator.core.policy_checks._validate_policy_with_registry", _tracking_validate_policy(active, peak)
    )
    policies = [(f"p{i}.json", _CONCURRENCY_POLICY, None) for i in range(5)]

    with caplog.at_level(logging.WARNING):
        await validate_policies(policies, max_concurrency=supplied)

    assert peak[0] == 1
    assert any("max_concurrency argument" in r.getMessage() for r in caplog.records)


async def test_max_concurrency_zero_in_config_is_clamped(tmp_path, monkeypatch, caplog):
    active = [0]
    peak = [0]
    monkeypatch.setattr(
        "iam_validator.core.policy_checks._validate_policy_with_registry", _tracking_validate_policy(active, peak)
    )
    config_file = tmp_path / "config.yaml"
    config_file.write_text("settings:\n  max_concurrency: 0\n")
    policies = [(f"p{i}.json", _CONCURRENCY_POLICY, None) for i in range(5)]

    with caplog.at_level(logging.WARNING):
        await validate_policies(policies, config_path=str(config_file))

    assert peak[0] == 1
    assert any("config setting max_concurrency" in r.getMessage() for r in caplog.records)

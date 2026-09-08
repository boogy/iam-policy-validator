"""Unit tests for the validate_policies orchestrator."""

from iam_validator.core import constants
from iam_validator.core.config.config_loader import SettingsSchema, ValidatorConfig
from iam_validator.core.config.defaults import DEFAULT_CONFIG
from iam_validator.core.models import IAMPolicy
from iam_validator.core.policy_checks import validate_policies


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

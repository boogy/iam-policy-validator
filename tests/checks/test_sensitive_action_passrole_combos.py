"""Tests for the iam:PassRole + downstream-service privilege-escalation combos.

The default sensitive_action config detects cross-statement `all_of` action
combinations. Beyond the original ec2:RunInstances pair, these cover the
classic PassRole escalation vectors: Glue dev endpoints, CloudFormation
service roles, SageMaker notebooks, SSM run-command, CodeBuild projects,
and Data Pipeline definitions.
"""

import pytest

from iam_validator.checks.action_condition_enforcement import (
    ActionConditionEnforcementCheck,
)
from iam_validator.checks.sensitive_action import SensitiveActionCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.config.defaults import get_default_config
from iam_validator.core.models import IAMPolicy, Statement


@pytest.fixture
def check():
    return SensitiveActionCheck()


def _sensitive_action_config(ignore_patterns: list[dict] | None = None) -> CheckConfig:
    """Build CheckConfig the way config_loader.py does: ignore_patterns and
    root_config populated from the default dict, not left at their empty
    defaults."""
    default_config = get_default_config()
    sensitive_action_config = default_config["sensitive_action"]
    if ignore_patterns is None:
        ignore_patterns = sensitive_action_config.get("ignore_patterns", [])
    return CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config=sensitive_action_config,
        root_config=default_config,
        ignore_patterns=ignore_patterns,
    )


@pytest.fixture
def config():
    return _sensitive_action_config()


def _policy(actions_by_statement: list[list[str]]) -> IAMPolicy:
    statements = [Statement(Effect="Allow", Action=actions, Resource="*") for actions in actions_by_statement]
    return IAMPolicy(Version="2012-10-17", Statement=statements)


def _combo_issues(issues, *actions):
    """Issues whose message mentions every action of the combo."""
    return [i for i in issues if all(a in i.message for a in actions)]


PASSROLE_COMBOS = [
    ("ec2:RunInstances",),  # pre-existing combo — regression guard
    ("glue:CreateDevEndpoint",),
    ("cloudformation:CreateStack",),
    ("sagemaker:CreateNotebookInstance",),
    ("ssm:SendCommand",),
    ("codebuild:CreateProject",),
    ("datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"),
]


class TestPassRoleCombos:
    @pytest.mark.parametrize("service_actions", PASSROLE_COMBOS, ids=lambda c: c[0].split(":")[0])
    async def test_combo_fires_across_statements(self, check, config, mock_fetcher, service_actions):
        policy = _policy([["iam:PassRole"], list(service_actions)])

        issues = await check.execute_policy(policy, "test.json", mock_fetcher, config)

        matches = _combo_issues(issues, "iam:PassRole", *service_actions)
        assert matches, f"expected combo issue for {service_actions}"
        assert all(i.severity == "high" for i in matches)
        assert all(i.suggestion for i in matches)

    @pytest.mark.parametrize("service_actions", PASSROLE_COMBOS, ids=lambda c: c[0].split(":")[0])
    async def test_no_combo_without_passrole(self, check, config, mock_fetcher, service_actions):
        policy = _policy([list(service_actions)])

        issues = await check.execute_policy(policy, "test.json", mock_fetcher, config)

        assert not _combo_issues(issues, "iam:PassRole", *service_actions)

    async def test_no_combo_with_only_passrole(self, check, config, mock_fetcher):
        policy = _policy([["iam:PassRole"]])

        issues = await check.execute_policy(policy, "test.json", mock_fetcher, config)

        assert not _combo_issues(issues, "glue:CreateDevEndpoint")
        assert not _combo_issues(issues, "cloudformation:CreateStack")

    async def test_datapipeline_requires_all_three(self, check, config, mock_fetcher):
        """CreatePipeline + PassRole without PutPipelineDefinition is not enough."""
        policy = _policy([["iam:PassRole"], ["datapipeline:CreatePipeline"]])

        issues = await check.execute_policy(policy, "test.json", mock_fetcher, config)

        assert not _combo_issues(issues, "datapipeline:CreatePipeline", "iam:PassRole")

    async def test_user_ignore_pattern_still_suppresses_combo(self, check, mock_fetcher):
        """The documented opt-out (user-supplied ignore_patterns) must keep working."""
        config = _sensitive_action_config(ignore_patterns=[{"action": "^iam:PassRole$"}])
        policy = _policy([["iam:PassRole"], ["ec2:RunInstances"]])

        issues = await check.execute_policy(policy, "test.json", mock_fetcher, config)

        assert not _combo_issues(issues, "iam:PassRole", "ec2:RunInstances")

    async def test_passrole_dedup_survives_default_ignore_patterns_removal(self, mock_fetcher):
        """The per-statement iam:PassRole dedup against action_condition_enforcement
        comes from `_get_actions_covered_by_condition_enforcement`, not from
        ignore_patterns."""
        default_config = get_default_config()
        statement = Statement(Effect="Allow", Action=["iam:PassRole"], Resource="*")
        policy = IAMPolicy(Version="2012-10-17", Statement=[statement])

        sensitive_config = _sensitive_action_config()
        sensitive_issues = await SensitiveActionCheck().execute(statement, 0, mock_fetcher, sensitive_config)

        ace_config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config=default_config["action_condition_enforcement"],
            root_config=default_config,
        )
        ace_issues = await ActionConditionEnforcementCheck().execute_policy(
            policy, "test.json", mock_fetcher, ace_config
        )

        passrole_ace_issues = [
            i for i in ace_issues if i.issue_type == "missing_required_condition" and "iam:PassRole" in (i.action or "")
        ]
        assert len(passrole_ace_issues) == 1

        passrole_sensitive_issues = [
            i for i in sensitive_issues if i.issue_type == "missing_condition" and i.action == "iam:PassRole"
        ]
        assert not passrole_sensitive_issues

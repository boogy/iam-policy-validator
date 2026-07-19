"""Tests for the iam:PassRole + downstream-service privilege-escalation combos.

The default sensitive_action config detects cross-statement `all_of` action
combinations. Beyond the original ec2:RunInstances pair, these cover the
classic PassRole escalation vectors: Glue dev endpoints, CloudFormation
service roles, SageMaker notebooks, SSM run-command, CodeBuild projects,
and Data Pipeline definitions.
"""

import pytest

from iam_validator.checks.sensitive_action import SensitiveActionCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.config.defaults import get_default_config
from iam_validator.core.models import IAMPolicy, Statement


@pytest.fixture
def check():
    return SensitiveActionCheck()


@pytest.fixture
def config():
    return CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config=get_default_config()["sensitive_action"],
    )


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

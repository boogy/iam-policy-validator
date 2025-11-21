"""Tests for policy-level ActionConditionEnforcementCheck.

This tests the new policy-level enforcement feature that scans the entire
policy and ensures ALL statements granting certain actions have required conditions.
"""

import pytest

from iam_validator.checks.action_condition_enforcement import (
    ActionConditionEnforcementCheck,
)
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement


@pytest.fixture
def fetcher():
    """Create a mock AWS service fetcher."""
    return AWSServiceFetcher(enable_cache=False)


@pytest.fixture
def check():
    """Create an ActionConditionEnforcementCheck instance."""
    return ActionConditionEnforcementCheck()


class TestPolicyLevelEnforcement:
    """Test policy-level condition enforcement."""

    @pytest.mark.asyncio
    async def test_policy_level_any_of_all_statements_have_mfa(self, check, fetcher):
        """Test that ALL statements with sensitive actions must have MFA."""
        # Policy with 3 statements, 2 have iam:CreateUser, both should have MFA
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    action=["iam:CreateUser"],
                    resource=["*"],
                    condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                    sid="Statement1",
                ),
                Statement(
                    effect="Allow",
                    action=["s3:GetObject"],
                    resource=["arn:aws:s3:::bucket/*"],
                    sid="Statement2",
                ),
                Statement(
                    effect="Allow",
                    action=["iam:CreateUser", "iam:CreateRole"],
                    resource=["*"],
                    # Missing MFA condition!
                    sid="Statement3",
                ),
            ],
        )

        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "policy_level_requirements": [
                    {
                        "actions": {"any_of": ["iam:CreateUser", "iam:AttachUserPolicy"]},
                        "scope": "policy",
                        "required_conditions": [
                            {
                                "condition_key": "aws:MultiFactorAuthPresent",
                                "expected_value": True,
                            }
                        ],
                        "description": "Privilege escalation actions require MFA",
                        "severity": "critical",
                    }
                ]
            },
        )

        issues = await check.execute_policy(policy, "test-policy.json", fetcher, config)

        # Should have 1 issue for Statement3 (missing MFA)
        assert len(issues) == 1
        assert issues[0].statement_index == 2
        assert issues[0].statement_sid == "Statement3"
        assert issues[0].severity == "critical"
        assert "aws:MultiFactorAuthPresent" in issues[0].message
        assert "2 statement(s) with these actions" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_policy_level_all_of_actions(self, check, fetcher):
        """Test policy-level enforcement with all_of actions."""
        # Policy where one statement has BOTH dangerous actions
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    action=["iam:CreateAccessKey"],
                    resource=["*"],
                    sid="Statement1",
                ),
                Statement(
                    effect="Allow",
                    action=["iam:CreateAccessKey", "iam:UpdateAccessKey"],
                    resource=["*"],
                    # Dangerous combination!
                    sid="Statement2",
                ),
            ],
        )

        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "policy_level_requirements": [
                    {
                        "actions": {
                            "all_of": ["iam:CreateAccessKey", "iam:UpdateAccessKey"]
                        },
                        "scope": "policy",
                        "description": "Dangerous combination of access key actions",
                        "severity": "critical",
                    }
                ]
            },
        )

        issues = await check.execute_policy(policy, "test-policy.json", fetcher, config)

        # Should detect the dangerous combination in Statement2
        assert len(issues) == 1
        assert issues[0].statement_sid == "Statement2"
        assert issues[0].issue_type == "action_detected"
        assert "all_of" in issues[0].message

    @pytest.mark.asyncio
    async def test_policy_level_no_matching_statements(self, check, fetcher):
        """Test that no issues are raised when no statements match."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    action=["s3:GetObject"],
                    resource=["arn:aws:s3:::bucket/*"],
                    sid="Statement1",
                ),
            ],
        )

        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "policy_level_requirements": [
                    {
                        "actions": {"any_of": ["iam:CreateUser"]},
                        "scope": "policy",
                        "required_conditions": [
                            {"condition_key": "aws:MultiFactorAuthPresent"}
                        ],
                    }
                ]
            },
        )

        issues = await check.execute_policy(policy, "test-policy.json", fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_policy_level_all_statements_compliant(self, check, fetcher):
        """Test that no issues when all statements have required conditions."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    action=["iam:CreateUser"],
                    resource=["*"],
                    condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                    sid="Statement1",
                ),
                Statement(
                    effect="Allow",
                    action=["iam:AttachUserPolicy"],
                    resource=["*"],
                    condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                    sid="Statement2",
                ),
            ],
        )

        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "policy_level_requirements": [
                    {
                        "actions": {"any_of": ["iam:CreateUser", "iam:AttachUserPolicy"]},
                        "scope": "policy",
                        "required_conditions": [
                            {
                                "condition_key": "aws:MultiFactorAuthPresent",
                                "expected_value": True,
                            }
                        ],
                    }
                ]
            },
        )

        issues = await check.execute_policy(policy, "test-policy.json", fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_policy_level_multiple_requirements(self, check, fetcher):
        """Test multiple policy-level requirements."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    action=["iam:CreateUser"],
                    resource=["*"],
                    # Missing MFA
                    sid="Statement1",
                ),
                Statement(
                    effect="Allow",
                    action=["s3:PutObject"],
                    resource=["arn:aws:s3:::bucket/*"],
                    # Missing encryption condition
                    sid="Statement2",
                ),
            ],
        )

        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "policy_level_requirements": [
                    {
                        "actions": {"any_of": ["iam:CreateUser"]},
                        "scope": "policy",
                        "required_conditions": [
                            {"condition_key": "aws:MultiFactorAuthPresent"}
                        ],
                        "severity": "high",
                    },
                    {
                        "actions": {"any_of": ["s3:PutObject"]},
                        "scope": "policy",
                        "required_conditions": [
                            {"condition_key": "s3:x-amz-server-side-encryption"}
                        ],
                        "severity": "medium",
                    },
                ]
            },
        )

        issues = await check.execute_policy(policy, "test-policy.json", fetcher, config)

        # Should have 2 issues (one for each requirement)
        assert len(issues) == 2

        # Check MFA issue
        mfa_issue = [i for i in issues if "MultiFactorAuthPresent" in i.message][0]
        assert mfa_issue.severity == "high"
        assert mfa_issue.statement_sid == "Statement1"

        # Check encryption issue
        enc_issue = [i for i in issues if "encryption" in i.message][0]
        assert enc_issue.severity == "medium"
        assert enc_issue.statement_sid == "Statement2"

    @pytest.mark.asyncio
    async def test_policy_level_with_all_of_conditions(self, check, fetcher):
        """Test policy-level enforcement with all_of conditions."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Allow",
                    action=["iam:DeleteUser"],
                    resource=["*"],
                    # Has MFA but missing SourceIp
                    condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                    sid="Statement1",
                ),
            ],
        )

        config = CheckConfig(
            check_id="action_condition_enforcement",
            enabled=True,
            config={
                "policy_level_requirements": [
                    {
                        "actions": {"any_of": ["iam:DeleteUser"]},
                        "scope": "policy",
                        "required_conditions": {
                            "all_of": [
                                {"condition_key": "aws:MultiFactorAuthPresent"},
                                {"condition_key": "aws:SourceIp"},
                            ]
                        },
                    }
                ]
            },
        )

        issues = await check.execute_policy(policy, "test-policy.json", fetcher, config)

        # Should have 1 issue for missing SourceIp
        assert len(issues) == 1
        assert "aws:SourceIp" in issues[0].message
        # Removed: POLICY-LEVEL no longer used



"""Tests for the rcp_best_practices check."""

import pytest

from iam_validator.checks.rcp_best_practices import RCPBestPracticesCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement


@pytest.fixture
def check():
    return RCPBestPracticesCheck()


@pytest.fixture
def config():
    return CheckConfig(check_id="rcp_best_practices", enabled=True)


def _policy(*statements: Statement) -> IAMPolicy:
    return IAMPolicy(version="2012-10-17", statement=list(statements))


def _canonical_identity_perimeter_statement() -> Statement:
    """AWS's canonical identity-perimeter RCP statement shape."""
    return Statement(
        Effect="Deny",
        Principal="*",
        Action=["s3:*"],
        Resource=["*"],
        Condition={
            "StringNotEqualsIfExists": {"aws:PrincipalOrgID": "o-example12345"},
            "BoolIfExists": {"aws:PrincipalIsAWSService": "false"},
        },
    )


class TestRCPBestPractices:
    async def test_only_runs_for_rcp_policy_type(self, check, config, mock_fetcher):
        policy = _policy(Statement(Effect="Deny", Principal="*", Action=["s3:*"], Resource=["*"]))
        issues = await check.execute_policy(policy, "test.json", mock_fetcher, config, policy_type="IDENTITY_POLICY")
        assert issues == []

    async def test_canonical_identity_perimeter_is_clean(self, check, config, mock_fetcher):
        policy = _policy(_canonical_identity_perimeter_statement())
        issues = await check.execute_policy(
            policy, "test.json", mock_fetcher, config, policy_type="RESOURCE_CONTROL_POLICY"
        )
        assert issues == []

    async def test_blanket_deny_flagged_low(self, check, config, mock_fetcher):
        policy = _policy(
            Statement(Effect="Deny", Principal="*", Action=["s3:PutAccountPublicAccessBlock"], Resource=["*"])
        )
        issues = await check.execute_policy(
            policy, "test.json", mock_fetcher, config, policy_type="RESOURCE_CONTROL_POLICY"
        )
        assert len(issues) == 1
        assert issues[0].issue_type == "rcp_blanket_deny"
        assert issues[0].severity == "low"

    async def test_org_boundary_without_carveout_flagged(self, check, config, mock_fetcher):
        policy = _policy(
            Statement(
                Effect="Deny",
                Principal="*",
                Action=["s3:*"],
                Resource=["*"],
                Condition={"StringNotEqualsIfExists": {"aws:PrincipalOrgID": "o-example12345"}},
            )
        )
        issues = await check.execute_policy(
            policy, "test.json", mock_fetcher, config, policy_type="RESOURCE_CONTROL_POLICY"
        )
        assert len(issues) == 1
        assert issues[0].issue_type == "rcp_missing_service_carveout"
        assert issues[0].severity == "medium"
        assert "aws:PrincipalIsAWSService" in issues[0].suggestion

    async def test_plain_string_not_equals_also_flagged(self, check, config, mock_fetcher):
        policy = _policy(
            Statement(
                Effect="Deny",
                Principal="*",
                Action=["sqs:*"],
                Resource=["*"],
                Condition={"StringNotEquals": {"aws:PrincipalAccount": "123456789012"}},
            )
        )
        issues = await check.execute_policy(
            policy, "test.json", mock_fetcher, config, policy_type="RESOURCE_CONTROL_POLICY"
        )
        assert [i for i in issues if i.issue_type == "rcp_missing_service_carveout"]

    async def test_secure_transport_only_condition_is_clean(self, check, config, mock_fetcher):
        """AWS's HTTPS-enforcement example RCP must not be flagged."""
        policy = _policy(
            Statement(
                Effect="Deny",
                Principal="*",
                Action=["s3:*", "sts:*", "kms:*"],
                Resource=["*"],
                Condition={"BoolIfExists": {"aws:SecureTransport": "false"}},
            )
        )
        issues = await check.execute_policy(
            policy, "test.json", mock_fetcher, config, policy_type="RESOURCE_CONTROL_POLICY"
        )
        assert issues == []

    async def test_allow_statement_ignored(self, check, config, mock_fetcher):
        """Allow statements (invalid in RCPs, flagged elsewhere) are skipped here."""
        policy = _policy(Statement(Effect="Allow", Principal="*", Action=["s3:*"], Resource=["*"]))
        issues = await check.execute_policy(
            policy, "test.json", mock_fetcher, config, policy_type="RESOURCE_CONTROL_POLICY"
        )
        assert issues == []

    async def test_multiple_statements_flagged_independently(self, check, config, mock_fetcher):
        policy = _policy(
            _canonical_identity_perimeter_statement(),
            Statement(Effect="Deny", Principal="*", Action=["kms:ScheduleKeyDeletion"], Resource=["*"]),
            Statement(
                Effect="Deny",
                Principal="*",
                Action=["secretsmanager:*"],
                Resource=["*"],
                Condition={"StringNotEqualsIfExists": {"aws:PrincipalOrgPaths": "o-example12345/r-ab12/*"}},
            ),
        )
        issues = await check.execute_policy(
            policy, "test.json", mock_fetcher, config, policy_type="RESOURCE_CONTROL_POLICY"
        )
        assert len(issues) == 2
        by_type = {i.issue_type: i for i in issues}
        assert by_type["rcp_blanket_deny"].statement_index == 1
        assert by_type["rcp_missing_service_carveout"].statement_index == 2

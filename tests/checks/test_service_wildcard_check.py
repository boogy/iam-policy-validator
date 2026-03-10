"""Tests for ServiceWildcardCheck."""

import pytest

from iam_validator.checks.service_wildcard import ServiceWildcardCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
async def fetcher():
    """Create AWS service fetcher for tests."""
    async with AWSServiceFetcher(prefetch_common=False) as f:
        yield f


@pytest.fixture
def check():
    return ServiceWildcardCheck()


@pytest.fixture
def config():
    return CheckConfig(check_id="service_wildcard", enabled=True, config={})


class TestServiceWildcardCheck:
    """Tests for ServiceWildcardCheck."""

    @pytest.mark.asyncio
    async def test_service_wildcard_detected(self, check, fetcher, config):
        """Test that service-level wildcards are detected."""
        statement = Statement(Effect="Allow", Action=["iam:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "overly_permissive"
        assert issues[0].action == "iam:*"

    @pytest.mark.asyncio
    async def test_multiple_service_wildcards(self, check, fetcher, config):
        """Test that multiple service wildcards are all detected."""
        statement = Statement(Effect="Allow", Action=["iam:*", "s3:*", "ec2:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 3
        actions = {issue.action for issue in issues}
        assert actions == {"iam:*", "s3:*", "ec2:*"}

    @pytest.mark.asyncio
    async def test_full_wildcard_skipped(self, check, fetcher, config):
        """Test that full wildcard Action:* is skipped (handled by wildcard_action check)."""
        statement = Statement(Effect="Allow", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_prefix_wildcard_not_flagged(self, check, fetcher, config):
        """Test that prefix wildcards like iam:Get* are not flagged."""
        statement = Statement(Effect="Allow", Action=["iam:Get*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_deny_statement_ignored(self, check, fetcher, config):
        """Test that Deny statements are ignored."""
        statement = Statement(Effect="Deny", Action=["iam:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_allowed_services_configuration(self, check, fetcher):
        """Test that configured allowed services are not flagged."""
        config = CheckConfig(
            check_id="service_wildcard",
            enabled=True,
            config={"allowed_services": ["logs", "cloudwatch"]},
        )
        statement = Statement(Effect="Allow", Action=["logs:*", "cloudwatch:*", "iam:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        # Only iam:* should be flagged
        assert len(issues) == 1
        assert issues[0].action == "iam:*"

    @pytest.mark.asyncio
    async def test_abac_resource_tag_condition_lowers_severity(self, check, fetcher, config):
        """Service wildcard with ABAC ResourceTag/PrincipalTag condition should be flagged at 'low' severity."""
        statement = Statement(
            Effect="Allow",
            Action=["secretsmanager:*"],
            Resource=["arn:aws:secretsmanager:*:123456789012:secret:*"],
            Condition={
                "StringLike": {
                    "aws:ResourceTag/owner": "${aws:PrincipalTag/owner}",
                    "aws:ResourceTag/env": "${aws:PrincipalTag/env}",
                }
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].action == "secretsmanager:*"
        assert issues[0].severity == "low"
        assert "ABAC" in issues[0].message

    @pytest.mark.asyncio
    async def test_abac_applies_to_any_service_wildcard(self, check, fetcher, config):
        """ABAC severity reduction is not limited to secretsmanager — applies to any service."""
        for action in ["s3:*", "ec2:*", "iam:*", "lambda:*"]:
            statement = Statement(
                Effect="Allow",
                Action=[action],
                Resource=["*"],
                Condition={
                    "StringEquals": {
                        "aws:ResourceTag/team": "${aws:PrincipalTag/team}",
                    }
                },
            )
            issues = await check.execute(statement, 0, fetcher, config)
            assert len(issues) == 1, f"Expected issue for {action}"
            assert issues[0].severity == "low", f"Expected low severity for {action}"

    @pytest.mark.asyncio
    async def test_abac_mitigated_severity_configurable(self, check, fetcher):
        """abac_mitigated_severity config option overrides the default 'low'."""
        config = CheckConfig(
            check_id="service_wildcard",
            enabled=True,
            config={"abac_mitigated_severity": "medium"},
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={
                "StringEquals": {
                    "aws:ResourceTag/owner": "${aws:PrincipalTag/owner}",
                }
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_abac_without_principal_tag_ref_uses_normal_severity(self, check, fetcher, config):
        """Condition with ResourceTag but a static value (not PrincipalTag) uses normal severity."""
        statement = Statement(
            Effect="Allow",
            Action=["iam:*"],
            Resource=["*"],
            Condition={
                "StringEquals": {
                    "aws:ResourceTag/env": "production",
                }
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].action == "iam:*"
        assert issues[0].severity == "high"

    @pytest.mark.asyncio
    async def test_non_resource_tag_condition_uses_normal_severity(self, check, fetcher, config):
        """Condition that doesn't use aws:ResourceTag/ does not lower severity."""
        statement = Statement(
            Effect="Allow",
            Action=["ec2:*"],
            Resource=["*"],
            Condition={
                "StringEquals": {
                    "aws:RequestedRegion": "us-east-1",
                }
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].action == "ec2:*"
        assert issues[0].severity == "high"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "operator",
        [
            "ForAllValues:StringEquals",
            "ForAnyValue:StringEquals",
            "StringEqualsIfExists",
            "ForAllValues:StringEqualsIfExists",
            "StringEqualsIgnoreCaseIfExists",
            "StringLikeIfExists",
            "ForAnyValue:StringLikeIfExists",
        ],
    )
    async def test_abac_with_set_operators_and_ifexists(self, check, fetcher, config, operator):
        """ABAC detection handles ForAllValues:/ForAnyValue: prefixes and IfExists suffix."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={
                operator: {
                    "aws:ResourceTag/team": "${aws:PrincipalTag/team}",
                }
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1, f"Expected issue for operator {operator}"
        assert issues[0].severity == "low", f"Expected low severity for operator {operator}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "operator",
        [
            "StringNotEquals",
            "StringNotLike",
            "StringNotEqualsIgnoreCase",
            "ForAllValues:StringNotEquals",
        ],
    )
    async def test_negated_operators_not_treated_as_abac(self, check, fetcher, config, operator):
        """Negated string operators (StringNotEquals, etc.) should NOT be treated as ABAC mitigation."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={
                operator: {
                    "aws:ResourceTag/team": "${aws:PrincipalTag/team}",
                }
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1, f"Expected issue for operator {operator}"
        assert issues[0].severity == "high", f"Expected high severity for negated operator {operator}"

    @pytest.mark.asyncio
    async def test_abac_and_plain_wildcard_in_same_policy(self, check, fetcher, config):
        """ABAC statement gets 'low' severity; plain wildcard gets full 'high' severity."""
        abac_statement = Statement(
            Effect="Allow",
            Action=["secretsmanager:*"],
            Resource=["arn:aws:secretsmanager:*:123456789012:secret:*"],
            Condition={
                "StringLike": {
                    "aws:ResourceTag/owner": "${aws:PrincipalTag/owner}",
                }
            },
        )
        plain_wildcard_statement = Statement(
            Effect="Allow",
            Action=["iam:*"],
            Resource=["*"],
        )

        abac_issues = await check.execute(abac_statement, 0, fetcher, config)
        plain_issues = await check.execute(plain_wildcard_statement, 1, fetcher, config)

        assert len(abac_issues) == 1
        assert abac_issues[0].severity == "low"
        assert len(plain_issues) == 1
        assert plain_issues[0].severity == "high"

    @pytest.mark.asyncio
    async def test_abac_condition_value_as_list(self, check, fetcher, config):
        """ABAC detection works when condition value is a list (OR semantics in AWS)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={
                "StringEquals": {
                    "aws:ResourceTag/team": ["${aws:PrincipalTag/team}", "shared"],
                }
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"

    @pytest.mark.asyncio
    async def test_mixed_abac_and_non_abac_conditions(self, check, fetcher, config):
        """ABAC is detected even when mixed with non-ABAC conditions in the same block."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Condition={
                "IpAddress": {
                    "aws:SourceIp": "10.0.0.0/8",
                },
                "StringEquals": {
                    "aws:ResourceTag/owner": "${aws:PrincipalTag/owner}",
                },
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"

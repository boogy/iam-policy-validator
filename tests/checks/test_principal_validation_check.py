"""Tests for PrincipalValidationCheck."""

import pytest

from iam_validator.checks.principal_validation import PrincipalValidationCheck
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
    """Create PrincipalValidationCheck instance."""
    return PrincipalValidationCheck()


@pytest.fixture
def config():
    """Create default check config matching actual defaults."""
    return CheckConfig(
        check_id="principal_validation",
        enabled=True,
        config={
            "block_wildcard_principal": False,  # Default: allow * with conditions
            "blocked_principals": [],
            "allowed_principals": [],
            "allowed_service_principals": ["aws:*"],
        },
    )


class TestPrincipalValidationCheck:
    """Tests for PrincipalValidationCheck."""

    @pytest.mark.asyncio
    async def test_no_principal_no_issue(self, check, fetcher, config):
        """Test that statements without Principal don't trigger issues."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_blocked_principal_wildcard(self, check, fetcher):
        """Test that wildcard principal (*) can be blocked with strict mode."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "block_wildcard_principal": True,  # Strict mode: block * entirely
                "blocked_principals": [],
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "blocked_principal"

    @pytest.mark.asyncio
    async def test_service_principal_allowed(self, check, fetcher, config):
        """Test that service principals are allowed by default."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"Service": "lambda.amazonaws.com"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_aws_account_principal_allowed(self, check, fetcher, config):
        """Test that AWS account principals are allowed by default."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_allowed_principals_whitelist(self, check, fetcher):
        """Test that allowed_principals whitelist works."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "allowed_principals": ["arn:aws:iam::123456789012:root"],
            },
        )
        # This principal is in the whitelist
        statement1 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
        )
        issues1 = await check.execute(statement1, 0, fetcher, config)
        assert len(issues1) == 0

        # This principal is NOT in the whitelist
        statement2 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::999999999999:root"},
        )
        issues2 = await check.execute(statement2, 0, fetcher, config)
        assert len(issues2) == 1
        assert issues2[0].issue_type == "unauthorized_principal"

    @pytest.mark.asyncio
    async def test_not_principal_field(self, check, fetcher):
        """Test that NotPrincipal field is also validated when blocking enabled."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "block_wildcard_principal": True,  # Strict mode: block * entirely
                "blocked_principals": [],
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            NotPrincipal="*",
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "blocked_principal"


class TestPrincipalConditionRequirements:
    """Tests for advanced principal_condition_requirements feature."""

    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @pytest.mark.asyncio
    async def test_all_of_conditions(self, check, fetcher):
        """Test all_of logic - ALL conditions must be present."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": {
                            "all_of": [
                                {"condition_key": "aws:SourceArn"},
                                {"condition_key": "aws:SourceAccount"},
                            ]
                        },
                    }
                ],
            },
        )
        # Statement with only one condition
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
            Condition={"StringEquals": {"aws:SourceArn": "arn:aws:s3:::my-bucket"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "missing_principal_condition"
        assert "aws:SourceAccount" in issues[0].message

    @pytest.mark.asyncio
    async def test_any_of_conditions(self, check, fetcher):
        """Test any_of logic - at least ONE condition must be present."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": {
                            "any_of": [
                                {"condition_key": "aws:SourceIp"},
                                {"condition_key": "aws:SourceVpce"},
                            ]
                        },
                    }
                ],
            },
        )
        # Statement without any of the required conditions
        statement1 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )
        issues1 = await check.execute(statement1, 0, fetcher, config)
        assert len(issues1) == 1
        assert issues1[0].issue_type == "missing_principal_condition_any_of"

        # Statement with one of the conditions (should pass)
        statement2 = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
            Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
        )
        issues2 = await check.execute(statement2, 0, fetcher, config)
        assert len(issues2) == 0

    @pytest.mark.asyncio
    async def test_none_of_conditions(self, check, fetcher):
        """Test none_of logic - NONE of these conditions should be present."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": {
                            "none_of": [
                                {
                                    "condition_key": "aws:SecureTransport",
                                    "expected_value": False,
                                }
                            ]
                        },
                    }
                ],
            },
        )
        # Statement with forbidden condition
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
            Condition={"Bool": {"aws:SecureTransport": "false"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "forbidden_principal_condition"


class TestServicePrincipalWildcardDetection:
    """Tests for detecting dangerous service principal wildcards like {"Service": "*"}."""

    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @pytest.mark.asyncio
    async def test_detects_service_principal_wildcard_string(self, check, fetcher):
        """Test detection of {"Service": "*"} pattern."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],  # Don't block regular *
                "block_service_principal_wildcard": True,  # Block {"Service": "*"}
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": "*"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "service_principal_wildcard"
        assert issues[0].severity == "critical"
        assert "any aws service" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_detects_service_principal_wildcard_in_list(self, check, fetcher):
        """Test detection of {"Service": ["lambda.amazonaws.com", "*"]} pattern."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "block_service_principal_wildcard": True,
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": ["lambda.amazonaws.com", "*"]},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "service_principal_wildcard"
        assert issues[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_not_principal_service_wildcard_not_flagged(self, check, fetcher):
        """Test that NotPrincipal with {"Service": "*"} is NOT flagged.

        NotPrincipal: {"Service": "*"} means "allow everyone EXCEPT all services"
        which is overly broad exclusion but NOT an overly permissive grant.
        The service_principal_wildcard check only applies to Principal field.
        """
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "block_service_principal_wildcard": True,
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            NotPrincipal={"Service": "*"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        # Should have no service_principal_wildcard issues for NotPrincipal
        service_wildcard_issues = [i for i in issues if i.issue_type == "service_principal_wildcard"]
        assert len(service_wildcard_issues) == 0

    @pytest.mark.asyncio
    async def test_allows_specific_service_principals(self, check, fetcher):
        """Test that specific service principals are still allowed."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "block_service_principal_wildcard": True,
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": "lambda.amazonaws.com"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_allows_multiple_specific_service_principals(self, check, fetcher):
        """Test that multiple specific service principals are allowed."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "block_service_principal_wildcard": True,
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": ["lambda.amazonaws.com", "ec2.amazonaws.com"]},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_can_disable_service_principal_wildcard_check(self, check, fetcher):
        """Test that the check can be disabled via config."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "block_service_principal_wildcard": False,  # Explicitly disabled
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": "*"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        # Should have no issues because check is disabled
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_default_behavior_blocks_service_principal_wildcard(self, check, fetcher):
        """Test that service principal wildcards are blocked by default."""
        # Use default config (no explicit block_service_principal_wildcard setting)
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": "*"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        # Should detect issue because default is to block
        assert len(issues) == 1
        assert issues[0].issue_type == "service_principal_wildcard"

    @pytest.mark.asyncio
    async def test_does_not_flag_aws_principal_wildcard(self, check, fetcher):
        """Test that {"AWS": "*"} is handled by blocked_principals, not this check."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],  # Don't block AWS wildcards
                "block_service_principal_wildcard": True,
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Principal={"AWS": "*"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        # Should have no service_principal_wildcard issues
        service_wildcard_issues = [i for i in issues if i.issue_type == "service_principal_wildcard"]
        assert len(service_wildcard_issues) == 0


class TestDenyStatementsAreSkipped:
    """A Deny cannot over-grant, so none of this check's rules apply to it.

    `Deny` + `Principal: "*"` is the canonical guardrail idiom (resource control
    policies, org-wide perimeters, `sts:TagSession` restrictions). Flagging it as
    public access is a false positive, and the suggested remediation -- scoping the
    statement with `aws:SourceArn`/`aws:PrincipalOrgID` -- would narrow the Deny and
    weaken the policy.
    """

    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @pytest.mark.asyncio
    async def test_deny_wildcard_principal_without_conditions_is_clean(self, check, fetcher):
        """The regression: a bare `Deny` + `Principal: "*"` must not be flagged."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "severity": "critical",
                        "required_conditions": {
                            "any_of": [
                                {"condition_key": "aws:SourceArn"},
                                {"condition_key": "aws:PrincipalOrgID"},
                            ]
                        },
                    }
                ],
            },
        )
        statement = Statement(
            Sid="DenyInsecureTransport",
            Effect="Deny",
            Action=["s3:*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
            Condition={"BoolIfExists": {"aws:SecureTransport": "false"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert issues == []

    @pytest.mark.asyncio
    async def test_allow_wildcard_principal_is_still_flagged(self, check, fetcher):
        """The guard must not weaken the Allow path -- same shape, Effect: Allow."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "severity": "critical",
                        "required_conditions": {
                            "any_of": [
                                {"condition_key": "aws:SourceArn"},
                                {"condition_key": "aws:PrincipalOrgID"},
                            ]
                        },
                    }
                ],
            },
        )
        statement = Statement(
            Sid="AllowAnyone",
            Effect="Allow",
            Action=["s3:*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "missing_principal_condition_any_of"
        assert issues[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_deny_blocked_principal_is_clean(self, check, fetcher):
        """`blocked_principals` describes who may be granted access, not denied."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": ["*"], "block_wildcard_principal": True},
        )
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal="*",
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert issues == []

    @pytest.mark.asyncio
    async def test_deny_service_principal_wildcard_is_clean(self, check, fetcher):
        """`{"Service": "*"}` under Deny denies every service -- that is hardening."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"block_service_principal_wildcard": True},
        )
        statement = Statement(
            Effect="Deny",
            Action=["sts:AssumeRole"],
            Resource=["*"],
            Principal={"Service": "*"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert issues == []

    @pytest.mark.asyncio
    async def test_deny_non_allowlisted_principal_is_clean(self, check, fetcher):
        """An `allowed_principals` allow-list constrains grants, not denies."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"allowed_principals": ["arn:aws:iam::111122223333:root"]},
        )
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal={"AWS": "arn:aws:iam::999988887777:root"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert issues == []

    @pytest.mark.asyncio
    async def test_deny_forbidden_condition_is_clean(self, check, fetcher):
        """`none_of` forbids allowing insecure transport; denying it is the fix."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": {
                            "none_of": [
                                {
                                    "condition_key": "aws:SecureTransport",
                                    "expected_value": False,
                                }
                            ]
                        },
                    }
                ],
            },
        )
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal="*",
            Condition={"Bool": {"aws:SecureTransport": "false"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert issues == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("effect", ["Deny", "deny", "DENY", " Deny "])
    async def test_deny_casing_variants_are_skipped(self, check, fetcher, effect):
        """AWS mandates exact casing, but user files reach the check unnormalised."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": ["*"], "block_wildcard_principal": True},
        )
        statement = Statement(Effect=effect, Action=["s3:*"], Resource=["*"], Principal="*")
        issues = await check.execute(statement, 0, fetcher, config)
        assert issues == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "not_principal",
        ["*", {"AWS": "*"}, {"Service": "*"}],
    )
    async def test_deny_with_notprincipal_wildcard_is_still_flagged(self, check, fetcher, not_principal):
        """NotPrincipal inverts the set, so a wildcard exception is real exposure.

        `Deny` + `NotPrincipal: "*"` denies nobody -- everyone is in "*", so nobody is
        "not *". The guard must not silence that.
        """
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": ["*"], "block_wildcard_principal": True},
        )
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            NotPrincipal=not_principal,
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "blocked_principal"

    @pytest.mark.asyncio
    async def test_deny_with_scoped_notprincipal_is_clean(self, check, fetcher):
        """A narrow NotPrincipal exception is a real lockdown, not an exposure."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": ["*"], "block_wildcard_principal": True},
        )
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            NotPrincipal={"AWS": "arn:aws:iam::111122223333:role/Admin"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert issues == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("effect", ["Allow", "allow", None, "Bogus"])
    async def test_non_deny_effects_are_still_validated(self, check, fetcher, effect):
        """Anything not recognisably a Deny is validated: never fail open on a grant."""
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": ["*"], "block_wildcard_principal": True},
        )
        statement = Statement(Effect=effect, Action=["s3:*"], Resource=["*"], Principal="*")
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "blocked_principal"


class TestInvertedDenyCarveOut:
    """AWS recommends replacing NotPrincipal with Deny + Principal "*" + ArnNotEquals.

    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html
    That rewrite carves the listed principals *out* of the deny, so the carve-out is the
    exposure -- and a carve-out of "*" excludes everyone, denying nothing.
    """

    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @pytest.fixture
    def config(self):
        return CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "principal_condition_requirements": [
                    {
                        "principals": ["*"],
                        "required_conditions": {"any_of": [{"condition_key": "aws:SourceArn"}]},
                    }
                ],
            },
        )

    @pytest.mark.asyncio
    async def test_aws_documented_role_carve_out_is_clean(self, check, fetcher, config):
        """The exact example from the AWS NotPrincipal page must not be flagged."""
        statement = Statement(
            Sid="DenyCrossAuditAccess",
            Effect="Deny",
            Action=["s3:*"],
            Resource=["arn:aws:s3:::audit"],
            Principal="*",
            Condition={"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::444455556666:role/read-only-role"}},
        )
        assert await check.execute(statement, 0, fetcher, config) == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "operator",
        ["ArnNotEquals", "ArnNotLike", "StringNotEquals", "StringNotLike", "StringNotEqualsIgnoreCase"],
    )
    async def test_equivalent_operators_on_principalarn_are_clean(self, check, fetcher, config, operator):
        """aws:PrincipalArn accepts ARN *and* String operators; all express the same carve-out.

        ARN operators are the documented preference, but the String forms are valid and
        must not be treated as a finding here.
        """
        statement = Statement(
            Sid="DenyCrossAuditAccess",
            Effect="Deny",
            Action=["s3:*"],
            Resource=["arn:aws:s3:::Bucket_Account_Audit"],
            Principal="*",
            Condition={operator: {"aws:PrincipalArn": "arn:aws:iam::444455556666:role/read-only-role"}},
        )
        assert await check.execute(statement, 0, fetcher, config) == []

    @pytest.mark.asyncio
    async def test_wildcard_org_carve_out_is_flagged(self, check, fetcher, config):
        """aws:PrincipalOrgID satisfies the any_of rule, so nothing else catches this.

        `Deny` + `StringNotEquals aws:PrincipalOrgID: "*"` exempts every org, denying
        nobody, and unlike the ARN keys `"*"` is a structurally valid value here.
        """
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal="*",
            Condition={"StringNotEquals": {"aws:PrincipalOrgID": "*"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "ineffective_deny_carve_out"

    @pytest.mark.asyncio
    async def test_notaction_deny_is_not_a_principal_carve_out(self, check, fetcher, config):
        """NotAction inverts the action axis, not the principal axis.

        That belongs to not_action_not_resource; the principal set is still "everyone".
        """
        statement = Statement(
            Effect="Deny",
            NotAction=["s3:*"],
            Resource=["*"],
            Principal="*",
        )
        assert await check.execute(statement, 0, fetcher, config) == []

    @pytest.mark.asyncio
    async def test_aws_documented_service_carve_out_is_clean(self, check, fetcher, config):
        """The service-principal variant from the same page, incl. the IfExists suffix."""
        statement = Statement(
            Sid="DenyNotCodeBuildAccess",
            Effect="Deny",
            Action=["s3:*"],
            Resource=["arn:aws:s3:::bucket"],
            Principal="*",
            Condition={"StringNotEqualsIfExists": {"aws:PrincipalServiceName": "codebuild.amazonaws.com"}},
        )
        assert await check.execute(statement, 0, fetcher, config) == []

    @pytest.mark.asyncio
    async def test_org_perimeter_deny_is_clean(self, check, fetcher, config):
        """The canonical org-boundary RCP shape stays clean."""
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal="*",
            Condition={
                "StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"},
                "BoolIfExists": {"aws:PrincipalIsAWSService": "false"},
            },
        )
        assert await check.execute(statement, 0, fetcher, config) == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "operator,key",
        [
            ("ArnNotEquals", "aws:PrincipalArn"),
            ("ArnNotLike", "aws:PrincipalArn"),
            ("StringNotEquals", "aws:PrincipalAccount"),
            ("StringNotEqualsIfExists", "aws:PrincipalServiceName"),
            ("StringNotLike", "aws:PrincipalOrgPaths"),
            ("ForAnyValue:StringNotEquals", "aws:PrincipalTag/team"),
        ],
    )
    async def test_wildcard_carve_out_is_flagged(self, check, fetcher, config, operator, key):
        """A carve-out of "*" excludes every principal, so the Deny denies nothing."""
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal="*",
            Condition={operator: {key: "*"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "ineffective_deny_carve_out"
        assert issues[0].field_name == "condition"

    @pytest.mark.asyncio
    async def test_wildcard_in_carve_out_list_is_flagged(self, check, fetcher, config):
        """A "*" hidden among specific ARNs still defeats the whole deny."""
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal="*",
            Condition={"ArnNotEquals": {"aws:PrincipalArn": ["arn:aws:iam::111122223333:role/A", "*"]}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "ineffective_deny_carve_out"

    @pytest.mark.asyncio
    async def test_non_principal_key_wildcard_is_ignored(self, check, fetcher, config):
        """A negated operator on a request key is not a principal carve-out.

        The repo's own rcp-valid-enforce-encryption fixture uses StringNotEquals on
        s3:x-amz-server-side-encryption, which must stay clean.
        """
        statement = Statement(
            Effect="Deny",
            Action=["s3:PutObject"],
            Resource=["*"],
            Principal="*",
            Condition={"StringNotEquals": {"s3:x-amz-server-side-encryption": "*"}},
        )
        assert await check.execute(statement, 0, fetcher, config) == []

    @pytest.mark.asyncio
    async def test_positive_operator_wildcard_is_ignored(self, check, fetcher, config):
        """StringEquals is not a carve-out -- it narrows the deny rather than exempting."""
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal="*",
            Condition={"StringEquals": {"aws:PrincipalAccount": "*"}},
        )
        assert await check.execute(statement, 0, fetcher, config) == []

    @pytest.mark.asyncio
    async def test_allow_with_negated_principal_condition_still_validated(self, check, fetcher, config):
        """The carve-out path must not swallow the Allow rules."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["*"],
            Principal="*",
            Condition={"ArnNotEquals": {"aws:PrincipalArn": "*"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "missing_principal_condition_any_of"


class TestCrossAccountOrgRequirement:
    """The cross_account_org requirement must accept the set operator its key needs."""

    @staticmethod
    def _config() -> CheckConfig:
        from iam_validator.core.config.principal_requirements import get_principal_requirement

        requirement = get_principal_requirement("cross_account_org")
        assert requirement is not None
        return CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "block_wildcard_principal": False,
                "blocked_principals": [],
                "allowed_principals": [],
                "allowed_service_principals": ["aws:*"],
                "principal_condition_requirements": [requirement],
            },
        )

    @pytest.mark.asyncio
    async def test_org_paths_with_set_operator_satisfies_requirement(self, check, fetcher):
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Condition={"ForAnyValue:StringLike": {"aws:PrincipalOrgPaths": "o-123456789/r-ab12/ou-ab12-11111111/*"}},
        )
        issues = await check.execute(statement, 0, fetcher, self._config())
        assert issues == []

    @pytest.mark.asyncio
    async def test_org_id_with_string_equals_satisfies_requirement(self, check, fetcher):
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Condition={"StringEquals": {"aws:PrincipalOrgID": "o-123456789"}},
        )
        issues = await check.execute(statement, 0, fetcher, self._config())
        assert issues == []

    @pytest.mark.asyncio
    async def test_unconditioned_cross_account_root_still_flagged(self, check, fetcher):
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
        )
        issues = await check.execute(statement, 0, fetcher, self._config())
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_null_check_alone_does_not_satisfy_requirement(self, check, fetcher):
        for value in ("true", "false"):
            statement = Statement(
                Effect="Allow",
                Action=["s3:GetObject"],
                Resource=["arn:aws:s3:::my-bucket/*"],
                Principal={"AWS": "arn:aws:iam::123456789012:root"},
                Condition={"Null": {"aws:PrincipalOrgID": value, "aws:PrincipalOrgPaths": value}},
            )
            issues = await check.execute(statement, 0, fetcher, self._config())
            assert len(issues) == 1, value

    @pytest.mark.asyncio
    async def test_miscased_condition_key_satisfies_requirement(self, check, fetcher):
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Condition={"StringEquals": {"aws:principalorgid": "o-123456789"}},
        )
        issues = await check.execute(statement, 0, fetcher, self._config())
        assert issues == []

    @pytest.mark.asyncio
    async def test_miscased_operator_satisfies_requirement(self, check, fetcher):
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Condition={"stringequals": {"aws:PrincipalOrgID": "o-123456789"}},
        )
        issues = await check.execute(statement, 0, fetcher, self._config())
        assert issues == []

    def test_org_paths_example_uses_a_set_operator(self):
        from iam_validator.core.config.principal_requirements import get_principal_requirement

        requirement = get_principal_requirement("cross_account_org")
        assert requirement is not None
        entry = next(
            c for c in requirement["required_conditions"]["any_of"] if c["condition_key"] == "aws:PrincipalOrgPaths"
        )
        assert "operator" not in entry
        assert "ForAnyValue:StringLike" in entry["example"]

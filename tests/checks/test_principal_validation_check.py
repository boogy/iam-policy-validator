"""Tests for PrincipalValidationCheck."""

import pytest

from iam_validator.checks.principal_validation import PrincipalValidationCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.finding_fingerprint import compute_finding_hash
from iam_validator.core.models import IAMPolicy, Statement, ValidationIssue


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


async def _run_both(check, statement: Statement, fetcher, config: CheckConfig) -> list[ValidationIssue]:
    policy = IAMPolicy(Version="2012-10-17", Statement=[statement])
    return [
        *await check.execute_policy(policy, "policy.json", fetcher, config),
        *await check.execute(statement, 0, fetcher, config),
    ]


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


class TestBlockedPrincipalsPrecedenceOverServiceAllowlist:
    """`blocked_principals` must win over the `allowed_service_principals` wildcard."""

    @pytest.mark.asyncio
    async def test_blocked_service_principal_is_not_bypassed_by_default_allowlist(self, check, fetcher):
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": ["lambda.amazonaws.com"],
                "allowed_service_principals": ["aws:*"],
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Principal={"Service": "lambda.amazonaws.com"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "blocked_principal"

    @pytest.mark.asyncio
    async def test_blocked_service_principal_is_not_bypassed_by_explicit_allowlist(self, check, fetcher):
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": ["lambda.amazonaws.com"],
                "allowed_service_principals": ["lambda.amazonaws.com"],
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Principal={"Service": "lambda.amazonaws.com"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "blocked_principal"

    @pytest.mark.asyncio
    async def test_unblocked_service_principal_still_allowed(self, check, fetcher):
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": ["lambda.amazonaws.com"],
                "allowed_service_principals": ["aws:*"],
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["sts:AssumeRole"],
            Principal={"Service": "ec2.amazonaws.com"},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0


class TestPrincipalConditionRequirements:
    """Tests for advanced principal_condition_requirements feature."""

    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @pytest.mark.parametrize(
        "required_conditions",
        [
            ["aws:SourceArn", {"condition_key": "aws:SourceAccount"}],
            {"all_of": ["aws:SourceArn", {"condition_key": "aws:SourceAccount"}]},
            {"any_of": ["aws:SourceArn", {"condition_key": "aws:SourceAccount"}]},
            {"none_of": ["aws:SourceArn", {"condition_key": "aws:SourceAccount"}]},
            {"all_of": "aws:SourceArn", "any_of": [{"condition_key": "aws:SourceAccount"}]},
            {"all_of": [{"condition_key": "aws:SourceAccount"}], "any_of": {"condition_key": "aws:SourceArn"}},
        ],
    )
    async def test_non_mapping_condition_entry_is_reported_not_raised(self, check, fetcher, required_conditions):
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [{"principals": ["*"], "required_conditions": required_conditions}],
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            Principal="*",
        )
        issues = await _run_both(check, statement, fetcher, config)
        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len(invalid) == 1
        assert invalid[0].severity == "error"
        assert "aws:SourceArn" in invalid[0].message
        others = [i for i in issues if i not in invalid]
        assert len(others) == (0 if "none_of" in required_conditions else 1)
        assert all("aws:SourceAccount" in i.message for i in others)

    @pytest.mark.parametrize("required_conditions", ["aws:SourceArn", 3])
    async def test_scalar_required_conditions_is_reported(self, check, fetcher, required_conditions):
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [{"principals": ["*"], "required_conditions": required_conditions}],
            },
        )
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal="*")
        issues = await _run_both(check, statement, fetcher, config)
        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]

    @pytest.mark.parametrize(
        ("required_conditions", "expected"),
        [
            ({"any_of": [{"conditon_key": "aws:SourceArn"}]}, ["invalid_condition_requirement"]),
            ([{"conditon_key": "aws:SourceArn"}], ["invalid_condition_requirement"]),
            (
                {"any_of": [{"conditon_key": "aws:SourceArn"}, {"condition_key": "aws:SourceAccount"}]},
                ["invalid_condition_requirement", "missing_principal_condition_any_of"],
            ),
            (
                {"allof": [{"condition_key": "aws:SourceArn"}], "any_of": [{"condition_key": "aws:SourceAccount"}]},
                ["invalid_condition_requirement", "missing_principal_condition_any_of"],
            ),
        ],
    )
    async def test_keyless_entry_or_unknown_group_is_reported_never_satisfied(
        self, check, fetcher, required_conditions, expected
    ):
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [{"principals": ["*"], "required_conditions": required_conditions}],
            },
        )
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal="*")
        issues = await _run_both(check, statement, fetcher, config)
        assert sorted(i.issue_type for i in issues) == expected

    @pytest.mark.parametrize(
        ("condition", "expected"),
        [
            (None, ["missing_principal_condition_any_of"]),
            ({"StringEquals": {"aws:SourceArn": "a"}}, ["missing_principal_condition_any_of"]),
            ({"StringEquals": {"aws:SourceArn": "a", "aws:SourceAccount": "1"}}, []),
        ],
    )
    async def test_nested_all_of_entry_under_any_of_needs_every_key(self, check, fetcher, condition, expected):
        nested = {"all_of": [{"condition_key": "aws:SourceArn"}, {"condition_key": "aws:SourceAccount"}]}
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {"principals": ["*"], "required_conditions": {"any_of": [nested]}}
                ],
            },
        )
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal="*", Condition=condition
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert [i.issue_type for i in issues] == expected

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
        "not *". The guard must not silence that. Two independent rules see it: the
        configured denylist (`blocked_principal`) and the logic of the carve-out itself
        (`ineffective_deny_carve_out`, which fires with no config at all).
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
        assert sorted(i.issue_type for i in issues) == [
            "blocked_principal",
            "ineffective_deny_carve_out",
        ]

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
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal="*",
            Condition={"StringNotLike": {"aws:PrincipalOrgID": "*"}},
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
            ("StringNotLikeIfExists", "aws:PrincipalServiceName"),
            ("StringNotLike", "aws:PrincipalOrgPaths"),
            ("ForAnyValue:StringNotLike", "aws:PrincipalTag/team"),
        ],
    )
    async def test_wildcard_carve_out_is_flagged(self, check, fetcher, config, operator, key):
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
    @pytest.mark.parametrize(
        "operator,key",
        [
            ("StringNotEquals", "aws:PrincipalOrgID"),
            ("StringNotEquals", "aws:PrincipalAccount"),
            ("StringNotEqualsIfExists", "aws:PrincipalServiceName"),
            ("StringNotEqualsIgnoreCase", "aws:PrincipalTag/team"),
            ("ForAllValues:StringNotEquals", "aws:PrincipalTag/team"),
        ],
    )
    async def test_literal_operator_wildcard_carve_out_denies_everyone(self, check, fetcher, config, operator, key):
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal="*",
            Condition={operator: {key: "*"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert [i.issue_type for i in issues] == ["literal_wildcard_deny_carve_out"]
        assert "every principal" in issues[0].message

    @pytest.mark.asyncio
    async def test_literal_wildcard_beside_real_values_keeps_their_carve_out(self, check, fetcher, config):
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal="*",
            Condition={"StringNotEquals": {"aws:PrincipalOrgID": ["o-abc123", "*"]}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert [i.issue_type for i in issues] == ["literal_wildcard_deny_carve_out"]
        assert "every principal" not in issues[0].message

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("principal", "claims_everyone"),
        [
            ({"AWS": "*"}, True),
            ({"AWS": ["arn:aws:iam::111122223333:root", "*"]}, True),
            ({"AWS": "arn:aws:iam::111122223333:role/SpecificRole"}, False),
            ({"Service": "*"}, False),
        ],
    )
    async def test_literal_wildcard_claims_everyone_only_for_wildcard_principal(
        self, check, fetcher, config, principal, claims_everyone
    ):
        statement = Statement(
            Effect="Deny",
            Action=["s3:*"],
            Resource=["*"],
            Principal=principal,
            Condition={"StringNotEquals": {"aws:PrincipalArn": "*"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert [i.issue_type for i in issues] == ["literal_wildcard_deny_carve_out"]
        assert ("every principal" in issues[0].message) is claims_everyone

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "condition",
        [
            {
                "ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/Trusted"},
                "StringNotEquals": {"aws:PrincipalOrgID": "*"},
            },
            {"StringNotEquals": {"aws:PrincipalOrgID": "*", "aws:PrincipalAccount": "111122223333"}},
            {"ForAnyValue:StringNotEquals": {"aws:PrincipalTag/team": "*"}},
            {"foranyvalue:StringNotEquals": {"aws:PrincipalTag/team": "*"}},
        ],
    )
    async def test_literal_wildcard_beside_other_conditions_does_not_claim_everyone(
        self, check, fetcher, config, condition
    ):
        statement = Statement(Effect="Deny", Action=["s3:*"], Resource=["*"], Principal="*", Condition=condition)
        issues = await check.execute(statement, 0, fetcher, config)
        assert [i.issue_type for i in issues] == ["literal_wildcard_deny_carve_out"]
        assert "every principal" not in issues[0].message

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


class TestPrincipalRequirementConfigRobustness:
    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @staticmethod
    def _config(requirement: dict) -> CheckConfig:
        return CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [{"principals": ["*"], **requirement}],
            },
        )

    @staticmethod
    def _statement(condition: dict | None = None) -> Statement:
        return Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal="*", Condition=condition
        )

    @pytest.mark.parametrize("operator", [5, ["StringEquals"]])
    async def test_non_string_operator_is_reported_not_raised(self, check, operator):
        config = self._config({"required_conditions": [{"condition_key": "aws:SourceArn", "operator": operator}]})

        issues = await _run_both(check, self._statement({"StringEquals": {"aws:SourceAccount": "1"}}), None, config)

        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]
        assert "operator" in issues[0].message

    @pytest.mark.parametrize("severity", [None, "", "urgent"])
    @pytest.mark.parametrize(
        ("required_conditions", "condition", "issue_type"),
        [
            ({"any_of": [{"condition_key": "aws:SourceArn"}]}, None, "missing_principal_condition_any_of"),
            (
                {"none_of": [{"condition_key": "aws:SourceArn"}]},
                {"StringEquals": {"aws:SourceArn": "x"}},
                "forbidden_principal_condition",
            ),
            ([{"condition_key": "aws:SourceArn"}], None, "missing_principal_condition"),
        ],
    )
    async def test_null_or_invalid_requirement_severity_falls_back(
        self, check, severity, required_conditions, condition, issue_type
    ):
        config = self._config({"severity": severity, "required_conditions": required_conditions})
        statement = self._statement(condition)
        policy = IAMPolicy(Version="2012-10-17", Statement=[statement])

        issues = await check.execute_policy(policy, "policy.json", None, config)
        issues += await check.execute(statement, 0, None, config)

        invalid = [] if severity is None else [("invalid_condition_requirement", "error")]
        assert [(i.issue_type, i.severity) for i in issues] == [*invalid, (issue_type, "high")]

    async def test_invalid_entry_severity_falls_back_to_requirement(self, check):
        config = self._config(
            {"severity": "low", "required_conditions": [{"condition_key": "aws:SourceArn", "severity": "urgent"}]}
        )

        issues = await _run_both(check, self._statement(), None, config)

        assert [(i.issue_type, i.severity) for i in issues] == [
            ("invalid_condition_requirement", "error"),
            ("missing_principal_condition", "low"),
        ]

    async def test_invalid_leaf_severity_falls_back_to_parent_all_of_severity(self, check):
        entry = {"severity": "low", "all_of": [{"condition_key": "aws:SourceArn", "severity": "Low"}]}
        config = self._config({"required_conditions": {"all_of": [entry]}})

        issues = await _run_both(check, self._statement(), None, config)

        assert [(i.issue_type, i.severity) for i in issues] == [
            ("invalid_condition_requirement", "error"),
            ("missing_principal_condition", "low"),
        ]

    async def test_nested_all_of_children_inherit_parent_presentation(self, check):
        entry = {
            "severity": "critical",
            "description": "DESC",
            "example": "EX",
            "all_of": [
                {"condition_key": "aws:SourceArn", "severity": None},
                {"condition_key": "aws:SourceAccount", "severity": "low"},
            ],
        }
        config = self._config({"required_conditions": [entry]})

        issues = await check.execute(self._statement(), 0, None, config)

        assert [(i.severity, i.suggestion, i.example) for i in issues] == [
            ("critical", "DESC", "EX"),
            ("low", "DESC", "EX"),
        ]


class TestPrincipalRequirementPresentation:
    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @staticmethod
    def _config(requirement: dict) -> CheckConfig:
        return CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [{"principals": ["*"], **requirement}],
            },
        )

    @staticmethod
    def _statement(condition: dict | None = None) -> Statement:
        return Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal="*", Condition=condition
        )

    async def test_null_operator_example_renders_default_operator(self, check):
        config = self._config({"required_conditions": [{"condition_key": "aws:SourceArn", "operator": None}]})

        issues = await check.execute(self._statement(), 0, None, config)

        assert [i.issue_type for i in issues] == ["missing_principal_condition"]
        assert '"StringEquals"' in issues[0].example
        assert "None" not in issues[0].example

    async def test_none_of_entry_severity_overrides_requirement_severity(self, check):
        config = self._config(
            {
                "severity": "low",
                "required_conditions": {"none_of": [{"condition_key": "aws:SourceArn", "severity": "critical"}]},
            }
        )

        issues = await check.execute(self._statement({"StringEquals": {"aws:SourceArn": "x"}}), 0, None, config)

        assert [(i.issue_type, i.severity) for i in issues] == [("forbidden_principal_condition", "critical")]

    @pytest.mark.parametrize("severity", ["Critical", "hgih"])
    async def test_invalid_requirement_severity_is_reported(self, check, severity):
        config = self._config({"severity": severity, "required_conditions": [{"condition_key": "aws:SourceArn"}]})
        statement = self._statement()
        policy = IAMPolicy(Version="2012-10-17", Statement=[statement])

        issues = await check.execute_policy(policy, "policy.json", None, config)
        issues += await check.execute(statement, 0, None, config)

        assert sorted((i.issue_type, i.severity) for i in issues) == [
            ("invalid_condition_requirement", "error"),
            ("missing_principal_condition", "high"),
        ]
        invalid = next(i for i in issues if i.issue_type == "invalid_condition_requirement")
        assert severity in invalid.message
        assert "Set `severity` to one of" in invalid.suggestion

    @pytest.mark.parametrize(
        "required_conditions",
        [
            [{"condition_key": "aws:SourceArn", "severity": "hgih"}],
            {"any_of": [{"condition_key": "aws:SourceArn", "severity": "hgih"}]},
            {"all_of": [{"all_of": [{"condition_key": "aws:SourceArn", "severity": "hgih"}]}]},
            [{"severity": "hgih", "all_of": [{"condition_key": "aws:SourceArn"}]}],
        ],
    )
    async def test_invalid_entry_severity_is_reported(self, check, required_conditions):
        config = self._config({"severity": "low", "required_conditions": required_conditions})

        issues = await _run_both(check, self._statement(), None, config)

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len(invalid) == 1
        assert "hgih" in invalid[0].message
        assert [i.severity for i in issues if i not in invalid] == ["low"]


class TestPrincipalRequirementPolicyLevelSeverity:
    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @staticmethod
    def _config(requirement: dict) -> CheckConfig:
        return CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [{"principals": ["*"], **requirement}],
            },
        )

    @staticmethod
    def _statement(principal: str = "*") -> Statement:
        return Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal=principal)

    async def _run_all(self, check, config, statements: list[Statement]) -> list:
        policy = IAMPolicy(Version="2012-10-17", Statement=statements)
        issues = list(await check.execute_policy(policy, "policy.json", None, config))
        for idx, statement in enumerate(statements):
            issues.extend(await check.execute(statement, idx, None, config))
        return issues

    async def test_invalid_requirement_severity_reported_once_per_policy(self, check):
        config = self._config({"severity": "urgent", "required_conditions": [{"condition_key": "aws:SourceArn"}]})

        issues = await self._run_all(check, config, [self._statement() for _ in range(3)])

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert [(i.statement_index, i.severity) for i in invalid] == [(-1, "error")]
        assert [i.severity for i in issues if i not in invalid] == ["high"] * 3

    async def test_not_reported_when_no_statement_matches(self, check):
        config = self._config(
            {
                "principals": ["arn:aws:iam::*:root"],
                "severity": "urgent",
                "required_conditions": [{"condition_key": "aws:SourceArn"}],
            }
        )

        policy = IAMPolicy(Version="2012-10-17", Statement=[self._statement()])

        assert await check.execute_policy(policy, "policy.json", None, config) == []

    async def test_entry_with_condition_key_and_all_of_is_reported(self, check):
        entry = {"condition_key": "aws:SourceArn", "all_of": [{"condition_key": "aws:SourceAccount"}]}
        config = self._config({"required_conditions": [entry]})

        issues = await _run_both(check, self._statement(), None, config)

        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]

    @pytest.mark.parametrize(
        "required_conditions",
        [
            [{"condition_key": "aws:SourceArn", "all_of": None}],
            {"all_of": [{"all_of": [{"condition_key": "aws:SourceArn", "all_of": None}]}]},
        ],
    )
    async def test_null_all_of_beside_condition_key_is_enforced(self, check, required_conditions):
        config = self._config({"required_conditions": required_conditions})
        policy = IAMPolicy(Version="2012-10-17", Statement=[self._statement()])

        issues = await check.execute_policy(policy, "policy.json", None, config)
        issues += await check.execute(self._statement(), 0, None, config)

        assert [i.issue_type for i in issues] == ["missing_principal_condition"]

    @pytest.mark.parametrize("required_conditions", [False, 0, ""])
    async def test_falsy_scalar_required_conditions_is_reported(self, check, required_conditions):
        config = self._config({"required_conditions": required_conditions})

        issues = await _run_both(check, self._statement(), None, config)

        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]


class TestPrincipalRequirementEvaluationScope:
    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @staticmethod
    def _config(requirement: dict | None = None, **options) -> CheckConfig:
        requirements = None if requirement is None else [{"principals": ["*"], **requirement}]
        return CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": [], "principal_condition_requirements": requirements, **options},
        )

    @staticmethod
    def _policy(principal) -> IAMPolicy:
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal=principal
        )
        return IAMPolicy(Version="2012-10-17", Statement=[statement])

    async def _invalid(self, check, config, principal) -> list:
        policy = self._policy(principal)
        issues = list(await check.execute_policy(policy, "policy.json", None, config))
        issues.extend(await check.execute(policy.statement[0], 0, None, config))
        return [i for i in issues if i.issue_type == "invalid_condition_requirement"]

    _BAD_SEVERITY = {"severity": "urgent", "required_conditions": [{"condition_key": "aws:SourceArn"}]}

    async def test_null_requirements_do_not_raise(self, check):
        assert await check.execute_policy(self._policy("*"), "policy.json", None, self._config()) == []

    async def test_bad_severity_not_reported_for_blocked_wildcard_principal(self, check):
        config = self._config(self._BAD_SEVERITY, block_wildcard_principal=True)

        assert await self._invalid(check, config, "*") == []

    async def test_bad_severity_not_reported_for_service_principal_wildcard(self, check):
        assert await self._invalid(check, self._config(self._BAD_SEVERITY), {"Service": "*"}) == []

    async def test_bad_severity_reported_for_aws_wildcard_principal(self, check):
        invalid = await self._invalid(check, self._config(self._BAD_SEVERITY), {"AWS": "*"})

        assert [i.statement_index for i in invalid] == [-1]

    async def test_string_principals_pattern_matches(self, check):
        root = "arn:aws:iam::123456789012:root"
        config = self._config({"principals": root, "required_conditions": [{"condition_key": "aws:SourceArn"}]})
        statement = self._policy({"AWS": root}).statement[0]

        issues = await check.execute(statement, 0, None, config)

        assert [i.issue_type for i in issues] == ["missing_principal_condition"]
        assert root in issues[0].message

    async def test_string_principals_label_in_invalid_severity(self, check):
        root = "arn:aws:iam::123456789012:root"
        config = self._config({**self._BAD_SEVERITY, "principals": root})

        invalid = await self._invalid(check, config, {"AWS": root})

        assert len(invalid) == 1
        assert f"`{root}`" in invalid[0].message

    @pytest.mark.parametrize("principals", [123, {"AWS": "*"}, True])
    async def test_malformed_principals_reported_once_per_policy(self, check, principals):
        config = self._config({"principals": principals, "required_conditions": [{"condition_key": "aws:SourceArn"}]})

        policy = self._policy("*")
        issues = list(await check.execute_policy(policy, "policy.json", None, config))
        issues.extend(await check.execute(policy.statement[0], 0, None, config))

        assert [(i.issue_type, i.statement_index, i.severity) for i in issues] == [
            ("invalid_condition_requirement", -1, "error")
        ]


class TestPrincipalListConfigRobustness:
    @pytest.fixture
    def check(self):
        return PrincipalValidationCheck()

    @staticmethod
    def _policy(principal) -> IAMPolicy:
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal=principal
        )
        return IAMPolicy(Version="2012-10-17", Statement=[statement])

    async def _run(self, check, options: dict, principal) -> list:
        config = CheckConfig(
            check_id="principal_validation", enabled=True, config={"blocked_principals": [], **options}
        )
        policy = self._policy(principal)
        issues = list(await check.execute_policy(policy, "policy.json", None, config))
        issues.extend(await check.execute(policy.statement[0], 0, None, config))
        return issues

    @pytest.mark.parametrize("key", ["blocked_principals", "allowed_principals"])
    async def test_non_string_list_entry_reported_once_and_string_entries_kept(self, check, key):
        root = "arn:aws:iam::123456789012:root"
        issues = await self._run(check, {key: [123456789012, root]}, {"AWS": root})

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert [(i.statement_index, i.severity) for i in invalid] == [(-1, "error")]
        assert key in invalid[0].message and "123456789012" in invalid[0].message
        expected = ["blocked_principal"] if key == "blocked_principals" else []
        assert [i.issue_type for i in issues if i not in invalid] == expected

    async def test_non_string_allowed_service_principal_reported(self, check):
        options = {"allowed_principals": ["arn:aws:iam::*:root"], "allowed_service_principals": [5]}
        issues = await self._run(check, options, {"Service": "s3.amazonaws.com"})

        assert [(i.issue_type, i.statement_index) for i in issues] == [
            ("invalid_condition_requirement", -1),
            ("unauthorized_principal", 0),
        ]

    async def test_non_string_requirement_principal_reported_once(self, check):
        requirement = {"principals": [123, "*"], "required_conditions": [{"condition_key": "aws:SourceArn"}]}
        issues = await self._run(check, {"principal_condition_requirements": [requirement]}, "*")

        assert [(i.issue_type, i.statement_index) for i in issues] == [
            ("invalid_condition_requirement", -1),
            ("missing_principal_condition", 0),
        ]

    async def test_non_string_requirement_principal_not_reported_when_requirement_matches_nothing(self, check):
        requirement = {
            "principals": ["arn:aws:iam::111111111111:root", 123],
            "required_conditions": [{"condition_key": "aws:SourceArn"}],
        }
        issues = await self._run(
            check, {"principal_condition_requirements": [requirement]}, {"AWS": "arn:aws:iam::222222222222:root"}
        )

        assert [i.issue_type for i in issues if i.issue_type == "invalid_condition_requirement"] == []

    async def test_requirement_with_only_non_string_principals_reported(self, check):
        requirement = {"principals": [123456789012], "required_conditions": [{"condition_key": "aws:SourceArn"}]}
        issues = await self._run(check, {"principal_condition_requirements": [requirement]}, {"AWS": "123456789012"})

        assert [(i.issue_type, i.statement_index) for i in issues] == [("invalid_condition_requirement", -1)]

    @pytest.mark.parametrize("allowed", [[111111111111], 111111111111, {"AWS": "x"}, True])
    async def test_allowlist_with_no_string_entries_stays_restrictive(self, check, allowed):
        issues = await self._run(check, {"allowed_principals": allowed}, {"AWS": "arn:aws:iam::999999999999:root"})

        assert [(i.issue_type, i.statement_index) for i in issues] == [
            ("invalid_condition_requirement", -1),
            ("unauthorized_principal", 0),
        ]

    async def test_empty_allowlist_is_disabled(self, check):
        issues = await self._run(check, {"allowed_principals": []}, {"AWS": "arn:aws:iam::999999999999:root"})

        assert issues == []

    @pytest.mark.parametrize("services", [[5], 5, {"a": 1}, False])
    async def test_service_allowlist_with_no_string_entries_allows_no_service(self, check, services):
        options = {"allowed_principals": ["arn:aws:iam::*:root"], "allowed_service_principals": services}
        issues = await self._run(check, options, {"Service": "s3.amazonaws.com"})

        assert [(i.issue_type, i.statement_index) for i in issues] == [
            ("invalid_condition_requirement", -1),
            ("unauthorized_principal", 0),
        ]

    async def test_null_service_allowlist_uses_default(self, check):
        options = {"allowed_principals": ["arn:aws:iam::*:root"], "allowed_service_principals": None}
        issues = await self._run(check, options, {"Service": "s3.amazonaws.com"})

        assert issues == []

    @pytest.mark.parametrize("key", ["blocked_principals", "allowed_principals", "allowed_service_principals"])
    @pytest.mark.parametrize("value", [123456789012, {"AWS": "*"}, True])
    async def test_scalar_non_string_list_value_reported_once(self, check, key, value):
        issues = await self._run(check, {key: value}, {"AWS": "arn:aws:iam::123456789012:root"})

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert [(i.statement_index, i.severity) for i in invalid] == [(-1, "error")]
        assert key in invalid[0].message and repr(value) in invalid[0].message
        assert "not a string or list" in invalid[0].message

    async def test_scalar_non_string_requirement_principals_reported_once(self, check):
        requirement = {"principals": 123, "required_conditions": [{"condition_key": "aws:SourceArn"}]}
        issues = await self._run(check, {"principal_condition_requirements": [requirement]}, "*")

        assert [(i.issue_type, i.statement_index) for i in issues] == [("invalid_condition_requirement", -1)]

    @pytest.mark.parametrize(
        ("principal", "expected"),
        [
            ({"AWS": [123456789012]}, []),
            ({"AWS": 123}, []),
            ({"AWS": [None, "*"]}, ["unauthorized_principal", "missing_principal_condition"]),
        ],
    )
    async def test_non_string_policy_principal_does_not_raise(self, check, principal, expected):
        requirement = {"principals": ["*"], "required_conditions": [{"condition_key": "aws:SourceArn"}]}
        options = {
            "allowed_principals": ["arn:aws:iam::*:root"],
            "blocked_principals": ["arn:aws:iam::999999999999:root"],
            "principal_condition_requirements": [requirement],
        }
        issues = await self._run(check, options, principal)

        assert [i.issue_type for i in issues] == expected

    @pytest.mark.parametrize("requirements", [["oops", 5], {"principals": ["*"]}, "oops", 5])
    async def test_malformed_requirement_entries_reported_once_not_raised(self, check, requirements):
        issues = await self._run(check, {"principal_condition_requirements": requirements}, "*")

        expected = 2 if isinstance(requirements, list) else 1
        assert [(i.issue_type, i.statement_index) for i in issues] == [("invalid_condition_requirement", -1)] * expected

    async def test_non_dict_requirement_entry_skipped_beside_valid_one(self, check):
        requirement = {"principals": ["*"], "required_conditions": [{"condition_key": "aws:SourceArn"}]}
        issues = await self._run(check, {"principal_condition_requirements": ["oops", requirement]}, "*")

        assert [(i.issue_type, i.statement_index) for i in issues] == [
            ("invalid_condition_requirement", -1),
            ("missing_principal_condition", 0),
        ]


class TestNestedAllOfMessages:
    NESTED = {"all_of": [{"condition_key": "aws:SourceIp"}, {"condition_key": "aws:SourceVpc"}]}

    async def _issues(self, required_conditions: dict, condition: dict | None) -> list:
        requirement = {"principals": ["*"], "required_conditions": required_conditions}
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": [], "principal_condition_requirements": [requirement]},
        )
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal="*", Condition=condition
        )
        return await PrincipalValidationCheck().execute(statement, 0, None, config)

    async def test_any_of_message_quotes_each_nested_key(self):
        issues = await self._issues({"any_of": [self.NESTED, {"condition_key": "aws:SourceArn"}]}, None)

        assert "(`aws:SourceIp` + `aws:SourceVpc`), `aws:SourceArn`" in issues[0].message
        assert "**Option 1**: (`aws:SourceIp` + `aws:SourceVpc`)" in issues[0].suggestion

    async def test_none_of_message_quotes_each_nested_key(self):
        condition = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}, "StringEquals": {"aws:SourceVpc": "vpc-1"}}
        issues = await self._issues({"none_of": [self.NESTED]}, condition)

        assert "`Condition` (`aws:SourceIp` + `aws:SourceVpc`)" in issues[0].message
        assert "Remove the (`aws:SourceIp` + `aws:SourceVpc`) `Condition`" in issues[0].suggestion

    async def test_any_of_message_quotes_each_principal_once(self):
        issues = await self._issues({"any_of": [{"condition_key": "aws:SourceArn"}]}, None)
        assert "`Principal`s `*` require" in issues[0].message

    async def test_none_of_message_quotes_each_principal_once(self):
        issues = await self._issues(
            {"none_of": [{"condition_key": "aws:SourceIp"}]}, {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
        )
        assert "`Principal`s `*` must NOT" in issues[0].message

    async def test_nested_option_shows_child_values(self):
        nested = {
            "all_of": [
                {"condition_key": "aws:SourceVpc", "expected_value": "vpc-1", "description": "vpc d"},
                {"condition_key": "aws:SourceIp"},
            ]
        }
        issues = await self._issues({"any_of": [nested]}, None)
        assert (
            "**Option 1**: (`aws:SourceVpc` + `aws:SourceIp`) - vpc d (values: `aws:SourceVpc`: `vpc-1`)"
            in issues[0].suggestion
        )

    @pytest.mark.parametrize(
        ("required_conditions", "condition"),
        [
            (
                {"none_of": [{"condition_key": "aws:SourceIp"}, {"condition_key": "aws:SourceArn"}]},
                {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}, "ArnLike": {"aws:SourceArn": "arn:aws:s3:::b"}},
            ),
            ({"all_of": [{"condition_key": "aws:SourceIp"}, {"condition_key": "aws:SourceArn"}]}, None),
        ],
    )
    async def test_findings_for_different_keys_get_distinct_ids(self, required_conditions, condition):
        issues = await self._issues(required_conditions, condition)
        assert [i.condition_key for i in issues] == ["aws:SourceIp", "aws:SourceArn"]
        assert (
            len(
                {
                    compute_finding_hash(
                        "p.json",
                        "principal_validation",
                        i.issue_type,
                        i.statement_sid,
                        i.statement_index,
                        i.action,
                        i.resource,
                        i.condition_key,
                    )
                    for i in issues
                }
            )
            == 2
        )

    async def test_nested_option_shows_deep_leaf_values_not_group_value(self):
        deep = {"all_of": [{"condition_key": "aws:SourceVpc", "expected_value": "vpc-1"}]}
        nested = {"expected_value": "ignored", "all_of": [deep, {"condition_key": "aws:SourceIp"}]}
        issues = await self._issues({"any_of": [nested]}, None)
        assert "(values: `aws:SourceVpc`: `vpc-1`)" in issues[0].suggestion
        assert "ignored" not in issues[0].suggestion

    async def test_any_of_and_nested_none_of_findings_carry_no_synthetic_key(self):
        any_of = await self._issues({"any_of": [self.NESTED, {"condition_key": "aws:SourceArn"}]}, None)
        condition = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}, "StringEquals": {"aws:SourceVpc": "vpc-1"}}
        none_of = await self._issues({"none_of": [self.NESTED]}, condition)
        assert [i.condition_key for i in any_of + none_of] == [None, None]


class TestPrincipalEntryProblemsReportedOncePerPolicy:
    @pytest.mark.parametrize(
        "required_conditions",
        [
            {"any_of": "oops"},
            [{"condition_key": "aws:SourceArn", "severity": "urgent"}],
            {"all_of": [{"all_of": [{"condition_key": "aws:SourceArn", "severity": "Low"}]}]},
            ["aws:SourceArn"],
            {"anyof": [{"condition_key": "aws:SourceArn"}]},
            "aws:SourceArn",
        ],
    )
    async def test_entry_problem_reported_once_for_many_statements(self, required_conditions):
        check = PrincipalValidationCheck()
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [{"principals": ["*"], "required_conditions": required_conditions}],
            },
        )
        statements = [
            Statement(
                Sid=f"S{i}", Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal="*"
            )
            for i in range(3)
        ]
        policy = IAMPolicy(Version="2012-10-17", Statement=statements)

        issues = list(await check.execute_policy(policy, "policy.json", None, config))
        for idx, statement in enumerate(statements):
            issues += await check.execute(statement, idx, None, config)

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert [i.statement_index for i in invalid] == [-1]


def _requirement_config(principals: list[str], required_conditions) -> CheckConfig:
    return CheckConfig(
        check_id="principal_validation",
        enabled=True,
        config={
            "blocked_principals": [],
            "principal_condition_requirements": [
                {"principals": principals, "required_conditions": required_conditions}
            ],
        },
    )


def _principal_statement(principal) -> Statement:
    return Statement(
        Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal={"AWS": principal}
    )


class TestPrincipalRequirementMatching:
    @pytest.mark.parametrize(
        ("requirement_principal", "statement_principal"),
        [
            ("arn:aws:iam::*:root", "123456789012"),
            ("123456789012", "arn:aws:iam::123456789012:root"),
        ],
    )
    async def test_account_id_and_root_arn_are_the_same_principal(
        self, check, requirement_principal, statement_principal
    ):
        config = _requirement_config([requirement_principal], [{"condition_key": "aws:SourceArn"}])

        issues = await _run_both(check, _principal_statement(statement_principal), None, config)

        assert [i.issue_type for i in issues] == ["missing_principal_condition"]

    @pytest.mark.parametrize("group", ["any_of", "none_of"])
    async def test_principal_matched_by_several_patterns_is_quoted_once(self, check, group):
        condition = {"condition_key": "aws:SourceArn"}
        required = {group: [condition, {"condition_key": "aws:SourceAccount"}]}
        config = _requirement_config(["arn:aws:iam::123456789012:*", "arn:aws:iam::*:root"], required)
        statement = _principal_statement(["arn:aws:iam::123456789012:root", "arn:aws:iam::123456789012:root"])
        if group == "none_of":
            statement = Statement(
                **{**statement.model_dump(by_alias=True), "Condition": {"ArnLike": {"aws:SourceArn": "x"}}}
            )

        issues = await _run_both(check, statement, None, config)

        assert len(issues) == 1
        assert issues[0].message.count("123456789012:root") == 1


def _finding_ids(issues: list[ValidationIssue]) -> list[str]:
    return [
        compute_finding_hash(
            "policy.json",
            "principal_validation",
            i.issue_type,
            i.statement_sid,
            i.statement_index,
            i.action,
            i.resource,
            i.condition_key,
            i.finding_key,
        )
        for i in issues
    ]


class TestPrincipalFindingIdentity:
    async def test_config_problems_in_different_requirements_have_distinct_ids(self, check):
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {"principals": ["*"], "required_conditions": [{"condition_key": 5}]},
                    {"principals": ["*"], "required_conditions": [{"condition_key": 6}]},
                ],
            },
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        ids = _finding_ids([i for i in issues if i.issue_type == "invalid_condition_requirement"])
        assert len(ids) == 2
        assert len(set(ids)) == 2

    async def test_config_problem_names_the_requirement_principals(self, check):
        config = _requirement_config(["arn:aws:iam::*:root"], [{"condition_key": 5}])

        issues = await _run_both(check, _principal_statement("arn:aws:iam::123456789012:root"), None, config)

        assert "`arn:aws:iam::*:root`" in issues[0].message

    async def test_identical_config_problems_are_reported_once(self, check):
        requirement = {"principals": ["*"], "required_conditions": [{"condition_key": 5}]}
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": [], "principal_condition_requirements": [requirement, dict(requirement)]},
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]

    async def test_any_of_findings_from_different_requirements_have_distinct_ids(self, check):
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={
                "blocked_principals": [],
                "principal_condition_requirements": [
                    {"principals": ["*"], "required_conditions": {"any_of": [{"condition_key": "aws:SourceArn"}]}},
                    {"principals": ["*"], "required_conditions": {"any_of": [{"condition_key": "aws:PrincipalOrgID"}]}},
                ],
            },
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert len(set(_finding_ids(issues))) == 2

    async def test_forbidden_leaves_differing_in_value_have_distinct_ids(self, check):
        required = {
            "none_of": [
                {"condition_key": "aws:SourceIp", "expected_value": "0.0.0.0/0"},
                {"condition_key": "aws:SourceIp", "expected_value": "::/0"},
            ]
        }
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::b/*"],
            Principal={"AWS": "*"},
            Condition={"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}, "StringEquals": {"aws:SourceIp": "::/0"}},
        )

        issues = await _run_both(check, statement, None, _requirement_config(["*"], required))

        assert len(issues) == 2
        assert len(set(_finding_ids(issues))) == 2

    async def test_nested_none_of_groups_have_distinct_ids(self, check):
        required = {
            "none_of": [
                {"all_of": [{"condition_key": "aws:SourceIp"}, {"condition_key": "aws:SourceVpc"}]},
                {"all_of": [{"condition_key": "aws:SourceArn"}, {"condition_key": "aws:SourceAccount"}]},
            ]
        }
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::b/*"],
            Principal="*",
            Condition={
                "StringEquals": {
                    "aws:SourceIp": "x",
                    "aws:SourceVpc": "x",
                    "aws:SourceArn": "x",
                    "aws:SourceAccount": "x",
                }
            },
        )

        issues = await _run_both(check, statement, None, _requirement_config(["*"], required))

        assert len(issues) == 2
        assert len(set(_finding_ids(issues))) == 2

    async def test_leaf_shared_by_nested_all_of_groups_is_reported_once(self, check):
        required = {
            "all_of": [
                {"all_of": [{"condition_key": "aws:SourceArn"}, {"condition_key": "aws:SourceAccount"}]},
                {"all_of": [{"condition_key": "aws:SourceArn"}, {"condition_key": "aws:PrincipalOrgID"}]},
            ]
        }

        issues = await _run_both(check, _principal_statement("*"), None, _requirement_config(["*"], required))

        assert sorted(i.condition_key for i in issues) == ["aws:PrincipalOrgID", "aws:SourceAccount", "aws:SourceArn"]

    async def test_shared_leaf_keeps_the_most_severe_finding(self, check):
        required = {
            "all_of": [
                {"all_of": [{"condition_key": "aws:SourceVpc", "severity": "low"}]},
                {"all_of": [{"condition_key": "aws:SourceVpc", "severity": "critical"}]},
            ]
        }

        issues = await _run_both(check, _principal_statement("*"), None, _requirement_config(["*"], required))

        assert [i.severity for i in issues] == ["critical"]


def _requirements_config(*requirements: dict, **extra) -> CheckConfig:
    return CheckConfig(
        check_id="principal_validation",
        enabled=True,
        config={"blocked_principals": [], "principal_condition_requirements": list(requirements), **extra},
    )


class TestPrincipalStableFindingKey:
    async def test_entries_with_the_same_invalid_severity_are_reported_separately(self, check):
        config = _requirement_config(
            ["*"],
            [
                {"condition_key": "aws:SourceArn", "severity": "urgent"},
                {"condition_key": "aws:SourceAccount", "severity": "urgent"},
            ],
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len({i.finding_key for i in invalid}) == 2

    async def test_requirement_finding_key_does_not_depend_on_message_wording(self, check, monkeypatch):
        config = _requirement_config(["*"], {"any_of": [{"condition_key": "aws:SourceArn"}]})
        before = [i.finding_key for i in await _run_both(check, _principal_statement("*"), None, config)]
        monkeypatch.setattr(
            "iam_validator.checks.principal_validation.format_list_with_backticks", lambda items: "reworded"
        )

        after = await _run_both(check, _principal_statement("*"), None, config)

        assert "reworded" in after[0].message
        assert [i.finding_key for i in after] == before

    async def test_requirement_finding_id_does_not_depend_on_matching_principals(self, check):
        config = _requirement_config(["arn:aws:iam::*:root"], [{"condition_key": "aws:SourceArn"}])
        one = _principal_statement("arn:aws:iam::111111111111:root")
        two = _principal_statement(["arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:root"])

        ids_one = _finding_ids(await _run_both(check, one, None, config))
        ids_two = _finding_ids(await _run_both(check, two, None, config))

        assert ids_one == ids_two

    async def test_config_problem_finding_key_does_not_depend_on_message_wording(self, check, monkeypatch):
        config = _requirement_config(["*"], [{"condition_key": 5}])
        before = [i.finding_key for i in await _run_both(check, _principal_statement("*"), None, config)]
        monkeypatch.setattr(
            "iam_validator.checks.principal_validation.format_list_with_backticks", lambda items: "reworded"
        )

        after = await _run_both(check, _principal_statement("*"), None, config)

        assert "reworded" in after[0].message
        assert [i.finding_key for i in after] == before

    async def test_requirements_rendering_the_same_message_are_both_reported(self, check):
        config = _requirements_config(
            {
                "principals": ["*"],
                "required_conditions": [{"condition_key": "aws:SourceAccount", "expected_value": "1"}],
            },
            {
                "principals": ["*"],
                "required_conditions": [{"condition_key": "aws:SourceAccount", "expected_value": "2"}],
            },
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert len(issues) == 2
        assert len(set(_finding_ids(issues))) == 2

    async def test_list_and_all_of_forms_of_one_entry_are_reported_once(self, check):
        entry = {"condition_key": "aws:SourceArn"}
        config = _requirements_config(
            {"principals": ["*"], "required_conditions": [entry]},
            {"principals": ["*"], "required_conditions": {"all_of": [dict(entry)]}},
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert [i.issue_type for i in issues] == ["missing_principal_condition"]

    async def test_config_problems_are_finalized_when_no_statement_reaches_condition_rules(self, check):
        config = _requirements_config(blocked_principals=["*", 5, 5])

        issues = await check.execute_policy(
            IAMPolicy(Version="2012-10-17", Statement=[_principal_statement("*")]), "policy.json", None, config
        )

        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"]
        assert issues[0].finding_key

    async def test_principal_findings_in_one_statement_have_distinct_ids(self, check):
        config = _requirements_config(blocked_principals=["111111111111", "222222222222"])
        statement = _principal_statement(["111111111111", "222222222222"])

        issues = await check.execute(statement, 0, None, config)

        assert [i.issue_type for i in issues] == ["blocked_principal", "blocked_principal"]
        assert len(set(_finding_ids(issues))) == 2


class TestPrincipalFindingCollapse:
    async def test_invalid_entries_differing_in_description_are_both_reported(self, check):
        config = _requirement_config(
            ["*"],
            [{"operator": "StringEquals", "description": "x"}, {"operator": "StringEquals", "description": "y"}],
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert [i.issue_type for i in issues] == ["invalid_condition_requirement"] * 2

    async def test_overlapping_requirements_with_the_same_missing_condition_are_reported_once(self, check):
        required = [{"condition_key": "aws:SourceArn"}]
        config = _requirements_config(
            {"principals": ["*"], "required_conditions": required, "severity": "medium"},
            {"principals": ["*", "arn:aws:iam::*:root"], "required_conditions": required, "severity": "critical"},
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert [(i.issue_type, i.severity) for i in issues] == [("missing_principal_condition", "critical")]

    async def test_requirements_differing_only_in_operator_are_both_reported(self, check):
        def requirement(operator: str) -> dict:
            entry = {"condition_key": "aws:SourceArn", "operator": operator, "example": "same"}
            return {"principals": ["*"], "required_conditions": [entry]}

        config = _requirements_config(requirement("ArnEquals"), requirement("ArnLike"))

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert len(issues) == 2
        assert len(set(_finding_ids(issues))) == 2

    async def test_list_and_all_of_forms_with_different_patterns_are_reported_once(self, check):
        entry = {"condition_key": "aws:SourceArn"}
        config = _requirements_config(
            {"principals": ["*"], "required_conditions": [entry]},
            {"principals": ["*", "arn:aws:iam::*:root"], "required_conditions": {"all_of": [dict(entry)]}},
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert [i.issue_type for i in issues] == ["missing_principal_condition"]

    async def test_principals_matched_by_different_requirements_share_one_finding(self, check):
        required = [{"condition_key": "aws:SourceArn"}]
        first, second = "arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:root"
        config = _requirements_config(
            {"principals": [first], "required_conditions": required},
            {"principals": [second], "required_conditions": required},
        )

        issues = await _run_both(check, _principal_statement([first, second]), None, config)

        assert len(issues) == 1
        assert first in issues[0].message and second in issues[0].message

    async def test_merged_finding_id_does_not_depend_on_severity_and_text_follows_it(self, check):
        def run(first_severity: str, second_severity: str):
            config = _requirements_config(
                {
                    "principals": ["*"],
                    "severity": first_severity,
                    "required_conditions": [{"condition_key": "aws:SourceArn", "description": "first"}],
                },
                {
                    "principals": ["*", "arn:aws:iam::*:root"],
                    "severity": second_severity,
                    "required_conditions": [{"condition_key": "aws:SourceArn", "description": "second"}],
                },
            )
            return _run_both(check, _principal_statement("*"), None, config)

        low_first = await run("low", "critical")
        high_first = await run("critical", "low")

        assert len(low_first) == len(high_first) == 1
        assert _finding_ids(low_first) == _finding_ids(high_first)
        assert [i.severity for i in low_first] == [i.severity for i in high_first] == ["critical"]
        assert (low_first[0].suggestion, high_first[0].suggestion) == ("second", "first")

    async def test_suppressed_requirement_does_not_add_its_principals(self, check):
        suppressed, enforced = "arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:root"
        config = _requirements_config(
            {
                "principals": [suppressed],
                "severity": "none",
                "required_conditions": [{"condition_key": "aws:SourceArn"}],
            },
            {
                "principals": [enforced],
                "severity": "high",
                "required_conditions": [{"condition_key": "aws:SourceArn"}],
            },
        )

        issues = await _run_both(check, _principal_statement([suppressed, enforced]), None, config)

        assert [i.severity for i in issues] == ["high"]
        assert enforced in issues[0].message and suppressed not in issues[0].message

    async def test_any_of_in_a_different_order_is_one_finding(self, check):
        arn, account = {"condition_key": "aws:SourceArn"}, {"condition_key": "aws:SourceAccount"}
        config = _requirements_config(
            {"principals": ["*"], "required_conditions": {"any_of": [arn, account]}},
            {"principals": ["*"], "required_conditions": {"any_of": [account, arn]}},
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert len(issues) == 1


ROOT = "arn:aws:iam::111111111111:root"


def _source_arn_requirement(principals: list[str], severity: str, description: str | None = None) -> dict:
    entry = {"condition_key": "aws:SourceArn"}
    if description is not None:
        entry["description"] = description
    return {"principals": principals, "severity": severity, "required_conditions": [entry]}


class TestPrincipalMergedFindingText:
    async def test_text_comes_from_the_most_severe_requirement(self, check):
        config = _requirements_config(
            _source_arn_requirement(["*"], "low", "optional hardening"),
            _source_arn_requirement(["*"], "critical", "STRONG"),
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert [(i.severity, i.suggestion) for i in issues] == [("critical", "STRONG")]

    async def test_equal_severity_text_comes_from_the_first_requirement(self, check):
        config = _requirements_config(
            _source_arn_requirement(["*"], "high", "first"),
            _source_arn_requirement(["*"], "high", "second"),
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert [(i.severity, i.suggestion) for i in issues] == [("high", "first")]


class TestPrincipalPublicWildcardId:
    def _config(self) -> CheckConfig:
        return _requirements_config(
            _source_arn_requirement(["arn:aws:iam::*:root"], "medium"),
            _source_arn_requirement(["*"], "critical"),
        )

    async def test_adding_the_public_wildcard_changes_the_id(self, check):
        without = await _run_both(check, _principal_statement([ROOT]), None, self._config())
        with_public = await _run_both(check, _principal_statement([ROOT, "*"]), None, self._config())

        assert len(without) == len(with_public) == 1
        assert _finding_ids(without) != _finding_ids(with_public)

    @pytest.mark.parametrize("principal", ["*", {"AWS": "*"}])
    async def test_public_wildcard_spellings_share_the_key(self, check, principal):
        public = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::b/*"], Principal=principal)
        mixed = _principal_statement(["*", ROOT])

        first = await _run_both(check, public, None, self._config())
        second = await _run_both(check, mixed, None, self._config())

        assert [i.finding_key for i in first] == [i.finding_key for i in second]


class TestPrincipalMalformedGroupNamed:
    async def test_groups_with_the_same_bad_value_are_reported_separately(self, check):
        config = _requirement_config(["*"], {"any_of": "aws:SourceArn", "none_of": "aws:SourceArn"})

        issues = await _run_both(check, _principal_statement("*"), None, config)

        invalid = [i for i in issues if i.issue_type == "invalid_condition_requirement"]
        assert len(set(_finding_ids(invalid))) == 2
        assert sorted("required_conditions.any_of" in i.message for i in invalid) == [False, True]
        assert sorted("required_conditions.none_of" in i.message for i in invalid) == [False, True]


class TestPrincipalAnyOfDuplicates:
    async def test_duplicate_any_of_entries_share_the_id(self, check):
        arn = {"condition_key": "aws:SourceArn"}
        config = _requirements_config(
            {"principals": ["*"], "required_conditions": {"any_of": [arn, dict(arn)]}},
            {"principals": ["*"], "required_conditions": {"any_of": [dict(arn)]}},
        )

        issues = await _run_both(check, _principal_statement("*"), None, config)

        assert len(issues) == 1

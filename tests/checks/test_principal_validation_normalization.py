"""Account-id/root-ARN equivalence and service-wildcard co-existence in principal_validation."""

import pytest

from iam_validator.checks.principal_validation import PrincipalValidationCheck, principal_spellings
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
def check():
    return PrincipalValidationCheck()


def _config(**overrides) -> CheckConfig:
    return CheckConfig(check_id="principal_validation", enabled=True, config=overrides)


def _statement(principal) -> Statement:
    return Statement(
        Effect="Allow",
        Principal=principal,
        Action=["s3:GetObject"],
        Resource=["arn:aws:s3:::bucket/*"],
    )


class TestPrincipalSpellings:
    def test_root_arn_also_spells_the_bare_account_id(self):
        assert principal_spellings("arn:aws:iam::123456789012:root") == [
            "arn:aws:iam::123456789012:root",
            "123456789012",
        ]

    def test_bare_account_id_also_spells_every_partition_root_arn(self):
        spellings = principal_spellings("123456789012")

        assert spellings[0] == "123456789012"
        assert "arn:aws:iam::123456789012:root" in spellings
        assert "arn:aws-cn:iam::123456789012:root" in spellings
        assert "arn:aws-us-gov:iam::123456789012:root" in spellings

    def test_other_principals_have_one_spelling(self):
        for principal in ("*", "lambda.amazonaws.com", "arn:aws:iam::123456789012:user/alice"):
            assert principal_spellings(principal) == [principal]


class TestBlockedPrincipalNormalization:
    @pytest.mark.parametrize(
        ("blocked", "principal"),
        [
            ("arn:aws:iam::123456789012:root", "123456789012"),
            ("123456789012", "arn:aws:iam::123456789012:root"),
            ("arn:aws:iam::123456789012:*", "123456789012"),
            ("arn:aws:iam::123456789012:root", "arn:aws:iam::123456789012:root"),
        ],
    )
    async def test_equivalent_spellings_are_blocked(self, check, mock_fetcher, blocked, principal):
        issues = await check.execute(
            _statement({"AWS": principal}), 0, mock_fetcher, _config(blocked_principals=[blocked])
        )

        assert [i.issue_type for i in issues] == ["blocked_principal"]

    async def test_a_different_account_is_not_blocked(self, check, mock_fetcher):
        issues = await check.execute(
            _statement({"AWS": "999988887777"}),
            0,
            mock_fetcher,
            _config(blocked_principals=["arn:aws:iam::123456789012:root"]),
        )

        assert issues == []

    async def test_wildcard_block_still_matches_only_literal_wildcard(self, check, mock_fetcher):
        issues = await check.execute(
            _statement({"AWS": "123456789012"}), 0, mock_fetcher, _config(blocked_principals=["*"])
        )

        assert issues == []


class TestAllowedPrincipalNormalization:
    @pytest.mark.parametrize(
        ("allowed", "principal"),
        [
            ("arn:aws:iam::123456789012:root", "123456789012"),
            ("123456789012", "arn:aws:iam::123456789012:root"),
        ],
    )
    async def test_equivalent_spellings_are_allowed(self, check, mock_fetcher, allowed, principal):
        issues = await check.execute(
            _statement({"AWS": principal}), 0, mock_fetcher, _config(allowed_principals=[allowed])
        )

        assert issues == []

    async def test_unlisted_account_is_still_flagged(self, check, mock_fetcher):
        issues = await check.execute(
            _statement({"AWS": "999988887777"}),
            0,
            mock_fetcher,
            _config(allowed_principals=["arn:aws:iam::123456789012:root"]),
        )

        assert [i.issue_type for i in issues] == ["unauthorized_principal"]


class TestServiceWildcardDoesNotMaskOtherPrincipals:
    async def test_blocked_principal_is_reported_alongside_service_wildcard(self, check, mock_fetcher):
        statement = _statement({"Service": "*", "AWS": "123456789012"})

        issues = await check.execute(
            statement, 0, mock_fetcher, _config(blocked_principals=["arn:aws:iam::123456789012:root"])
        )

        issue_types = {i.issue_type for i in issues}
        assert "blocked_principal" in issue_types
        assert "service_principal_wildcard" in issue_types

    async def test_unauthorized_principal_is_reported_alongside_service_wildcard(self, check, mock_fetcher):
        statement = _statement({"Service": "*", "AWS": "999988887777"})

        issues = await check.execute(
            statement,
            0,
            mock_fetcher,
            _config(allowed_principals=["arn:aws:iam::123456789012:root"]),
        )

        issue_types = {i.issue_type for i in issues}
        assert "unauthorized_principal" in issue_types
        assert "service_principal_wildcard" in issue_types

    @pytest.mark.parametrize("service", ["*", ["*"], ["*", "lambda.amazonaws.com"]])
    async def test_aws_wildcard_is_blocked_alongside_service_wildcard(self, check, mock_fetcher, service):
        issues = await check.execute(
            _statement({"AWS": "*", "Service": service}),
            0,
            mock_fetcher,
            _config(block_wildcard_principal=True),
        )

        issue_types = [i.issue_type for i in issues]
        assert "blocked_principal" in issue_types
        assert "service_principal_wildcard" in issue_types

    async def test_aws_wildcard_is_unauthorized_alongside_service_wildcard(self, check, mock_fetcher):
        issues = await check.execute(
            _statement({"AWS": ["*"], "Service": "*"}),
            0,
            mock_fetcher,
            _config(allowed_principals=["arn:aws:iam::123456789012:root"]),
        )

        assert "unauthorized_principal" in [i.issue_type for i in issues]

    async def test_service_wildcard_alone_is_not_reported_as_blocked(self, check, mock_fetcher):
        issues = await check.execute(
            _statement({"Service": "*"}), 0, mock_fetcher, _config(block_wildcard_principal=True)
        )

        assert "blocked_principal" not in [i.issue_type for i in issues]

    async def test_condition_requirements_stay_suppressed_under_service_wildcard(self, check, mock_fetcher):
        statement = _statement({"Service": "*"})

        issues = await check.execute(
            statement,
            0,
            mock_fetcher,
            _config(
                principal_condition_requirements=[
                    {"principals": ["*"], "required_conditions": {"all_of": [{"condition_key": "aws:SourceArn"}]}}
                ]
            ),
        )

        assert [i.issue_type for i in issues] == ["service_principal_wildcard"]

"""A Deny whose NotPrincipal carve-out is "*" exempts everyone and denies nothing."""

from unittest.mock import AsyncMock

import pytest

from iam_validator.checks.principal_validation import PrincipalValidationCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
def check():
    return PrincipalValidationCheck()


@pytest.fixture
def config():
    return CheckConfig(check_id="principal_validation", enabled=True)


async def _run(check, config, **statement_kwargs):
    statement = Statement(Action=["s3:*"], Resource=["*"], **statement_kwargs)
    return await check.execute(statement, 0, AsyncMock(), config)


class TestWildcardNotPrincipalIsFlagged:
    @pytest.mark.parametrize(
        "not_principal",
        [
            "*",
            {"AWS": "*"},
            {"AWS": ["*"]},
            {"AWS": ["*", "arn:aws:iam::111122223333:root"]},
            {"AWS": "arn:aws:iam::111122223333:root", "Service": "*"},
            " * ",
        ],
    )
    async def test_a_wildcard_carve_out_denies_nothing(self, check, config, not_principal):
        issues = await _run(check, config, Effect="Deny", NotPrincipal=not_principal)

        assert [i.issue_type for i in issues] == ["ineffective_deny_carve_out"]
        assert issues[0].field_name == "principal"

    async def test_the_message_names_the_consequence(self, check, config):
        issues = await _run(check, config, Effect="Deny", NotPrincipal="*")

        assert "denies nothing" in issues[0].message

    async def test_the_severity_follows_the_check(self, check, config):
        issues = await _run(check, config, Effect="Deny", NotPrincipal="*")

        assert issues[0].severity == "high"

    async def test_a_severity_override_is_honoured(self, check):
        config = CheckConfig(check_id="principal_validation", enabled=True, severity="critical")

        issues = await _run(check, config, Effect="Deny", NotPrincipal="*")

        assert issues[0].severity == "critical"

    async def test_lowercase_deny_is_still_a_deny(self, check, config):
        issues = await _run(check, config, Effect="deny", NotPrincipal="*")

        assert [i.issue_type for i in issues] == ["ineffective_deny_carve_out"]


class TestNarrowerOrNonDenyCarveOutsAreLeftAlone:
    @pytest.mark.parametrize(
        "not_principal",
        [
            {"AWS": "arn:aws:iam::111122223333:root"},
            {"AWS": ["arn:aws:iam::111122223333:root", "arn:aws:iam::444455556666:root"]},
            {"Service": "lambda.amazonaws.com"},
            "arn:aws:iam::111122223333:role/Admin",
        ],
    )
    async def test_a_specific_carve_out_is_clean(self, check, config, not_principal):
        assert await _run(check, config, Effect="Deny", NotPrincipal=not_principal) == []

    async def test_allow_with_notprincipal_is_left_to_not_principal_validation(self, check, config):
        issues = await _run(check, config, Effect="Allow", NotPrincipal="*")

        assert [i.issue_type for i in issues] == []

    async def test_a_plain_deny_principal_wildcard_is_not_a_carve_out(self, check, config):
        assert await _run(check, config, Effect="Deny", Principal="*") == []


class TestTheExistingNotPrincipalRulesStillApply:
    async def test_a_blocked_principal_is_still_reported_alongside(self, check):
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": ["arn:aws:iam::111122223333:root"]},
        )

        issues = await _run(
            check,
            config,
            Effect="Deny",
            NotPrincipal={"AWS": ["*", "arn:aws:iam::111122223333:root"]},
        )

        assert sorted(i.issue_type for i in issues) == [
            "blocked_principal",
            "ineffective_deny_carve_out",
        ]

    async def test_a_narrow_carve_out_still_reaches_the_blocked_list(self, check):
        config = CheckConfig(
            check_id="principal_validation",
            enabled=True,
            config={"blocked_principals": ["arn:aws:iam::111122223333:root"]},
        )

        issues = await _run(check, config, Effect="Deny", NotPrincipal={"AWS": "arn:aws:iam::111122223333:root"})

        assert [i.issue_type for i in issues] == ["blocked_principal"]


class TestPrincipalExtractionCoversBothFields:
    def test_extract_principals_keeps_principal_then_not_principal(self, check):
        statement = Statement(
            Effect="Deny",
            Principal={"AWS": "arn:aws:iam::111122223333:root"},
            NotPrincipal={"AWS": ["arn:aws:iam::444455556666:root", "*"]},
            Action=["s3:*"],
            Resource=["*"],
        )

        assert check._extract_principals(statement) == [
            "arn:aws:iam::111122223333:root",
            "arn:aws:iam::444455556666:root",
            "*",
        ]

    def test_extract_not_principals_ignores_principal(self, check):
        statement = Statement(
            Effect="Deny",
            Principal={"AWS": "arn:aws:iam::111122223333:root"},
            NotPrincipal="*",
            Action=["s3:*"],
            Resource=["*"],
        )

        assert check._extract_not_principals(statement) == ["*"]

    def test_a_statement_without_notprincipal_extracts_nothing(self, check):
        statement = Statement(Effect="Allow", Principal="*", Action=["s3:*"], Resource=["*"])

        assert check._extract_not_principals(statement) == []

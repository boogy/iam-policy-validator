"""The alphanumeric Sid charset is an IAM rule, so resource-based policies are exempt."""

import pytest

from iam_validator.checks.sid_uniqueness import SidUniquenessCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement

# AWS's own console-generated SQS / SNS resource policies.
AWS_GENERATED_SIDS = ["__owner_statement", "__default_statement_ID"]

STRICT_POLICY_TYPES = [
    "IDENTITY_POLICY",
    "TRUST_POLICY",
    "SERVICE_CONTROL_POLICY",
    "RESOURCE_CONTROL_POLICY",
]


@pytest.fixture
def check():
    return SidUniquenessCheck()


@pytest.fixture
def config():
    return CheckConfig(check_id="sid_uniqueness", enabled=True)


def _policy(*sids: str) -> IAMPolicy:
    return IAMPolicy(
        version="2012-10-17",
        statement=[Statement(Sid=sid, Effect="Allow", Action=["s3:GetObject"], Resource=["*"]) for sid in sids],
    )


async def _run(check, config, mock_fetcher, policy, policy_type=None):
    kwargs = {"policy_type": policy_type} if policy_type else {}
    return await check.execute_policy(policy, "test.json", mock_fetcher, config, **kwargs)


class TestResourcePolicyCharsetIsNotEnforced:
    @pytest.mark.parametrize("sid", [*AWS_GENERATED_SIDS, "Allow public read", "grant-log-delivery"])
    async def test_non_alphanumeric_sid_is_accepted(self, check, config, mock_fetcher, sid):
        issues = await _run(check, config, mock_fetcher, _policy(sid), "RESOURCE_POLICY")

        assert issues == []

    async def test_duplicates_are_still_reported(self, check, config, mock_fetcher):
        issues = await _run(
            check, config, mock_fetcher, _policy("__owner_statement", "__owner_statement"), "RESOURCE_POLICY"
        )

        assert [i.issue_type for i in issues] == ["duplicate_sid"]


class TestOtherPolicyTypesKeepStrictValidation:
    @pytest.mark.parametrize("policy_type", STRICT_POLICY_TYPES)
    @pytest.mark.parametrize("sid", [*AWS_GENERATED_SIDS, "Allow public read"])
    async def test_non_alphanumeric_sid_is_still_an_error(self, check, config, mock_fetcher, policy_type, sid):
        issues = await _run(check, config, mock_fetcher, _policy(sid), policy_type)

        assert [i.issue_type for i in issues] == ["invalid_sid_format"]
        assert issues[0].severity == "error"

    async def test_an_unresolved_policy_type_stays_strict(self, check, config, mock_fetcher):
        issues = await _run(check, config, mock_fetcher, _policy("__owner_statement"))

        assert [i.issue_type for i in issues] == ["invalid_sid_format"]

    async def test_an_alphanumeric_sid_is_clean_everywhere(self, check, config, mock_fetcher):
        for policy_type in [*STRICT_POLICY_TYPES, "RESOURCE_POLICY"]:
            issues = await _run(check, config, mock_fetcher, _policy("AllowRead"), policy_type)

            assert issues == [], policy_type

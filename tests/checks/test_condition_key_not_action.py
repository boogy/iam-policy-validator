"""A NotAction statement has no action to resolve per-action keys against, but global keys are still decidable."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.checks.condition_key_validation import ConditionKeyValidationCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
def check():
    return ConditionKeyValidationCheck()


@pytest.fixture
def config():
    return CheckConfig(check_id="condition_key_validation", enabled=True)


def _not_action_statement(condition):
    return Statement(Effect="Allow", NotAction=["s3:*"], Resource=["*"], Condition=condition)


async def _run(check, config, mock_fetcher, condition):
    return await check.execute(_not_action_statement(condition), 0, mock_fetcher, config)


class TestBogusGlobalKeysAreReported:
    @pytest.mark.parametrize("key", ["aws:TotallyBogusKey", "aws:PrincipalOrgId2", "aws:MFA"])
    async def test_an_unrecognized_aws_key_is_flagged(self, check, config, mock_fetcher, key):
        issues = await _run(check, config, mock_fetcher, {"StringEquals": {key: "x"}})

        assert [(i.issue_type, i.severity) for i in issues] == [("invalid_condition_key", "warning")]
        assert key in issues[0].message

    async def test_the_message_explains_why_only_global_keys_are_checked(self, check, config, mock_fetcher):
        issues = await _run(check, config, mock_fetcher, {"StringEquals": {"aws:Nope": "x"}})

        assert "NotAction" in issues[0].message

    async def test_the_finding_never_fails_the_run_by_default(self, check, config, mock_fetcher):
        issues = await _run(check, config, mock_fetcher, {"StringEquals": {"aws:Nope": "x"}})

        assert issues[0].severity != "error"


class TestValidKeysAreAccepted:
    @pytest.mark.parametrize(
        "key",
        [
            "aws:PrincipalOrgID",
            "aws:principalorgid",
            "aws:SecureTransport",
            "aws:PrincipalTag/team",
            "aws:RequestTag/team",
            "aws:ResourceTag/team",
            "aws:CalledVia",
        ],
    )
    async def test_a_real_global_or_tag_key_is_clean(self, check, config, mock_fetcher, key):
        assert await _run(check, config, mock_fetcher, {"StringEquals": {key: "x"}}) == []

    @pytest.mark.parametrize("key", ["s3:prefix", "ec2:Region", "nosuchservice:whatever"])
    async def test_a_service_prefixed_key_is_not_judged(self, check, config, mock_fetcher, key):
        assert await _run(check, config, mock_fetcher, {"StringEquals": {key: "x"}}) == []

    async def test_a_statement_without_conditions_is_clean(self, check, config, mock_fetcher):
        statement = Statement(Effect="Allow", NotAction=["s3:*"], Resource=["*"])

        assert await check.execute(statement, 0, mock_fetcher, config) == []


class TestActionStatementsKeepTheAwsDataPath:
    async def test_a_named_action_still_consults_the_fetcher(self, check, config, mock_fetcher):
        mock_fetcher.validate_actions_batch = AsyncMock(return_value={"s3:GetObject": (True, None, False)})
        mock_fetcher.validate_condition_key = AsyncMock(return_value=MagicMock(is_valid=True, warning_message=None))
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:TotallyBogusKey": "x"}},
        )

        await check.execute(statement, 0, mock_fetcher, config)

        mock_fetcher.validate_condition_key.assert_awaited_once_with("s3:GetObject", "aws:TotallyBogusKey", ["*"])

    async def test_a_notaction_statement_never_consults_the_fetcher(self, check, config, mock_fetcher):
        mock_fetcher.validate_actions_batch = AsyncMock(return_value={})
        mock_fetcher.validate_condition_key = AsyncMock()

        await _run(check, config, mock_fetcher, {"StringEquals": {"aws:Nope": "x"}})

        assert not mock_fetcher.validate_actions_batch.called
        assert not mock_fetcher.validate_condition_key.called

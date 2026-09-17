"""Only BoolIfExists false on aws:PrincipalIsAWSService is a complete service carve-out."""

import pytest

from iam_validator.checks.rcp_best_practices import RCPBestPracticesCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement

CARVEOUT_KEY = "aws:PrincipalIsAWSService"
ORG_BOUNDARY = {"aws:PrincipalOrgID": "o-example12345"}


@pytest.fixture
def check():
    return RCPBestPracticesCheck()


@pytest.fixture
def config():
    return CheckConfig(check_id="rcp_best_practices", enabled=True)


async def _run(check, config, mock_fetcher, carveout: dict) -> list:
    statement = Statement(
        Effect="Deny",
        Principal="*",
        Action=["s3:*"],
        Resource=["*"],
        Condition={"StringNotEqualsIfExists": ORG_BOUNDARY, **carveout},
    )
    policy = IAMPolicy(version="2012-10-17", statement=[statement])
    return await check.execute_policy(policy, "test.json", mock_fetcher, config, policy_type="RESOURCE_CONTROL_POLICY")


class TestIneffectiveCarveoutIsStillFlagged:
    @pytest.mark.parametrize(
        "carveout",
        [
            {"StringEquals": {CARVEOUT_KEY: "true"}},
            {"StringEquals": {CARVEOUT_KEY: "false"}},
            {"StringNotEquals": {CARVEOUT_KEY: "false"}},
            {"Null": {CARVEOUT_KEY: "true"}},
            {"Null": {CARVEOUT_KEY: "false"}},
            {"Bool": {CARVEOUT_KEY: "true"}},
            {"BoolIfExists": {CARVEOUT_KEY: "true"}},
            {"BoolIfExists": {CARVEOUT_KEY: True}},
            {"ForAnyValue:Bool": {CARVEOUT_KEY: "true"}},
        ],
    )
    async def test_wrong_operator_or_value_does_not_suppress_the_finding(self, check, config, mock_fetcher, carveout):
        issues = await _run(check, config, mock_fetcher, carveout)

        assert [i.issue_type for i in issues] == ["rcp_missing_service_carveout"]

    async def test_message_says_the_key_is_present_but_ineffective(self, check, config, mock_fetcher):
        issues = await _run(check, config, mock_fetcher, {"Bool": {CARVEOUT_KEY: "true"}})

        assert "not as a carve-out" in issues[0].message

    async def test_message_says_the_key_is_absent_when_it_is(self, check, config, mock_fetcher):
        issues = await _run(check, config, mock_fetcher, {})

        assert "no `aws:PrincipalIsAWSService` carve-out" in issues[0].message

    async def test_the_key_under_another_operator_does_not_vouch_for_a_bad_bool(self, check, config, mock_fetcher):
        issues = await _run(
            check,
            config,
            mock_fetcher,
            {"Bool": {CARVEOUT_KEY: "true"}, "StringEquals": {CARVEOUT_KEY: "false"}},
        )

        assert [i.issue_type for i in issues] == ["rcp_missing_service_carveout"]


class TestEffectiveCarveoutIsAccepted:
    @pytest.mark.parametrize(
        "carveout",
        [
            {"BoolIfExists": {CARVEOUT_KEY: "false"}},
            {"boolifexists": {CARVEOUT_KEY: "FALSE"}},
            {"BoolIfExists": {"aws:principalisawsservice": "false"}},
            {"BoolIfExists": {CARVEOUT_KEY: False}},
            {"ForAnyValue:BoolIfExists": {CARVEOUT_KEY: "false"}},
            {"BoolIfExists": {CARVEOUT_KEY: ["false"]}},
        ],
    )
    async def test_recognized_spellings_suppress_the_finding(self, check, config, mock_fetcher, carveout):
        issues = await _run(check, config, mock_fetcher, carveout)

        assert issues == []

    async def test_a_second_bad_block_does_not_undo_a_good_one(self, check, config, mock_fetcher):
        issues = await _run(
            check,
            config,
            mock_fetcher,
            {"BoolIfExists": {CARVEOUT_KEY: "false"}, "Null": {CARVEOUT_KEY: "true"}},
        )

        assert issues == []


class TestBoolWithoutIfExistsLeavesAnonymousRequestsOut:
    @pytest.mark.parametrize(
        "carveout",
        [
            {"Bool": {CARVEOUT_KEY: "false"}},
            {"bool": {CARVEOUT_KEY: "FALSE"}},
            {"Bool": {CARVEOUT_KEY: False}},
            {"Bool": {"aws:principalisawsservice": "false"}},
            {"ForAnyValue:Bool": {CARVEOUT_KEY: "false"}},
        ],
    )
    async def test_bare_bool_gets_its_own_finding(self, check, config, mock_fetcher, carveout):
        issues = await _run(check, config, mock_fetcher, carveout)

        assert [i.issue_type for i in issues] == ["rcp_carveout_missing_ifexists"]

    async def test_the_message_names_anonymous_requests_not_service_principals(self, check, config, mock_fetcher):
        issues = await _run(check, config, mock_fetcher, {"Bool": {CARVEOUT_KEY: "false"}})

        assert "anonymous requests" in issues[0].message.lower()
        assert "BoolIfExists" in issues[0].suggestion

    async def test_an_ifexists_sibling_does_not_rescue_a_bare_bool(self, check, config, mock_fetcher):
        issues = await _run(
            check,
            config,
            mock_fetcher,
            {"BoolIfExists": {CARVEOUT_KEY: "false"}, "Bool": {CARVEOUT_KEY: "false"}},
        )

        assert [i.issue_type for i in issues] == ["rcp_carveout_missing_ifexists"]

    async def test_no_finding_without_an_org_boundary(self, check, config, mock_fetcher):
        statement = Statement(
            Effect="Deny",
            Principal="*",
            Action=["s3:*"],
            Resource=["*"],
            Condition={"Bool": {CARVEOUT_KEY: "false"}},
        )
        policy = IAMPolicy(version="2012-10-17", statement=[statement])

        issues = await check.execute_policy(
            policy, "test.json", mock_fetcher, config, policy_type="RESOURCE_CONTROL_POLICY"
        )

        assert issues == []

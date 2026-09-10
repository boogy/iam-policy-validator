"""Condition keys for federated identity providers AWS cannot enumerate."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.checks.condition_key_validation import ConditionKeyValidationCheck
from iam_validator.core.aws_service.validators import (
    ServiceValidator,
    find_matching_condition_key,
)
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import ActionDetail, IAMPolicy, ServiceDetail

GITHUB_ACTIONS_TRUST_POLICY = (
    Path(__file__).resolve().parents[2] / "examples/trust-policies/github-actions-oidc-trust-policy.json"
)

GITHUB_ACTIONS_KEYS = [
    "token.actions.githubusercontent.com:actor",
    "token.actions.githubusercontent.com:repository",
    "token.actions.${Domain}.ghe.com:actor",
    "token.actions.githubusercontent.com/${SubPath}:actor",
    "oidc.circleci.com/org/${OrgId}:oidc.circleci.com/project-id",
]


@pytest.fixture
def sts_service() -> ServiceDetail:
    return ServiceDetail(
        Name="sts",
        prefix="sts",
        Actions=[
            ActionDetail(Name="AssumeRoleWithWebIdentity", ActionConditionKeys=list(GITHUB_ACTIONS_KEYS)),
            ActionDetail(Name="AssumeRole", ActionConditionKeys=["sts:RoleSessionName"]),
        ],
    )


class TestPlaceholderPatterns:
    @pytest.mark.parametrize(
        ("condition_key", "expected"),
        [
            ("token.actions.mycorp.ghe.com:actor", "token.actions.${Domain}.ghe.com:actor"),
            ("token.actions.githubusercontent.com/myorg:actor", "token.actions.githubusercontent.com/${SubPath}:actor"),
            (
                "oidc.circleci.com/org/abc-123:oidc.circleci.com/project-id",
                "oidc.circleci.com/org/${OrgId}:oidc.circleci.com/project-id",
            ),
        ],
    )
    def test_provider_placeholder_matches(self, condition_key, expected):
        assert find_matching_condition_key(condition_key, GITHUB_ACTIONS_KEYS) == expected

    def test_placeholder_does_not_span_the_claim_separator(self):
        assert find_matching_condition_key("token.actions.mycorp.ghe.com:bogus", GITHUB_ACTIONS_KEYS) is None

    def test_tag_key_placeholder_keeps_tag_validation(self):
        keys = ["aws:ResourceTag/${TagKey}"]
        assert find_matching_condition_key("aws:ResourceTag/Environment", keys) == "aws:ResourceTag/${TagKey}"
        assert find_matching_condition_key("aws:ResourceTag/" + "x" * 200, keys) is None


class TestWebIdentityClaims:
    @pytest.mark.parametrize("claim", ["aud", "sub", "oaud", "amr"])
    async def test_standard_oidc_claims_accepted_for_any_provider(self, sts_service, claim):
        result = await ServiceValidator().validate_condition_key(
            "sts:AssumeRoleWithWebIdentity", f"token.actions.githubusercontent.com:{claim}", sts_service
        )
        assert result.is_valid

    async def test_provider_url_with_path_accepted(self, sts_service):
        result = await ServiceValidator().validate_condition_key(
            "sts:AssumeRoleWithWebIdentity", "oidc.eks.eu-west-1.amazonaws.com/id/ABC123:sub", sts_service
        )
        assert result.is_valid

    async def test_claim_is_matched_case_insensitively(self, sts_service):
        result = await ServiceValidator().validate_condition_key(
            "sts:AssumeRoleWithWebIdentity", "TOKEN.ACTIONS.GITHUBUSERCONTENT.COM:AUD", sts_service
        )
        assert result.is_valid

    async def test_unknown_claim_still_rejected(self, sts_service):
        result = await ServiceValidator().validate_condition_key(
            "sts:AssumeRoleWithWebIdentity", "token.actions.githubusercontent.com:bogus", sts_service
        )
        assert not result.is_valid

    async def test_prefix_without_a_domain_still_rejected(self, sts_service):
        result = await ServiceValidator().validate_condition_key(
            "sts:AssumeRoleWithWebIdentity", "notaprovider:sub", sts_service
        )
        assert not result.is_valid

    async def test_claim_rejected_for_non_federating_action(self, sts_service):
        result = await ServiceValidator().validate_condition_key(
            "sts:AssumeRole", "token.actions.githubusercontent.com:sub", sts_service
        )
        assert not result.is_valid


async def test_shipped_github_actions_trust_policy_has_no_condition_key_findings(sts_service):
    validator = ServiceValidator()
    fetcher = MagicMock()
    fetcher.validate_actions_batch = AsyncMock(return_value={"sts:AssumeRoleWithWebIdentity": (True, None, False)})

    async def validate(action, key, resources=None):
        return await validator.validate_condition_key(action, key, sts_service)

    fetcher.validate_condition_key = AsyncMock(side_effect=validate)

    policy = IAMPolicy.model_validate(json.loads(GITHUB_ACTIONS_TRUST_POLICY.read_text(encoding="utf-8")))
    check = ConditionKeyValidationCheck()
    config = CheckConfig(check_id=check.check_id, enabled=True, severity=check.default_severity)

    issues = await check.execute(policy.statement[0], 0, fetcher, config)
    assert issues == []

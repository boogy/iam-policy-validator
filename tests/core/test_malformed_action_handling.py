"""Tests for malformed action handling in the AWS service fetcher.

An action whose service prefix cannot be parsed (most commonly a wildcard
vendor such as ``*:Untag*``, which AWS rejects with
``MalformedPolicyDocument: Action vendors ... must not contain wildcards``)
must surface as a validation finding. It previously raised ``ValueError`` out
of the fetcher, which the check registry downgraded to a log warning -- so
``action_validation`` and ``condition_key_validation`` were silently skipped
for the whole statement and the policy passed.
"""

import pytest

from iam_validator.checks.action_validation import ActionValidationCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.aws_service.parsers import ServiceParser
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement

MALFORMED_ACTIONS = ["*:Untag*", "*:UntagResource", "*:*", "s3GetObject", "s3:Get Object"]


class TestActionFormatErrorMessage:
    """The message has to name the wildcard-vendor case explicitly."""

    @pytest.fixture
    def parser(self):
        return ServiceParser()

    @pytest.mark.parametrize("action", ["*:Untag*", "*:UntagResource", "ec?:DescribeTags"])
    def test_wildcard_vendor_is_called_out(self, parser, action):
        message = parser.describe_action_format_error(action)

        assert "service prefix cannot contain a wildcard" in message
        assert "must not contain wildcards" in message
        assert action in message

    def test_wildcard_vendor_message_suggests_per_service_actions(self, parser):
        message = parser.describe_action_format_error("*:Untag*")

        assert "`iam:Untag*`" in message
        assert "inside the action name is allowed" in message

    def test_missing_separator_gets_its_own_message(self, parser):
        message = parser.describe_action_format_error("s3GetObject")

        assert "Expected `<service>:<action>`" in message
        assert "wildcard" not in message

    def test_unparseable_action_name_falls_back(self, parser):
        message = parser.describe_action_format_error("s3:Get Object")

        assert "Expected `<service>:<action>`" in message

    @pytest.mark.parametrize("action", MALFORMED_ACTIONS)
    def test_parse_action_raises_with_the_explanation(self, parser, action):
        with pytest.raises(ValueError, match="Invalid action format"):
            parser.parse_action(action)

    @pytest.mark.parametrize("action", ["iam:Untag*", "kms:*Alias", "iam:D*RolePolicy", "s3:GetObject"])
    def test_wildcards_inside_the_action_name_still_parse(self, parser, action):
        service, action_name = parser.parse_action(action)

        assert service == action.split(":")[0]
        assert action_name == action.split(":")[1]


class TestFetcherReturnsInsteadOfRaising:
    """validate_action's documented contract is a tuple, for every input."""

    @pytest.fixture
    def fetcher(self):
        return AWSServiceFetcher()

    @pytest.mark.parametrize("action", MALFORMED_ACTIONS)
    async def test_validate_action_reports_malformed_action(self, fetcher, action):
        is_valid, error, is_wildcard = await fetcher.validate_action(action)

        assert is_valid is False
        assert error is not None
        assert "Invalid action format" in error
        assert is_wildcard is False

    async def test_validate_actions_batch_reports_malformed_action(self, fetcher):
        results = await fetcher.validate_actions_batch(["*:Untag*", "s3:GetObject"])

        assert set(results) == {"*:Untag*", "s3:GetObject"}
        assert results["*:Untag*"][0] is False
        assert "Invalid action format" in results["*:Untag*"][1]
        assert results["s3:GetObject"][0] is True

    async def test_validate_actions_batch_still_groups_by_service(self, fetcher):
        results = await fetcher.validate_actions_batch(["s3:GetObject", "s3:PutObject", "iam:CreateRole", "*:Untag*"])

        assert results["s3:GetObject"][0] is True
        assert results["s3:PutObject"][0] is True
        assert results["iam:CreateRole"][0] is True
        assert results["*:Untag*"][0] is False

    async def test_condition_key_validation_is_skipped_not_crashed(self, fetcher):
        result = await fetcher.validate_condition_key("*:Untag*", "aws:ResourceTag/env")

        assert result.is_valid is True


class TestCheckReportsMalformedAction:
    """End result: the finding reaches the report."""

    async def test_action_validation_flags_wildcard_vendor(self):
        statement = Statement(Effect="Deny", Action=["*:Untag*"], Resource=["*"])

        async with AWSServiceFetcher() as fetcher:
            issues = await ActionValidationCheck().execute(
                statement, 0, fetcher, CheckConfig(check_id="action_validation")
            )

        assert len(issues) == 1
        assert issues[0].issue_type == "invalid_action"
        assert issues[0].severity == "error"
        assert "service prefix cannot contain a wildcard" in issues[0].message

    async def test_a_malformed_action_does_not_hide_its_neighbours(self):
        statement = Statement(Effect="Allow", Action=["*:Untag*", "s3:NoSuchAction", "s3:GetObject"], Resource=["*"])

        async with AWSServiceFetcher() as fetcher:
            issues = await ActionValidationCheck().execute(
                statement, 0, fetcher, CheckConfig(check_id="action_validation")
            )

        assert {issue.action for issue in issues} == {"*:Untag*", "s3:NoSuchAction"}

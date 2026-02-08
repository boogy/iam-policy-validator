"""Tests for SDK check development helpers."""

from unittest.mock import AsyncMock

import pytest

from iam_validator.core.models import ValidationIssue
from iam_validator.sdk.helpers import CheckHelper, expand_actions

# ---------------------------------------------------------------------------
# CheckHelper
# ---------------------------------------------------------------------------


class TestCheckHelper:
    """Tests for the CheckHelper class."""

    @pytest.fixture
    def helper(self, mock_fetcher):
        return CheckHelper(mock_fetcher)

    def test_arn_matches(self, helper):
        assert helper.arn_matches("arn:*:s3:::*/*", "arn:aws:s3:::bucket/key") is True

    def test_arn_matches_no_match(self, helper):
        assert (
            helper.arn_matches("arn:*:s3:::*/*", "arn:aws:ec2:us-east-1:123:instance/i-1") is False
        )

    def test_arn_matches_with_resource_type(self, helper):
        assert (
            helper.arn_matches("arn:*:s3:::*", "arn:aws:s3:::bucket/key", resource_type="bucket")
            is False
        )

    def test_arn_strictly_valid(self, helper):
        assert (
            helper.arn_strictly_valid("arn:*:iam::*:user/*", "arn:aws:iam::123456789012:user/alice")
            is True
        )

    def test_arn_strictly_valid_fails(self, helper):
        assert (
            helper.arn_strictly_valid("arn:*:iam::*:user/*", "arn:aws:iam::123456789012:u*")
            is False
        )

    def test_create_issue_basic(self, helper):
        issue = helper.create_issue(
            severity="high",
            statement_idx=0,
            message="Test issue",
        )
        assert isinstance(issue, ValidationIssue)
        assert issue.severity == "high"
        assert issue.statement_index == 0
        assert issue.message == "Test issue"
        assert issue.issue_type == "custom"

    def test_create_issue_all_fields(self, helper):
        issue = helper.create_issue(
            severity="critical",
            statement_idx=2,
            message="Sensitive access detected",
            statement_sid="MyStatement",
            issue_type="sensitive_action",
            action="iam:CreateUser",
            resource="arn:aws:iam::123:user/*",
            condition_key="aws:SourceIp",
            suggestion="Restrict with conditions",
            line_number=42,
        )
        assert issue.severity == "critical"
        assert issue.statement_index == 2
        assert issue.statement_sid == "MyStatement"
        assert issue.issue_type == "sensitive_action"
        assert issue.action == "iam:CreateUser"
        assert issue.resource == "arn:aws:iam::123:user/*"
        assert issue.condition_key == "aws:SourceIp"
        assert issue.suggestion == "Restrict with conditions"
        assert issue.line_number == 42

    async def test_expand_actions(self, helper, mock_fetcher):
        mock_fetcher.expand_wildcard_action = AsyncMock(
            return_value=["s3:GetObject", "s3:GetObjectAcl"]
        )
        # expand_actions on helper calls expand_wildcard_actions internally
        # which uses fetcher.expand_wildcard_action
        # We need to mock the underlying function
        from unittest.mock import patch

        with patch(
            "iam_validator.sdk.helpers.expand_wildcard_actions",
            new_callable=AsyncMock,
            return_value=["s3:GetObject", "s3:GetObjectAcl"],
        ):
            result = await helper.expand_actions(["s3:Get*"])
            assert "s3:GetObject" in result
            assert "s3:GetObjectAcl" in result


# ---------------------------------------------------------------------------
# expand_actions (standalone)
# ---------------------------------------------------------------------------


class TestExpandActions:
    """Tests for the standalone expand_actions() function."""

    async def test_with_fetcher(self, mock_fetcher):
        from unittest.mock import patch

        with patch(
            "iam_validator.sdk.helpers.expand_wildcard_actions",
            new_callable=AsyncMock,
            return_value=["s3:GetObject", "s3:PutObject"],
        ):
            result = await expand_actions(["s3:*"], fetcher=mock_fetcher)
            assert "s3:GetObject" in result

    async def test_without_fetcher_creates_one(self):
        from unittest.mock import patch

        with patch(
            "iam_validator.sdk.helpers.expand_wildcard_actions",
            new_callable=AsyncMock,
            return_value=["ec2:RunInstances"],
        ):
            result = await expand_actions(["ec2:Run*"])
            assert "ec2:RunInstances" in result

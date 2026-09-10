"""Tests for policy structure validation enhancements."""

import pytest

from iam_validator.checks.policy_structure import PolicyStructureCheck, validate_policy_document
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy


class TestOutdatedVersionWarning:
    """Tests for the outdated version 2008-10-17 warning."""

    def test_current_version_no_warning(self):
        """Version 2012-10-17 should not produce any version issues."""
        policy_dict = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        issues = validate_policy_document(policy_dict)
        version_issues = [i for i in issues if i.issue_type in ("outdated_version", "invalid_version")]
        assert len(version_issues) == 0

    def test_outdated_version_warning_with_suggestion(self):
        """Version 2008-10-17 should produce an outdated_version warning with upgrade suggestion."""
        policy_dict = {
            "Version": "2008-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        issues = validate_policy_document(policy_dict)
        outdated_issues = [i for i in issues if i.issue_type == "outdated_version"]
        assert len(outdated_issues) == 1
        assert outdated_issues[0].severity == "warning"
        assert "2008-10-17" in outdated_issues[0].message
        assert "policy variables" in outdated_issues[0].message.lower()
        assert "2012-10-17" in outdated_issues[0].suggestion

    def test_invalid_version_still_error(self):
        """Invalid version (not 2012-10-17 or 2008-10-17) should still be an error."""
        policy_dict = {
            "Version": "2020-01-01",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        issues = validate_policy_document(policy_dict)
        invalid_issues = [i for i in issues if i.issue_type == "invalid_version"]
        assert len(invalid_issues) == 1
        assert invalid_issues[0].severity == "error"

    def test_missing_version_still_error(self):
        """Missing version should still be an error."""
        policy_dict = {
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        issues = validate_policy_document(policy_dict)
        missing_issues = [i for i in issues if i.issue_type == "missing_version"]
        assert len(missing_issues) == 1
        assert missing_issues[0].severity == "error"


class TestSingleObjectStatementDoesNotMutateCaller:
    """validate_policy_document must not mutate the dict passed to it."""

    def test_bare_statement_object_left_untouched(self):
        policy_dict = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        }
        validate_policy_document(policy_dict)
        assert isinstance(policy_dict["Statement"], dict)


class TestSingleObjectStatementPerStatementValidation:
    """A single-object Statement must still receive per-statement structural checks.

    This guards against PolicyStructureCheck.execute_policy silently relying on
    validate_policy_document mutating raw_policy_dict["Statement"] into a list.
    """

    @pytest.fixture
    def check(self):
        return PolicyStructureCheck()

    @pytest.fixture
    def fetcher(self):
        return AWSServiceFetcher()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="policy_structure")

    async def test_bare_statement_object_flags_action_conflict(self, check, fetcher, config):
        raw_policy_dict = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotAction": "s3:DeleteObject",
                "Resource": "*",
            },
        }
        policy = IAMPolicy(**raw_policy_dict)

        issues = await check.execute_policy(policy, "test.json", fetcher, config, raw_policy_dict=raw_policy_dict)

        conflict_issues = [i for i in issues if i.issue_type == "action_conflict"]
        assert len(conflict_issues) == 1
        assert conflict_issues[0].statement_index == 0
        # raw_policy_dict["Statement"] must stay a bare object; execute_policy
        # normalizes it locally rather than depending on a mutation.
        assert isinstance(raw_policy_dict["Statement"], dict)

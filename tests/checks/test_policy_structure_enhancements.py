"""Tests for policy structure validation enhancements."""

from iam_validator.checks.policy_structure import validate_policy_document


class TestOutdatedVersionWarning:
    """Tests for the outdated version 2008-10-17 warning."""

    def test_current_version_no_warning(self):
        """Version 2012-10-17 should not produce any version issues."""
        policy_dict = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        issues = validate_policy_document(policy_dict)
        version_issues = [
            i for i in issues if i.issue_type in ("outdated_version", "invalid_version")
        ]
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

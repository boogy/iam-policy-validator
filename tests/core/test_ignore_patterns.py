"""Tests for ignore pattern functionality with list support."""

import pytest

from iam_validator.core.ignore_patterns import IgnorePatternMatcher
from iam_validator.core.models import ValidationIssue


class TestIgnorePatternListSupport:
    """Test suite for ignore patterns with list support."""

    def test_single_action_pattern(self):
        """Test single action pattern (existing behavior)."""
        actions = frozenset(["s3:GetObject", "s3:PutObject", "iam:CreateUser"])
        ignore_patterns = [{"action": "^s3:GetObject$"}]

        filtered = IgnorePatternMatcher.filter_actions(actions, ignore_patterns)

        assert "s3:GetObject" not in filtered
        assert "s3:PutObject" in filtered
        assert "iam:CreateUser" in filtered

    def test_list_of_action_patterns(self):
        """Test list of action patterns (new feature)."""
        actions = frozenset(["s3:GetObject", "s3:PutObject", "iam:CreateUser", "ec2:RunInstances"])
        ignore_patterns = [{"action": ["^s3:GetObject$", "^s3:PutObject$"]}]

        filtered = IgnorePatternMatcher.filter_actions(actions, ignore_patterns)

        assert "s3:GetObject" not in filtered
        assert "s3:PutObject" not in filtered
        assert "iam:CreateUser" in filtered
        assert "ec2:RunInstances" in filtered

    def test_list_with_regex_patterns(self):
        """Test list with regex patterns."""
        actions = frozenset(
            [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "iam:CreateUser",
                "iam:DeleteUser",
            ]
        )
        ignore_patterns = [{"action": ["^s3:.*", "^iam:Create.*"]}]

        filtered = IgnorePatternMatcher.filter_actions(actions, ignore_patterns)

        # All s3 actions should be filtered
        assert "s3:GetObject" not in filtered
        assert "s3:PutObject" not in filtered
        assert "s3:DeleteObject" not in filtered
        # iam:CreateUser should be filtered
        assert "iam:CreateUser" not in filtered
        # iam:DeleteUser should remain
        assert "iam:DeleteUser" in filtered

    def test_multiple_patterns_with_lists(self):
        """Test multiple ignore patterns with lists."""
        actions = frozenset(
            [
                "s3:GetObject",
                "s3:PutObject",
                "iam:CreateUser",
                "ec2:RunInstances",
                "lambda:InvokeFunction",
            ]
        )
        ignore_patterns = [
            {"action": ["^s3:.*"]},
            {"action": ["^iam:.*", "^ec2:.*"]},
        ]

        filtered = IgnorePatternMatcher.filter_actions(actions, ignore_patterns)

        # s3, iam, and ec2 actions should be filtered
        assert "s3:GetObject" not in filtered
        assert "s3:PutObject" not in filtered
        assert "iam:CreateUser" not in filtered
        assert "ec2:RunInstances" not in filtered
        # lambda should remain
        assert "lambda:InvokeFunction" in filtered

    def test_mixed_single_and_list_patterns(self):
        """Test mixing single and list action patterns."""
        actions = frozenset(
            [
                "s3:GetObject",
                "s3:PutObject",
                "iam:CreateUser",
                "ec2:RunInstances",
            ]
        )
        ignore_patterns = [
            {"action": "^s3:GetObject$"},  # Single pattern
            {"action": ["^iam:.*", "^ec2:.*"]},  # List pattern
        ]

        filtered = IgnorePatternMatcher.filter_actions(actions, ignore_patterns)

        assert "s3:GetObject" not in filtered
        assert "s3:PutObject" in filtered
        assert "iam:CreateUser" not in filtered
        assert "ec2:RunInstances" not in filtered

    def test_empty_list(self):
        """Test empty list doesn't break anything."""
        actions = frozenset(["s3:GetObject", "s3:PutObject"])
        ignore_patterns = [{"action": []}]

        filtered = IgnorePatternMatcher.filter_actions(actions, ignore_patterns)

        # Nothing should be filtered
        assert filtered == actions

    def test_issue_matching_with_list(self):
        """Test issue matching with list of action patterns."""
        issue = ValidationIssue(
            severity="high",
            issue_type="sensitive_action",
            message="Test",
            statement_index=0,
            action="s3:PutObject",
        )

        # Should match with list containing the action
        pattern = {"action": ["^s3:GetObject$", "^s3:PutObject$", "^s3:DeleteObject$"]}
        assert IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

        # Should not match if action not in list
        pattern = {"action": ["^s3:GetObject$", "^iam:.*"]}
        assert not IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

    def test_issue_matching_with_regex_list(self):
        """Test issue matching with regex patterns in list."""
        issue = ValidationIssue(
            severity="high",
            issue_type="sensitive_action",
            message="Test",
            statement_index=0,
            action="iam:CreateUser",
        )

        # Should match with regex pattern in list
        pattern = {"action": ["^s3:.*", "^iam:Create.*", "^ec2:.*"]}
        assert IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

        # Should not match if no pattern matches
        pattern = {"action": ["^s3:.*", "^iam:Delete.*"]}
        assert not IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

    def test_combined_fields_with_list(self):
        """Test combining filepath and list of actions (AND logic)."""
        issue = ValidationIssue(
            severity="high",
            issue_type="sensitive_action",
            message="Test",
            statement_index=0,
            action="s3:PutObject",
        )

        # Both filepath AND action must match
        pattern = {
            "filepath": "^test/.*",
            "action": ["^s3:GetObject$", "^s3:PutObject$"],
        }
        assert IgnorePatternMatcher._matches_pattern(pattern, issue, "test/policy.json")

        # filepath matches but action doesn't
        pattern = {
            "filepath": "^test/.*",
            "action": ["^s3:GetObject$", "^iam:.*"],
        }
        assert not IgnorePatternMatcher._matches_pattern(pattern, issue, "test/policy.json")

        # action matches but filepath doesn't
        pattern = {
            "filepath": "^prod/.*",
            "action": ["^s3:PutObject$"],
        }
        assert not IgnorePatternMatcher._matches_pattern(pattern, issue, "test/policy.json")

    def test_should_ignore_issue_with_list(self):
        """Test should_ignore_issue with list patterns."""
        issue = ValidationIssue(
            severity="high",
            issue_type="sensitive_action",
            message="Test",
            statement_index=0,
            action="iam:PassRole",
        )

        ignore_patterns = [
            {
                "action": [
                    "^iam:PassRole$",
                    "^iam:CreateUser$",
                    "^iam:AttachUserPolicy$",
                ]
            }
        ]

        assert IgnorePatternMatcher.should_ignore_issue(issue, "test.json", ignore_patterns)

    def test_action_matches_alias(self):
        """Test that action_matches alias also works with lists."""
        actions = frozenset(["s3:GetObject", "s3:PutObject", "iam:CreateUser"])
        ignore_patterns = [{"action_matches": ["^s3:.*"]}]  # Old field name

        filtered = IgnorePatternMatcher.filter_actions(actions, ignore_patterns)

        assert "s3:GetObject" not in filtered
        assert "s3:PutObject" not in filtered
        assert "iam:CreateUser" in filtered

    def test_resource_field_with_list(self):
        """Test that resource field also supports lists."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
            resource="arn:aws:s3:::my-bucket/*",
        )

        # Resource should match with list
        pattern = {
            "resource": [
                "arn:aws:s3:::my-bucket/.*",
                "arn:aws:s3:::other-bucket/.*",
            ]
        }
        assert IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

        # Should not match if resource not in list patterns
        pattern = {
            "resource": [
                "arn:aws:s3:::other-bucket/.*",
                "arn:aws:dynamodb:.*",
            ]
        }
        assert not IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

    def test_condition_key_field_with_list(self):
        """Test that condition_key field also supports lists."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
            condition_key="aws:PrincipalOrgID",
        )

        # Condition key should match with list
        pattern = {
            "condition_key": [
                "aws:PrincipalOrgID",
                "aws:SourceAccount",
                "aws:SourceArn",
            ]
        }
        assert IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

        # Should not match if condition key not in list
        pattern = {
            "condition_key": [
                "aws:SourceAccount",
                "s3:prefix",
            ]
        }
        assert not IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

    def test_filepath_field_with_list(self):
        """Test that filepath field also supports lists."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
        )

        # Filepath should match with list
        pattern = {
            "filepath": [
                "^test/.*",
                "^examples/.*",
                "^sandbox/.*",
            ]
        }
        assert IgnorePatternMatcher._matches_pattern(pattern, issue, "test/policy.json")
        assert IgnorePatternMatcher._matches_pattern(pattern, issue, "examples/s3-policy.json")

        # Should not match if filepath not in list
        pattern = {
            "filepath": [
                "^prod/.*",
                "^staging/.*",
            ]
        }
        assert not IgnorePatternMatcher._matches_pattern(pattern, issue, "test/policy.json")

    def test_sid_field_with_list_exact_match(self):
        """Test that sid field supports lists with exact matches."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
            statement_sid="AllowS3Access",
        )

        # SID should match with list (exact match)
        pattern = {
            "sid": [
                "AllowS3Access",
                "AllowIAMAccess",
                "AllowEC2Access",
            ]
        }
        assert IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

        # Should not match if SID not in list
        pattern = {
            "sid": [
                "DenyS3Access",
                "AllowIAMAccess",
            ]
        }
        assert not IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

    def test_sid_field_with_list_regex(self):
        """Test that sid field supports lists with regex patterns."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
            statement_sid="AllowS3ReadAccess",
        )

        # SID should match with regex in list
        pattern = {
            "sid": [
                "Allow.*Access",  # Regex with *
                "Deny.*",
            ]
        }
        assert IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

        # Should not match if no pattern matches
        pattern = {
            "sid": [
                "Deny.*",
                "Block.*",
            ]
        }
        assert not IgnorePatternMatcher._matches_pattern(pattern, issue, "test.json")

    def test_all_fields_support_lists(self):
        """Test that all fields support lists simultaneously."""
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
            statement_sid="AllowS3Access",
            action="s3:PutObject",
            resource="arn:aws:s3:::my-bucket/*",
            condition_key="aws:SourceIp",
        )

        # All fields with lists (AND logic across fields, OR within each list)
        pattern = {
            "filepath": ["^test/.*", "^examples/.*"],
            "sid": ["AllowS3Access", "AllowEC2Access"],
            "action": ["^s3:Put.*", "^s3:Delete.*"],
            "resource": ["arn:aws:s3:::my-bucket/.*", "arn:aws:s3:::other-bucket/.*"],
            "condition_key": ["aws:SourceIp", "aws:SourceAccount"],
        }
        assert IgnorePatternMatcher._matches_pattern(pattern, issue, "test/policy.json")

        # If any field doesn't match, whole pattern fails
        pattern = {
            "filepath": ["^test/.*"],
            "action": ["^s3:Put.*"],
            "resource": ["arn:aws:s3:::different-bucket/.*"],  # This won't match
        }
        assert not IgnorePatternMatcher._matches_pattern(pattern, issue, "test/policy.json")


class TestDegenerateIgnorePatterns:
    def test_empty_entry_ignores_nothing(self):
        issue = ValidationIssue(severity="high", issue_type="test", message="Test", statement_index=0)

        assert not IgnorePatternMatcher.should_ignore_issue(issue, "policy.json", [{}])

    def test_annotation_only_entry_ignores_nothing(self):
        issue = ValidationIssue(severity="high", issue_type="test", message="Test", statement_index=0)

        assert not IgnorePatternMatcher.should_ignore_issue(issue, "policy.json", [{"reason": "reviewed"}])

    def test_annotation_keys_do_not_block_a_match(self):
        issue = ValidationIssue(
            severity="high", issue_type="test", message="Test", statement_index=0, action="iam:PassRole"
        )
        entry = {"action": "iam:PassRole", "reason": "approved", "description": "d", "comment": "c"}

        assert IgnorePatternMatcher.should_ignore_issue(issue, "policy.json", [entry])

    @pytest.mark.parametrize(
        "entry",
        [{"action": ""}, {"action": [""]}, {"resource": ""}, {"filepath": ""}, {"sid": ""}, {"sid": [""]}],
    )
    def test_empty_regex_value_ignores_nothing(self, entry):
        issue = ValidationIssue(
            severity="high",
            issue_type="test",
            message="Test",
            statement_index=0,
            statement_sid="S1",
            action="iam:PassRole",
            resource="*",
        )

        assert not IgnorePatternMatcher.should_ignore_issue(issue, "policy.json", [entry])

    def test_empty_action_pattern_filters_no_action(self):
        actions = frozenset({"iam:PassRole"})

        assert IgnorePatternMatcher.filter_actions(actions, [{"action": [""]}]) == actions

    def test_overflowing_repetition_is_invalid_not_a_crash(self):
        from iam_validator.core.ignore_patterns import compile_pattern

        assert compile_pattern("a{99999999999}") is None


class TestFilterActionsScoping:
    @pytest.mark.parametrize(
        "entry",
        [
            {"filepath": "dev/.*", "action": "s3:.*"},
            {"sid": "Dev", "action": "s3:.*"},
            {"action": "s3:.*", "typo": "x"},
        ],
    )
    def test_entry_with_other_fields_filters_no_action(self, entry):
        actions = frozenset({"s3:DeleteBucket"})

        assert IgnorePatternMatcher.filter_actions(actions, [entry]) == actions

    def test_action_only_entry_with_annotation_still_filters(self):
        entry = {"action": "s3:.*", "reason": "accepted"}

        assert IgnorePatternMatcher.filter_actions(frozenset({"s3:DeleteBucket"}), [entry]) == frozenset()

    @pytest.mark.parametrize(("path", "ignored"), [("dev/x.json", True), ("prod/x.json", False)])
    def test_filepath_scoped_entry_still_ignores_findings_in_its_files(self, path, ignored):
        entry = {"filepath": "dev/.*", "action": "s3:.*"}
        issue = ValidationIssue(
            severity="high",
            statement_index=0,
            issue_type="sensitive_action",
            message="m",
            action="s3:DeleteBucket",
        )

        assert IgnorePatternMatcher.should_ignore_issue(issue, path, [entry]) is ignored

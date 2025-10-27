"""Tests for security best practices check."""

import pytest

from iam_validator.checks.security_best_practices import SecurityBestPracticesCheck
from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement


class TestSecurityBestPracticesCheck:
    """Test suite for SecurityBestPracticesCheck."""

    @pytest.fixture
    def check(self):
        """Create a SecurityBestPracticesCheck instance."""
        return SecurityBestPracticesCheck()

    @pytest.fixture
    def fetcher(self):
        """Create a mock AWSServiceFetcher instance."""
        return AWSServiceFetcher()

    @pytest.fixture
    def config(self):
        """Create a default CheckConfig."""
        return CheckConfig(check_id="security_best_practices")

    def test_check_id(self, check):
        """Test check_id property."""
        assert check.check_id == "security_best_practices"

    def test_description(self, check):
        """Test description property."""
        assert check.description == "Checks for common security anti-patterns"

    def test_default_severity(self, check):
        """Test default_severity property."""
        assert check.default_severity == "warning"

    @pytest.mark.asyncio
    async def test_deny_statement_skipped(self, check, fetcher, config):
        """Test that Deny statements are skipped."""
        statement = Statement(Effect="Deny", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_action(self, check, fetcher, config):
        """Test wildcard action detection."""
        statement = Statement(Effect="Allow", Action=["*"], Resource=["arn:aws:s3:::my-bucket"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should have one issue for wildcard action
        wildcard_action_issues = [i for i in issues if "all actions" in i.message]
        assert len(wildcard_action_issues) == 1
        assert wildcard_action_issues[0].severity == "warning"
        assert wildcard_action_issues[0].issue_type == "overly_permissive"

    @pytest.mark.asyncio
    async def test_wildcard_resource(self, check, fetcher, config):
        """Test wildcard resource detection."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should have one issue for wildcard resource
        wildcard_resource_issues = [i for i in issues if "all resources" in i.message]
        assert len(wildcard_resource_issues) == 1
        assert wildcard_resource_issues[0].severity == "warning"
        assert wildcard_resource_issues[0].issue_type == "overly_permissive"

    @pytest.mark.asyncio
    async def test_full_wildcard_critical(self, check, fetcher, config):
        """Test both wildcards together is flagged as critical."""
        statement = Statement(Effect="Allow", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should have critical issue for full wildcard
        critical_issues = [i for i in issues if "CRITICAL SECURITY RISK" in i.message]
        assert len(critical_issues) == 1
        assert critical_issues[0].severity == "error"
        assert critical_issues[0].issue_type == "security_risk"

    @pytest.mark.asyncio
    async def test_sensitive_action_without_condition(self, check, fetcher, config):
        """Test sensitive action without conditions."""
        statement = Statement(Effect="Allow", Action=["iam:CreateUser"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should have issue for sensitive action without condition
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert sensitive_issues[0].severity == "warning"
        assert sensitive_issues[0].issue_type == "missing_condition"
        assert sensitive_issues[0].action == "iam:CreateUser"

    @pytest.mark.asyncio
    async def test_sensitive_action_with_condition(self, check, fetcher, config):
        """Test sensitive action with conditions passes."""
        statement = Statement(
            Effect="Allow",
            Action=["iam:CreateUser"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should not have issue for sensitive action with condition
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 0

    @pytest.mark.asyncio
    async def test_multiple_sensitive_actions(self, check, fetcher, config):
        """Test multiple sensitive actions are all flagged."""
        statement = Statement(
            Effect="Allow",
            Action=["iam:CreateUser", "iam:DeleteUser", "s3:DeleteBucket"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should have one issue mentioning all sensitive actions
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        # All three actions should be mentioned in the message
        assert "iam:CreateUser" in sensitive_issues[0].message
        assert "iam:DeleteUser" in sensitive_issues[0].message
        assert "s3:DeleteBucket" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_statement_with_sid(self, check, fetcher, config):
        """Test that statement SID is captured."""
        statement = Statement(Sid="TestStatement", Effect="Allow", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        assert all(issue.statement_sid == "TestStatement" for issue in issues)

    @pytest.mark.asyncio
    async def test_statement_index(self, check, fetcher, config):
        """Test that statement index is captured."""
        statement = Statement(Effect="Allow", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 5, fetcher, config)

        assert all(issue.statement_index == 5 for issue in issues)

    @pytest.mark.asyncio
    async def test_disable_wildcard_action_check(self, check, fetcher):
        """Test disabling wildcard action check."""
        config = CheckConfig(
            check_id="security_best_practices", config={"wildcard_action_check": {"enabled": False}}
        )
        statement = Statement(Effect="Allow", Action=["*"], Resource=["arn:aws:s3:::bucket"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should not have wildcard action issue
        wildcard_action_issues = [i for i in issues if "all actions" in i.message]
        assert len(wildcard_action_issues) == 0

    @pytest.mark.asyncio
    async def test_disable_wildcard_resource_check(self, check, fetcher):
        """Test disabling wildcard resource check."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={"wildcard_resource_check": {"enabled": False}},
        )
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should not have wildcard resource issue
        wildcard_resource_issues = [i for i in issues if "all resources" in i.message]
        assert len(wildcard_resource_issues) == 0

    @pytest.mark.asyncio
    async def test_disable_sensitive_action_check(self, check, fetcher):
        """Test disabling sensitive action check."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={"sensitive_action_check": {"enabled": False}},
        )
        statement = Statement(Effect="Allow", Action=["iam:CreateUser"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should not have sensitive action issue
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 0

    @pytest.mark.asyncio
    async def test_custom_severity_wildcard_action(self, check, fetcher):
        """Test custom severity for wildcard action check."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={"wildcard_action_check": {"severity": "error"}},
        )
        statement = Statement(Effect="Allow", Action=["*"], Resource=["arn:aws:s3:::bucket"])
        issues = await check.execute(statement, 0, fetcher, config)

        wildcard_action_issues = [i for i in issues if "all actions" in i.message]
        assert wildcard_action_issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_custom_sensitive_actions(self, check, fetcher):
        """Test custom sensitive actions list."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={"sensitive_action_check": {"sensitive_actions": ["s3:PutObject"]}},
        )
        statement = Statement(
            Effect="Allow", Action=["s3:PutObject", "iam:CreateUser"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should only flag s3:PutObject, not iam:CreateUser
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert sensitive_issues[0].action == "s3:PutObject"

    @pytest.mark.asyncio
    async def test_sensitive_action_pattern_regex(self, check, fetcher):
        """Test sensitive action pattern matching with regex."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [],
                    "sensitive_action_patterns": ["^iam:.*", ".*:Delete.*"],
                }
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["iam:CreateUser", "s3:DeleteBucket", "s3:GetObject"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag iam:CreateUser and s3:DeleteBucket, but not s3:GetObject
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        # Both actions should be mentioned in the message
        assert "iam:CreateUser" in sensitive_issues[0].message
        assert "s3:DeleteBucket" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_invalid_regex_pattern_ignored(self, check, fetcher):
        """Test that invalid regex patterns are ignored."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [],
                    "sensitive_action_patterns": ["[invalid(regex"],
                }
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],  # Use non-sensitive action
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should not flag anything since the pattern is invalid and action isn't in default list
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 0

    @pytest.mark.asyncio
    async def test_normal_action_not_flagged(self, check, fetcher, config):
        """Test that normal actions are not flagged."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::my-bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should have no issues
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, fetcher, config):
        """Test that line number is captured when available."""
        statement = Statement(Effect="Allow", Action=["*"], Resource=["*"])
        statement.line_number = 42

        issues = await check.execute(statement, 0, fetcher, config)

        assert all(issue.line_number == 42 for issue in issues)

    @pytest.mark.asyncio
    async def test_service_wildcard_detected(self, check, fetcher, config):
        """Test that service-level wildcards are detected."""
        statement = Statement(Effect="Allow", Action=["iam:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        service_wildcard_issues = [i for i in issues if "Service-level wildcard" in i.message]
        assert len(service_wildcard_issues) == 1
        assert service_wildcard_issues[0].action == "iam:*"
        assert service_wildcard_issues[0].severity == "warning"
        assert "iam service" in service_wildcard_issues[0].message

    @pytest.mark.asyncio
    async def test_multiple_service_wildcards(self, check, fetcher, config):
        """Test multiple service-level wildcards are all flagged."""
        statement = Statement(Effect="Allow", Action=["iam:*", "s3:*", "ec2:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        service_wildcard_issues = [i for i in issues if "Service-level wildcard" in i.message]
        assert len(service_wildcard_issues) == 3
        flagged_actions = {issue.action for issue in service_wildcard_issues}
        assert flagged_actions == {"iam:*", "s3:*", "ec2:*"}

    @pytest.mark.asyncio
    async def test_allowed_service_wildcard(self, check, fetcher):
        """Test that allowed services don't trigger the check."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={"service_wildcard_check": {"allowed_services": ["logs", "cloudwatch"]}},
        )
        statement = Statement(Effect="Allow", Action=["logs:*", "cloudwatch:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should not flag allowed services
        service_wildcard_issues = [i for i in issues if "Service-level wildcard" in i.message]
        assert len(service_wildcard_issues) == 0

    @pytest.mark.asyncio
    async def test_mixed_allowed_and_disallowed_service_wildcards(self, check, fetcher):
        """Test mix of allowed and disallowed service wildcards."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={"service_wildcard_check": {"allowed_services": ["logs"]}},
        )
        statement = Statement(Effect="Allow", Action=["logs:*", "iam:*", "s3:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should only flag iam:* and s3:*, not logs:*
        service_wildcard_issues = [i for i in issues if "Service-level wildcard" in i.message]
        assert len(service_wildcard_issues) == 2
        flagged_actions = {issue.action for issue in service_wildcard_issues}
        assert flagged_actions == {"iam:*", "s3:*"}

    @pytest.mark.asyncio
    async def test_service_wildcard_with_custom_severity(self, check, fetcher):
        """Test custom severity for service wildcard check."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={"service_wildcard_check": {"severity": "error"}},
        )
        statement = Statement(Effect="Allow", Action=["iam:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        service_wildcard_issues = [i for i in issues if "Service-level wildcard" in i.message]
        assert service_wildcard_issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_service_wildcard_check_disabled(self, check, fetcher):
        """Test disabling service wildcard check."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={"service_wildcard_check": {"enabled": False}},
        )
        statement = Statement(Effect="Allow", Action=["iam:*", "s3:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should not have service wildcard issues
        service_wildcard_issues = [i for i in issues if "Service-level wildcard" in i.message]
        assert len(service_wildcard_issues) == 0

    @pytest.mark.asyncio
    async def test_full_wildcard_not_flagged_by_service_check(self, check, fetcher, config):
        """Test that full wildcard (*) is not flagged by service wildcard check."""
        statement = Statement(Effect="Allow", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Full wildcard should be caught by wildcard_action_check, not service_wildcard_check
        service_wildcard_issues = [i for i in issues if "Service-level wildcard" in i.message]
        assert len(service_wildcard_issues) == 0

    @pytest.mark.asyncio
    async def test_partial_wildcards_not_flagged(self, check, fetcher, config):
        """Test that partial wildcards like 'iam:Get*' are not flagged."""
        statement = Statement(Effect="Allow", Action=["iam:Get*", "s3:List*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Partial wildcards should not trigger service wildcard check
        service_wildcard_issues = [i for i in issues if "Service-level wildcard" in i.message]
        assert len(service_wildcard_issues) == 0

    @pytest.mark.asyncio
    async def test_service_wildcard_suggestion(self, check, fetcher, config):
        """Test that service wildcard issues include helpful suggestions."""
        statement = Statement(Effect="Allow", Action=["iam:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        service_wildcard_issues = [i for i in issues if "Service-level wildcard" in i.message]
        assert service_wildcard_issues[0].suggestion is not None
        assert "iam:Get*" in service_wildcard_issues[0].suggestion
        assert "iam:List*" in service_wildcard_issues[0].suggestion

    # ============================================================================
    # Tests for any_of/all_of functionality in sensitive_actions
    # ============================================================================

    @pytest.mark.asyncio
    async def test_sensitive_actions_any_of(self, check, fetcher):
        """Test sensitive_actions with any_of logic."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": {"any_of": ["iam:CreateUser", "s3:DeleteBucket"]}
                }
            },
        )
        statement = Statement(
            Effect="Allow", Action=["iam:CreateUser", "s3:GetObject"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag iam:CreateUser (matches any_of)
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert "iam:CreateUser" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_sensitive_actions_all_of(self, check, fetcher):
        """Test sensitive_actions with all_of logic."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": {"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]}
                }
            },
        )

        # Statement with both actions - should be flagged
        statement = Statement(
            Effect="Allow",
            Action=["iam:CreateUser", "iam:AttachUserPolicy", "s3:GetObject"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        # Should mention both actions in message
        assert "iam:CreateUser" in sensitive_issues[0].message
        assert "iam:AttachUserPolicy" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_sensitive_actions_all_of_partial_match(self, check, fetcher):
        """Test sensitive_actions with all_of logic - partial match should not flag."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": {"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]}
                }
            },
        )

        # Statement with only one action - should NOT be flagged (all_of requires both)
        statement = Statement(
            Effect="Allow", Action=["iam:CreateUser", "s3:GetObject"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 0

    @pytest.mark.asyncio
    async def test_sensitive_action_patterns_any_of(self, check, fetcher):
        """Test sensitive_action_patterns with any_of logic."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [],
                    "sensitive_action_patterns": {"any_of": ["^iam:Delete.*", "^s3:Delete.*"]},
                }
            },
        )
        statement = Statement(
            Effect="Allow", Action=["iam:DeleteUser", "s3:GetObject"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag iam:DeleteUser (matches any_of pattern)
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert "iam:DeleteUser" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_sensitive_action_patterns_all_of(self, check, fetcher):
        """Test sensitive_action_patterns with all_of logic."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [],
                    "sensitive_action_patterns": {"all_of": ["^iam:.*", ".*User$"]},
                }
            },
        )

        # Action that matches both patterns
        statement = Statement(
            Effect="Allow",
            Action=["iam:CreateUser", "iam:DeleteRole", "s3:GetObject"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should only flag iam:CreateUser (matches both patterns)
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert "iam:CreateUser" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_sensitive_action_patterns_all_of_no_match(self, check, fetcher):
        """Test sensitive_action_patterns with all_of logic - no complete match."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [],  # Disable default sensitive actions
                    "sensitive_action_patterns": {"all_of": ["^iam:.*", ".*User$"]},
                }
            },
        )

        # Actions that match only one pattern each (avoid default sensitive actions)
        statement = Statement(
            Effect="Allow", Action=["iam:GetRole", "ec2:CreateUser", "s3:GetObject"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should not flag anything (no action matches ALL patterns)
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 0

    @pytest.mark.asyncio
    async def test_combined_actions_and_patterns_any_of(self, check, fetcher):
        """Test combination of sensitive_actions and sensitive_action_patterns with any_of."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": {"any_of": ["s3:DeleteBucket"]},
                    "sensitive_action_patterns": {"any_of": ["^iam:Delete.*"]},
                }
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["s3:DeleteBucket", "iam:DeleteUser", "ec2:RunInstances"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag both s3:DeleteBucket (exact match) and iam:DeleteUser (pattern match)
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        # Both actions should be in the message
        assert "s3:DeleteBucket" in sensitive_issues[0].message
        assert "iam:DeleteUser" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_combined_actions_and_patterns_all_of(self, check, fetcher):
        """Test combination of sensitive_actions and sensitive_action_patterns with all_of."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": {"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]},
                    "sensitive_action_patterns": {"all_of": ["^s3:.*", ".*Bucket.*"]},
                }
            },
        )

        # Statement with actions matching both all_of criteria
        statement = Statement(
            Effect="Allow",
            Action=["iam:CreateUser", "iam:AttachUserPolicy", "s3:DeleteBucket"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag because both all_of conditions are met
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1

    @pytest.mark.asyncio
    async def test_backward_compatibility_simple_list(self, check, fetcher):
        """Test backward compatibility with simple list format."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": ["iam:CreateUser", "s3:DeleteBucket"]
                }
            },
        )
        statement = Statement(Effect="Allow", Action=["iam:CreateUser"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should work as before (any_of logic)
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert "iam:CreateUser" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_backward_compatibility_pattern_list(self, check, fetcher):
        """Test backward compatibility with simple pattern list format."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [],
                    "sensitive_action_patterns": ["^iam:Delete.*", "^s3:Delete.*"],
                }
            },
        )
        statement = Statement(Effect="Allow", Action=["iam:DeleteUser"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should work as before (any_of logic)
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert "iam:DeleteUser" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_wildcard_actions_ignored(self, check, fetcher):
        """Test that wildcard actions are ignored in sensitive action checks."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": ["*"]  # Should not flag wildcard
                }
            },
        )
        statement = Statement(Effect="Allow", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should not have sensitive action issues (wildcard is handled by other checks)
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 0

    @pytest.mark.asyncio
    async def test_empty_config_uses_defaults(self, check, fetcher):
        """Test that empty config falls back to default sensitive actions."""
        config = CheckConfig(
            check_id="security_best_practices", config={"sensitive_action_check": {}}
        )
        statement = Statement(
            Effect="Allow",
            Action=["iam:CreateUser"],  # In default list
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should use default sensitive actions
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert "iam:CreateUser" in sensitive_issues[0].message

    # ============================================================================
    # Tests for multi-group any_of/all_of functionality
    # ============================================================================

    @pytest.mark.asyncio
    async def test_multiple_all_of_groups_first_matches(self, check, fetcher):
        """Test multiple all_of groups where first group matches."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [
                        {"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]},
                        {"all_of": ["lambda:CreateFunction", "iam:PassRole"]},
                    ]
                }
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["iam:CreateUser", "iam:AttachUserPolicy", "s3:GetObject"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag because first all_of group is satisfied
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert "iam:CreateUser" in sensitive_issues[0].message
        assert "iam:AttachUserPolicy" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_multiple_all_of_groups_second_matches(self, check, fetcher):
        """Test multiple all_of groups where second group matches."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [
                        {"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]},
                        {"all_of": ["lambda:CreateFunction", "iam:PassRole"]},
                    ]
                }
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["lambda:CreateFunction", "iam:PassRole", "s3:GetObject"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag because second all_of group is satisfied
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert "lambda:CreateFunction" in sensitive_issues[0].message
        assert "iam:PassRole" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_multiple_all_of_groups_both_match(self, check, fetcher):
        """Test multiple all_of groups where both groups match."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [
                        {"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]},
                        {"all_of": ["lambda:CreateFunction", "iam:PassRole"]},
                    ]
                }
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=[
                "iam:CreateUser",
                "iam:AttachUserPolicy",
                "lambda:CreateFunction",
                "iam:PassRole",
            ],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag because both all_of groups are satisfied
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        # All four actions should be mentioned
        assert "iam:CreateUser" in sensitive_issues[0].message
        assert "iam:AttachUserPolicy" in sensitive_issues[0].message
        assert "lambda:CreateFunction" in sensitive_issues[0].message
        assert "iam:PassRole" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_multiple_all_of_groups_none_match(self, check, fetcher):
        """Test multiple all_of groups where no groups match."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [
                        {"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]},
                        {"all_of": ["lambda:CreateFunction", "iam:PassRole"]},
                    ]
                }
            },
        )
        statement = Statement(
            Effect="Allow",
            Action=["iam:CreateUser", "s3:GetObject"],  # Only partial match
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should not flag because no all_of group is fully satisfied
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 0

    @pytest.mark.asyncio
    async def test_mixed_groups_strings_and_all_of(self, check, fetcher):
        """Test mixed configuration with strings and all_of groups."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [
                        "s3:DeleteBucket",  # Simple string
                        {"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]},
                    ]
                }
            },
        )

        # Test 1: Only simple string matches
        statement1 = Statement(Effect="Allow", Action=["s3:DeleteBucket"], Resource=["*"])
        issues1 = await check.execute(statement1, 0, fetcher, config)
        sensitive_issues1 = [i for i in issues1 if "Sensitive action" in i.message]
        assert len(sensitive_issues1) == 1
        assert "s3:DeleteBucket" in sensitive_issues1[0].message

        # Test 2: Only all_of group matches
        statement2 = Statement(
            Effect="Allow", Action=["iam:CreateUser", "iam:AttachUserPolicy"], Resource=["*"]
        )
        issues2 = await check.execute(statement2, 0, fetcher, config)
        sensitive_issues2 = [i for i in issues2 if "Sensitive action" in i.message]
        assert len(sensitive_issues2) == 1

        # Test 3: Both match
        statement3 = Statement(
            Effect="Allow",
            Action=["s3:DeleteBucket", "iam:CreateUser", "iam:AttachUserPolicy"],
            Resource=["*"],
        )
        issues3 = await check.execute(statement3, 0, fetcher, config)
        sensitive_issues3 = [i for i in issues3 if "Sensitive action" in i.message]
        assert len(sensitive_issues3) == 1
        assert "s3:DeleteBucket" in sensitive_issues3[0].message

    @pytest.mark.asyncio
    async def test_multiple_pattern_all_of_groups(self, check, fetcher):
        """Test multiple all_of groups in sensitive_action_patterns."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [],
                    "sensitive_action_patterns": [
                        {"all_of": ["^iam:.*", ".*User$"]},  # IAM user actions
                        {"all_of": ["^s3:.*", ".*Bucket.*"]},  # S3 bucket actions
                    ],
                }
            },
        )

        # Test 1: Matches first pattern group
        statement1 = Statement(
            Effect="Allow", Action=["iam:CreateUser", "s3:GetObject"], Resource=["*"]
        )
        issues1 = await check.execute(statement1, 0, fetcher, config)
        sensitive_issues1 = [i for i in issues1 if "Sensitive action" in i.message]
        assert len(sensitive_issues1) == 1
        assert "iam:CreateUser" in sensitive_issues1[0].message

        # Test 2: Matches second pattern group
        statement2 = Statement(
            Effect="Allow", Action=["s3:DeleteBucket", "ec2:RunInstances"], Resource=["*"]
        )
        issues2 = await check.execute(statement2, 0, fetcher, config)
        sensitive_issues2 = [i for i in issues2 if "Sensitive action" in i.message]
        assert len(sensitive_issues2) == 1
        assert "s3:DeleteBucket" in sensitive_issues2[0].message

    @pytest.mark.asyncio
    async def test_mixed_pattern_groups_strings_and_all_of(self, check, fetcher):
        """Test mixed pattern configuration with strings and all_of groups."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [],
                    "sensitive_action_patterns": [
                        "^kms:Delete.*",  # Simple pattern
                        {"all_of": ["^iam:.*", ".*User$"]},  # IAM user actions
                    ],
                }
            },
        )

        # Test with both matching
        statement = Statement(
            Effect="Allow",
            Action=["kms:DeleteKey", "iam:CreateUser", "s3:GetObject"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert "kms:DeleteKey" in sensitive_issues[0].message
        assert "iam:CreateUser" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_multiple_any_of_groups(self, check, fetcher):
        """Test multiple any_of groups in configuration."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [
                        {"any_of": ["iam:CreateUser", "iam:CreateRole"]},
                        {"any_of": ["s3:DeleteBucket", "s3:DeleteObject"]},
                    ]
                }
            },
        )

        # Test first group match
        statement = Statement(
            Effect="Allow", Action=["iam:CreateUser", "ec2:RunInstances"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        assert "iam:CreateUser" in sensitive_issues[0].message

    @pytest.mark.asyncio
    async def test_complex_nested_groups(self, check, fetcher):
        """Test complex nested group configuration."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [
                        "rds:DeleteDBInstance",  # Simple action
                        {
                            "all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]
                        },  # Privilege escalation
                        {
                            "any_of": ["lambda:CreateFunction", "lambda:UpdateFunctionCode"]
                        },  # Lambda changes
                    ],
                    "sensitive_action_patterns": [
                        "^kms:Delete.*",  # KMS delete operations
                        {"all_of": ["^s3:.*", ".*Bucket.*"]},  # S3 bucket operations
                    ],
                }
            },
        )

        # Test statement matching multiple groups
        statement = Statement(
            Effect="Allow",
            Action=[
                "rds:DeleteDBInstance",  # Matches simple action
                "lambda:CreateFunction",  # Matches any_of group
                "s3:DeleteBucket",  # Matches pattern all_of group
                "kms:DeleteKey",  # Matches simple pattern
            ],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        sensitive_issues = [i for i in issues if "Sensitive action" in i.message]
        assert len(sensitive_issues) == 1
        # All four matching actions should be mentioned
        assert "rds:DeleteDBInstance" in sensitive_issues[0].message
        assert "lambda:CreateFunction" in sensitive_issues[0].message
        assert "s3:DeleteBucket" in sensitive_issues[0].message
        assert "kms:DeleteKey" in sensitive_issues[0].message

    # ============================================================================
    # Tests for policy-level privilege escalation detection
    # ============================================================================

    @pytest.mark.asyncio
    async def test_policy_level_privilege_escalation_detected(self, check, fetcher):
        """Test policy-level detection of privilege escalation across multiple statements."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [{"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]}]
                }
            },
        )

        # Create a policy with actions scattered across multiple statements
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="AllowCreateUser", Effect="Allow", Action=["iam:CreateUser"], Resource=["*"]
                ),
                Statement(
                    Sid="AllowS3Read",
                    Effect="Allow",
                    Action=["s3:GetObject", "s3:ListBucket"],
                    Resource=["*"],
                ),
                Statement(
                    Sid="AllowAttachPolicy",
                    Effect="Allow",
                    Action=["iam:AttachUserPolicy"],
                    Resource=["*"],
                ),
            ],
        )

        # Execute policy-level check
        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Should detect privilege escalation across statements
        priv_esc_issues = [i for i in issues if i.issue_type == "privilege_escalation"]
        assert len(priv_esc_issues) == 1
        assert "Policy-level privilege escalation detected" in priv_esc_issues[0].message
        assert "iam:CreateUser" in priv_esc_issues[0].message
        assert "iam:AttachUserPolicy" in priv_esc_issues[0].message
        assert priv_esc_issues[0].statement_index == -1  # Policy-level issue
        assert "AllowCreateUser" in priv_esc_issues[0].suggestion
        assert "AllowAttachPolicy" in priv_esc_issues[0].suggestion

    @pytest.mark.asyncio
    async def test_policy_level_no_privilege_escalation_partial_match(self, check, fetcher):
        """Test policy-level check doesn't flag when only partial match."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [{"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]}]
                }
            },
        )

        # Policy with only one of the required actions
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="AllowCreateUser", Effect="Allow", Action=["iam:CreateUser"], Resource=["*"]
                ),
                Statement(
                    Sid="AllowS3Read", Effect="Allow", Action=["s3:GetObject"], Resource=["*"]
                ),
            ],
        )

        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Should NOT detect privilege escalation (all_of requires both actions)
        priv_esc_issues = [i for i in issues if i.issue_type == "privilege_escalation"]
        assert len(priv_esc_issues) == 0

    @pytest.mark.asyncio
    async def test_policy_level_multiple_escalation_patterns(self, check, fetcher):
        """Test policy-level detection of multiple privilege escalation patterns."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [
                        {"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]},
                        {"all_of": ["iam:CreateRole", "iam:AttachRolePolicy"]},
                        {"all_of": ["lambda:CreateFunction", "iam:PassRole"]},
                    ]
                }
            },
        )

        # Policy with actions for two different escalation patterns
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Effect="Allow", Action=["iam:CreateUser"], Resource=["*"]),
                Statement(Effect="Allow", Action=["iam:AttachUserPolicy"], Resource=["*"]),
                Statement(Effect="Allow", Action=["lambda:CreateFunction"], Resource=["*"]),
                Statement(Effect="Allow", Action=["iam:PassRole"], Resource=["*"]),
            ],
        )

        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Should detect BOTH privilege escalation patterns
        priv_esc_issues = [i for i in issues if i.issue_type == "privilege_escalation"]
        assert len(priv_esc_issues) == 2

        # Check both patterns are detected
        messages = [issue.message for issue in priv_esc_issues]
        assert any("iam:CreateUser" in msg and "iam:AttachUserPolicy" in msg for msg in messages)
        assert any("lambda:CreateFunction" in msg and "iam:PassRole" in msg for msg in messages)

    @pytest.mark.asyncio
    async def test_policy_level_with_patterns(self, check, fetcher):
        """Test policy-level detection using regex patterns."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_action_patterns": [{"all_of": ["^iam:Create.*", "^iam:Attach.*"]}]
                }
            },
        )

        # Policy with actions matching both patterns
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Effect="Allow", Action=["iam:CreateUser"], Resource=["*"]),
                Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["*"]),
                Statement(Effect="Allow", Action=["iam:AttachUserPolicy"], Resource=["*"]),
            ],
        )

        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Should detect privilege escalation via patterns
        priv_esc_issues = [i for i in issues if i.issue_type == "privilege_escalation"]
        assert len(priv_esc_issues) == 1
        assert "iam:CreateUser" in priv_esc_issues[0].message
        assert "iam:AttachUserPolicy" in priv_esc_issues[0].message

    @pytest.mark.asyncio
    async def test_policy_level_deny_statements_ignored(self, check, fetcher):
        """Test that Deny statements are ignored in policy-level checks."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [{"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]}]
                }
            },
        )

        # Policy with Deny statements
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Effect="Allow", Action=["iam:CreateUser"], Resource=["*"]),
                Statement(Effect="Deny", Action=["iam:AttachUserPolicy"], Resource=["*"]),
            ],
        )

        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Should NOT detect privilege escalation (Deny doesn't grant permissions)
        priv_esc_issues = [i for i in issues if i.issue_type == "privilege_escalation"]
        assert len(priv_esc_issues) == 0

    @pytest.mark.asyncio
    async def test_policy_level_wildcards_ignored(self, check, fetcher):
        """Test that wildcard actions are ignored in policy-level privilege escalation checks."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "sensitive_actions": [{"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]}]
                }
            },
        )

        # Policy with wildcard (should be handled by other checks)
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Effect="Allow", Action=["*"], Resource=["*"]),
            ],
        )

        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Wildcard actions are filtered out in policy-level checks
        priv_esc_issues = [i for i in issues if i.issue_type == "privilege_escalation"]
        assert len(priv_esc_issues) == 0

    @pytest.mark.asyncio
    async def test_policy_level_check_disabled(self, check, fetcher):
        """Test that policy-level check respects sensitive_action_check enabled flag."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "sensitive_action_check": {
                    "enabled": False,  # Disabled
                    "sensitive_actions": [{"all_of": ["iam:CreateUser", "iam:AttachUserPolicy"]}],
                }
            },
        )

        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Effect="Allow", Action=["iam:CreateUser"], Resource=["*"]),
                Statement(Effect="Allow", Action=["iam:AttachUserPolicy"], Resource=["*"]),
            ],
        )

        issues = await check.execute_policy(policy, "test.json", fetcher, config)

        # Should not detect anything when check is disabled
        assert len(issues) == 0

    # ============================================================================
    # Tests for wildcard_resource_check with allowed_wildcards
    # ============================================================================

    @pytest.mark.asyncio
    async def test_wildcard_resource_with_allowed_actions(self, check, fetcher):
        """Test that Resource: '*' is allowed when all actions are in allowed_wildcards."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "wildcard_resource_check": {
                    "enabled": True,
                    "allowed_wildcards": ["s3:List*", "s3:Describe*", "ec2:Describe*"],
                }
            },
        )

        # Statement with only allowed wildcard actions and Resource: "*"
        statement = Statement(
            Effect="Allow", Action=["s3:ListAllMyBuckets", "s3:DescribeBuckets"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should NOT flag wildcard resource (all actions are in allowed list)
        wildcard_resource_issues = [i for i in issues if "all resources" in i.message]
        assert len(wildcard_resource_issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_resource_with_non_allowed_actions(self, check, fetcher):
        """Test that Resource: '*' is flagged when actions are NOT in allowed_wildcards."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "wildcard_resource_check": {
                    "enabled": True,
                    "allowed_wildcards": ["s3:List*", "s3:Describe*"],
                }
            },
        )

        # Statement with action NOT in allowed list and Resource: "*"
        statement = Statement(Effect="Allow", Action=["s3:PutObject"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag wildcard resource (action is not in allowed list)
        wildcard_resource_issues = [i for i in issues if "all resources" in i.message]
        assert len(wildcard_resource_issues) == 1

    @pytest.mark.asyncio
    async def test_wildcard_resource_mixed_actions(self, check, fetcher):
        """Test Resource: '*' flagged when statement has mix of allowed and non-allowed actions."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "wildcard_resource_check": {
                    "enabled": True,
                    "allowed_wildcards": ["s3:List*", "s3:Describe*"],
                }
            },
        )

        # Statement with BOTH allowed and non-allowed actions
        statement = Statement(
            Effect="Allow", Action=["s3:ListBucket", "s3:PutObject"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag wildcard resource (not ALL actions are allowed)
        wildcard_resource_issues = [i for i in issues if "all resources" in i.message]
        assert len(wildcard_resource_issues) == 1

    @pytest.mark.asyncio
    async def test_wildcard_resource_with_wildcard_pattern_match(self, check, fetcher):
        """Test that pattern matching works for allowed_wildcards."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "wildcard_resource_check": {
                    "enabled": True,
                    "allowed_wildcards": ["s3:List*", "ec2:Describe*"],
                }
            },
        )

        # Statement with actions matching wildcard patterns
        statement = Statement(
            Effect="Allow",
            Action=["s3:ListBucket", "s3:ListAllMyBuckets", "ec2:DescribeInstances"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should NOT flag (all actions match patterns)
        wildcard_resource_issues = [i for i in issues if "all resources" in i.message]
        assert len(wildcard_resource_issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_resource_inherits_from_parent(self, check, fetcher):
        """Test that wildcard_resource_check inherits from parent security_best_practices_check."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                # Parent level allowed_wildcards
                "allowed_wildcards": ["s3:List*", "iam:List*", "ec2:Describe*"],
                "wildcard_resource_check": {
                    "enabled": True
                    # No allowed_wildcards specified - inherits from parent
                }
            },
        )

        # Statement with actions that are in parent's allowed_wildcards
        statement = Statement(
            Effect="Allow", Action=["s3:ListAllMyBuckets", "iam:ListRoles"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)

        # Should NOT flag (inherits allowed_wildcards from parent)
        wildcard_resource_issues = [i for i in issues if "all resources" in i.message]
        assert len(wildcard_resource_issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_resource_empty_allowed_list(self, check, fetcher):
        """Test that empty allowed_wildcards list flags all Resource: '*'."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={"wildcard_resource_check": {"enabled": True, "allowed_wildcards": []}},
        )

        # Statement with safe actions but empty allowed_wildcards
        statement = Statement(Effect="Allow", Action=["s3:ListBucket"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag wildcard resource (allowed_wildcards is empty)
        wildcard_resource_issues = [i for i in issues if "all resources" in i.message]
        assert len(wildcard_resource_issues) == 1

    @pytest.mark.asyncio
    async def test_wildcard_resource_with_full_wildcard_action(self, check, fetcher):
        """Test that Resource: '*' with Action: '*' is flagged by both checks."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={
                "wildcard_resource_check": {
                    "enabled": True,
                    "allowed_wildcards": ["s3:List*"],
                }
            },
        )

        # Statement with full wildcard action
        statement = Statement(Effect="Allow", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag wildcard resource (action "*" is never in allowed list)
        wildcard_resource_issues = [i for i in issues if "all resources" in i.message]
        assert len(wildcard_resource_issues) >= 1  # May be flagged by both checks

        # Should also flag with critical full wildcard check
        critical_issues = [i for i in issues if "CRITICAL SECURITY RISK" in i.message]
        assert len(critical_issues) == 1

    @pytest.mark.asyncio
    async def test_wildcard_resource_no_config(self, check, fetcher):
        """Test wildcard_resource_check with no root_config (no allowed_wildcards available)."""
        config = CheckConfig(
            check_id="security_best_practices",
            config={"wildcard_resource_check": {"enabled": True}},
            root_config={},  # Empty root config
        )

        # Statement with safe actions
        statement = Statement(Effect="Allow", Action=["s3:ListBucket"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)

        # Should flag wildcard resource (no allowed_wildcards configured anywhere)
        wildcard_resource_issues = [i for i in issues if "all resources" in i.message]
        assert len(wildcard_resource_issues) == 1

"""Tests for MCP query tools."""

import pytest

from iam_validator.mcp.tools.query import (
    expand_wildcard_action,
    get_condition_requirements,
    get_policy_summary,
    list_checks,
    list_sensitive_actions,
    query_action_details,
    query_arn_formats,
    query_condition_keys,
    query_service_actions,
)


class TestQueryServiceActions:
    """Tests for query_service_actions function."""

    @pytest.mark.asyncio
    async def test_queries_service_actions(self):
        """Should return actions list and accept valid access levels."""
        actions = await query_service_actions("s3")
        assert isinstance(actions, list)

        # Test valid access levels
        for level in ["read", "write", "list", "tagging", "permissions-management"]:
            result = await query_service_actions("s3", access_level=level)
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_validates_access_level(self):
        """Should reject invalid access level."""
        with pytest.raises(ValueError, match="Invalid access level"):
            await query_service_actions("s3", access_level="invalid")


class TestQueryActionDetails:
    """Tests for query_action_details function."""

    @pytest.mark.asyncio
    async def test_queries_action_details(self):
        """Should return action details with expected attributes."""
        details = await query_action_details("s3:GetObject")
        if details:
            assert hasattr(details, "action")
            assert hasattr(details, "service")
            assert hasattr(details, "access_level")
            assert hasattr(details, "resource_types")
            assert hasattr(details, "condition_keys")
            assert isinstance(details.resource_types, list)
            assert isinstance(details.condition_keys, list)

    @pytest.mark.asyncio
    async def test_validates_action_format(self):
        """Should require service:action format."""
        with pytest.raises(ValueError, match="Invalid action format"):
            await query_action_details("invalid_action")


class TestExpandWildcardAction:
    """Tests for expand_wildcard_action function."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pattern,expected_prefix", [
        ("s3:Get*", "s3:Get"),
        ("s3:*", "s3:"),
    ])
    async def test_expands_wildcard_patterns(self, pattern, expected_prefix):
        """Should expand wildcard patterns correctly."""
        actions = await expand_wildcard_action(pattern)
        assert isinstance(actions, list)
        assert len(actions) > 0
        for action in actions:
            assert action.startswith(expected_prefix)
        # Should be sorted
        if len(actions) > 1:
            assert actions == sorted(actions)

    @pytest.mark.asyncio
    async def test_handles_invalid_pattern(self):
        """Should raise error for invalid wildcard pattern."""
        with pytest.raises(ValueError):
            await expand_wildcard_action("invalid:pattern*")


class TestQueryConditionKeys:
    """Tests for query_condition_keys function."""

    @pytest.mark.asyncio
    async def test_queries_condition_keys(self):
        """Should return condition keys for service."""
        keys = await query_condition_keys("s3")
        assert isinstance(keys, list)
        if keys:
            for key in keys:
                assert isinstance(key, str)


class TestQueryArnFormats:
    """Tests for query_arn_formats function."""

    @pytest.mark.asyncio
    async def test_queries_arn_formats(self):
        """Should return ARN formats with proper structure."""
        arns = await query_arn_formats("s3")
        assert isinstance(arns, list)
        if arns:
            for arn in arns:
                assert isinstance(arn, dict)
                assert "resource_type" in arn
                assert "arn_formats" in arn


class TestListChecks:
    """Tests for list_checks function."""

    @pytest.mark.asyncio
    async def test_returns_check_list_with_structure(self):
        """Should return sorted check list with proper structure."""
        checks = await list_checks()
        assert isinstance(checks, list)
        assert len(checks) > 0

        check_ids = []
        for check in checks:
            assert "check_id" in check
            assert "description" in check
            assert "default_severity" in check
            check_ids.append(check["check_id"])

        # Should be sorted and include key checks
        assert check_ids == sorted(check_ids)
        assert "wildcard_action" in check_ids
        assert "action_validation" in check_ids


class TestGetPolicySummary:
    """Tests for get_policy_summary function."""

    @pytest.mark.asyncio
    async def test_summarizes_policy(self, simple_policy_dict, wildcard_policy_dict, policy_with_condition_dict):
        """Should correctly summarize policy attributes."""
        # Test simple policy
        summary = await get_policy_summary(simple_policy_dict)
        assert hasattr(summary, "total_statements")
        assert hasattr(summary, "allow_statements")
        assert hasattr(summary, "deny_statements")
        assert hasattr(summary, "services_used")
        assert hasattr(summary, "actions_count")
        assert summary.total_statements == 1
        assert summary.allow_statements == 1
        assert "s3" in summary.services_used

        # Test wildcard detection
        wildcard_summary = await get_policy_summary(wildcard_policy_dict)
        assert hasattr(wildcard_summary, "has_wildcards")
        assert wildcard_summary.has_wildcards is True

        # Test condition detection
        condition_summary = await get_policy_summary(policy_with_condition_dict)
        assert hasattr(condition_summary, "has_conditions")
        assert condition_summary.has_conditions is True

    @pytest.mark.asyncio
    async def test_counts_deny_statements(self):
        """Should correctly count Allow and Deny statements."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]},
                {"Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": ["*"]},
            ],
        }
        summary = await get_policy_summary(policy)
        assert summary.allow_statements == 1
        assert summary.deny_statements == 1
        assert summary.total_statements == 2


class TestListSensitiveActions:
    """Tests for list_sensitive_actions function."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("category", [
        None,  # All categories
        "credential_exposure",
        "privilege_escalation",
        "data_access",
        "resource_exposure",
        "priv_esc",  # Alias
    ])
    async def test_lists_sensitive_actions(self, category):
        """Should list sensitive actions with optional category filter."""
        actions = await list_sensitive_actions(category=category)
        assert isinstance(actions, list)
        # Should be sorted
        if len(actions) > 1:
            assert actions == sorted(actions)

    @pytest.mark.asyncio
    async def test_validates_category(self):
        """Should reject invalid category."""
        with pytest.raises(ValueError, match="Invalid category"):
            await list_sensitive_actions(category="invalid_category")


class TestGetConditionRequirements:
    """Tests for get_condition_requirements function."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", [
        "iam:PassRole",  # Has requirements
        "ec2:DescribeInstances",  # No requirements
        "s3:*",  # Wildcard
    ])
    async def test_returns_requirements(self, action):
        """Should return requirements dict or None."""
        req = await get_condition_requirements(action)
        assert req is None or isinstance(req, dict)

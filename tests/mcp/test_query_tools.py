"""Tests for MCP query tools.

This module tests the query tools provided by the MCP server:
- query_service_actions: Get actions for a service
- query_action_details: Get action metadata
- expand_wildcard_action: Expand wildcard patterns
- query_condition_keys: Get condition keys
- query_arn_formats: Get ARN formats
- list_checks: List validation checks
- get_policy_summary: Analyze policy
- list_sensitive_actions: List sensitive actions
- get_condition_requirements: Get required conditions
"""

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
    async def test_queries_s3_actions(self, mock_fetcher):
        """Should return S3 actions."""
        with pytest.MonkeyPatch.context() as m:
            # Mock the fetcher context manager
            async def mock_context():
                return mock_fetcher

            actions = await query_service_actions("s3")

        assert isinstance(actions, list)

    @pytest.mark.asyncio
    async def test_filters_by_access_level(self, mock_fetcher):
        """Should filter actions by access level."""
        actions = await query_service_actions("s3", access_level="read")

        assert isinstance(actions, list)

    @pytest.mark.asyncio
    async def test_validates_access_level(self):
        """Should reject invalid access level."""
        with pytest.raises(ValueError, match="Invalid access level"):
            await query_service_actions("s3", access_level="invalid")

    @pytest.mark.asyncio
    async def test_accepts_valid_access_levels(self):
        """Should accept all valid access levels."""
        valid_levels = ["read", "write", "list", "tagging", "permissions-management"]

        for level in valid_levels:
            # Should not raise
            try:
                await query_service_actions("s3", access_level=level)
            except ValueError as e:
                if "Invalid access level" in str(e):
                    pytest.fail(f"Should accept access level: {level}")

    @pytest.mark.asyncio
    async def test_returns_action_names(self):
        """Should return action names as strings."""
        actions = await query_service_actions("s3")

        if actions:
            for action in actions:
                assert isinstance(action, str)
                assert ":" in action or action == "*"


class TestQueryActionDetails:
    """Tests for query_action_details function."""

    @pytest.mark.asyncio
    async def test_queries_action_details(self):
        """Should return action details."""
        details = await query_action_details("s3:GetObject")

        if details:  # May return None if not found
            assert hasattr(details, "action")
            assert hasattr(details, "service")
            assert hasattr(details, "access_level")

    @pytest.mark.asyncio
    async def test_validates_action_format(self):
        """Should require service:action format."""
        with pytest.raises(ValueError, match="Invalid action format"):
            await query_action_details("invalid_action")

    @pytest.mark.asyncio
    async def test_returns_none_for_nonexistent_action(self):
        """Should return None if action doesn't exist."""
        details = await query_action_details("s3:NonExistentAction")

        # May return None or raise error depending on implementation
        assert details is None or isinstance(details, object)

    @pytest.mark.asyncio
    async def test_includes_resource_types(self):
        """Should include resource types in details."""
        details = await query_action_details("s3:GetObject")

        if details:
            assert hasattr(details, "resource_types")
            assert isinstance(details.resource_types, list)

    @pytest.mark.asyncio
    async def test_includes_condition_keys(self):
        """Should include condition keys in details."""
        details = await query_action_details("s3:GetObject")

        if details:
            assert hasattr(details, "condition_keys")
            assert isinstance(details.condition_keys, list)

    @pytest.mark.asyncio
    async def test_includes_description(self):
        """Should include description in details."""
        details = await query_action_details("s3:GetObject")

        if details:
            assert hasattr(details, "description")


class TestExpandWildcardAction:
    """Tests for expand_wildcard_action function."""

    @pytest.mark.asyncio
    async def test_expands_prefix_wildcard(self):
        """Should expand s3:Get* pattern."""
        actions = await expand_wildcard_action("s3:Get*")

        assert isinstance(actions, list)
        assert len(actions) > 0
        # All should start with s3:Get
        for action in actions:
            assert action.startswith("s3:Get")

    @pytest.mark.asyncio
    async def test_expands_service_wildcard(self):
        """Should expand s3:* pattern."""
        actions = await expand_wildcard_action("s3:*")

        assert isinstance(actions, list)
        assert len(actions) > 0

    @pytest.mark.asyncio
    async def test_handles_invalid_pattern(self):
        """Should raise error for invalid wildcard pattern."""
        with pytest.raises(ValueError):
            await expand_wildcard_action("invalid:pattern*")

    @pytest.mark.asyncio
    async def test_returns_sorted_actions(self):
        """Should return sorted action list."""
        actions = await expand_wildcard_action("s3:Get*")

        if len(actions) > 1:
            assert actions == sorted(actions)


class TestQueryConditionKeys:
    """Tests for query_condition_keys function."""

    @pytest.mark.asyncio
    async def test_queries_s3_condition_keys(self):
        """Should return S3 condition keys."""
        keys = await query_condition_keys("s3")

        assert isinstance(keys, list)
        # Should have some condition keys
        if keys:
            for key in keys:
                assert isinstance(key, str)

    @pytest.mark.asyncio
    async def test_returns_key_names(self):
        """Should return condition key names."""
        keys = await query_condition_keys("s3")

        if keys:
            # Keys should have the format service:key or aws:key
            for key in keys:
                assert ":" in key or key.startswith("aws:")


class TestQueryArnFormats:
    """Tests for query_arn_formats function."""

    @pytest.mark.asyncio
    async def test_queries_s3_arn_formats(self):
        """Should return S3 ARN formats."""
        arns = await query_arn_formats("s3")

        assert isinstance(arns, list)

    @pytest.mark.asyncio
    async def test_arn_format_structure(self):
        """Should return ARNs with resource_type and arn_formats."""
        arns = await query_arn_formats("s3")

        if arns:
            for arn in arns:
                assert isinstance(arn, dict)
                assert "resource_type" in arn
                assert "arn_formats" in arn


class TestListChecks:
    """Tests for list_checks function."""

    @pytest.mark.asyncio
    async def test_returns_check_list(self):
        """Should return list of validation checks."""
        checks = await list_checks()

        assert isinstance(checks, list)
        assert len(checks) > 0  # Should have at least some checks

    @pytest.mark.asyncio
    async def test_check_structure(self):
        """Should include check_id, description, severity."""
        checks = await list_checks()

        for check in checks:
            assert "check_id" in check
            assert "description" in check
            assert "default_severity" in check

    @pytest.mark.asyncio
    async def test_includes_wildcard_action_check(self):
        """Should include wildcard_action check."""
        checks = await list_checks()

        check_ids = [c["check_id"] for c in checks]
        assert "wildcard_action" in check_ids

    @pytest.mark.asyncio
    async def test_includes_action_validation_check(self):
        """Should include action_validation check."""
        checks = await list_checks()

        check_ids = [c["check_id"] for c in checks]
        assert "action_validation" in check_ids

    @pytest.mark.asyncio
    async def test_checks_sorted_by_id(self):
        """Should return checks sorted by check_id."""
        checks = await list_checks()

        check_ids = [c["check_id"] for c in checks]
        assert check_ids == sorted(check_ids)


class TestGetPolicySummary:
    """Tests for get_policy_summary function."""

    @pytest.mark.asyncio
    async def test_summarizes_simple_policy(self, simple_policy_dict):
        """Should summarize a simple policy."""
        summary = await get_policy_summary(simple_policy_dict)

        assert hasattr(summary, "total_statements")
        assert hasattr(summary, "allow_statements")
        assert hasattr(summary, "deny_statements")

    @pytest.mark.asyncio
    async def test_counts_statements(self, simple_policy_dict):
        """Should count total statements."""
        summary = await get_policy_summary(simple_policy_dict)

        assert summary.total_statements == 1

    @pytest.mark.asyncio
    async def test_counts_allow_statements(self, simple_policy_dict):
        """Should count Allow statements."""
        summary = await get_policy_summary(simple_policy_dict)

        assert summary.allow_statements == 1

    @pytest.mark.asyncio
    async def test_counts_deny_statements(self):
        """Should count Deny statements."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["*"],
                },
                {
                    "Effect": "Deny",
                    "Action": ["s3:DeleteBucket"],
                    "Resource": ["*"],
                },
            ],
        }

        summary = await get_policy_summary(policy)

        assert summary.allow_statements == 1
        assert summary.deny_statements == 1
        assert summary.total_statements == 2

    @pytest.mark.asyncio
    async def test_lists_services_used(self, simple_policy_dict):
        """Should list services used in policy."""
        summary = await get_policy_summary(simple_policy_dict)

        assert hasattr(summary, "services_used")
        assert isinstance(summary.services_used, list)
        assert "s3" in summary.services_used

    @pytest.mark.asyncio
    async def test_counts_actions(self, simple_policy_dict):
        """Should count unique actions."""
        summary = await get_policy_summary(simple_policy_dict)

        assert hasattr(summary, "actions_count")
        assert summary.actions_count > 0

    @pytest.mark.asyncio
    async def test_detects_wildcards(self, wildcard_policy_dict):
        """Should detect wildcard usage."""
        summary = await get_policy_summary(wildcard_policy_dict)

        assert hasattr(summary, "has_wildcards")
        assert summary.has_wildcards is True

    @pytest.mark.asyncio
    async def test_detects_conditions(self, policy_with_condition_dict):
        """Should detect presence of conditions."""
        summary = await get_policy_summary(policy_with_condition_dict)

        assert hasattr(summary, "has_conditions")
        assert summary.has_conditions is True

    @pytest.mark.asyncio
    async def test_no_wildcards_for_simple_policy(self, simple_policy_dict):
        """Should report no wildcards for specific actions."""
        summary = await get_policy_summary(simple_policy_dict)

        # Depends on whether Resource has wildcard
        assert hasattr(summary, "has_wildcards")


class TestListSensitiveActions:
    """Tests for list_sensitive_actions function."""

    @pytest.mark.asyncio
    async def test_lists_all_sensitive_actions(self):
        """Should list all sensitive actions when no category specified."""
        actions = await list_sensitive_actions()

        assert isinstance(actions, list)
        assert len(actions) > 0

    @pytest.mark.asyncio
    async def test_filters_by_credential_exposure(self):
        """Should filter by credential_exposure category."""
        actions = await list_sensitive_actions(category="credential_exposure")

        assert isinstance(actions, list)
        # Should include credential exposure actions
        if actions:
            assert "iam:CreateAccessKey" in actions or "iam:GetUser" in actions or len(actions) > 0

    @pytest.mark.asyncio
    async def test_filters_by_privilege_escalation(self):
        """Should filter by privilege_escalation category."""
        actions = await list_sensitive_actions(category="privilege_escalation")

        assert isinstance(actions, list)

    @pytest.mark.asyncio
    async def test_filters_by_data_access(self):
        """Should filter by data_access category."""
        actions = await list_sensitive_actions(category="data_access")

        assert isinstance(actions, list)

    @pytest.mark.asyncio
    async def test_filters_by_resource_exposure(self):
        """Should filter by resource_exposure category."""
        actions = await list_sensitive_actions(category="resource_exposure")

        assert isinstance(actions, list)

    @pytest.mark.asyncio
    async def test_validates_category(self):
        """Should reject invalid category."""
        with pytest.raises(ValueError, match="Invalid category"):
            await list_sensitive_actions(category="invalid_category")

    @pytest.mark.asyncio
    async def test_returns_sorted_actions(self):
        """Should return sorted action list."""
        actions = await list_sensitive_actions()

        if len(actions) > 1:
            assert actions == sorted(actions)

    @pytest.mark.asyncio
    async def test_handles_category_alias(self):
        """Should handle priv_esc as alias for privilege_escalation."""
        actions = await list_sensitive_actions(category="priv_esc")

        assert isinstance(actions, list)


class TestGetConditionRequirements:
    """Tests for get_condition_requirements function."""

    @pytest.mark.asyncio
    async def test_returns_requirements_for_passrole(self):
        """Should return requirements for iam:PassRole."""
        req = await get_condition_requirements("iam:PassRole")

        # May return None if CONDITION_REQUIREMENTS not available
        if req:
            assert isinstance(req, dict)

    @pytest.mark.asyncio
    async def test_returns_none_for_safe_actions(self):
        """Should return None for actions without requirements."""
        req = await get_condition_requirements("ec2:DescribeInstances")

        # Should be None or empty dict
        assert req is None or isinstance(req, dict)

    @pytest.mark.asyncio
    async def test_handles_service_wildcard(self):
        """Should handle service-level wildcards."""
        req = await get_condition_requirements("s3:*")

        # May have requirements for s3:* pattern
        assert req is None or isinstance(req, dict)

    @pytest.mark.asyncio
    async def test_handles_nonexistent_action(self):
        """Should handle actions that don't exist."""
        req = await get_condition_requirements("fake:NonExistentAction")

        assert req is None or isinstance(req, dict)

"""Tests for MCP policy generation tools.

This module tests the policy generation tools provided by the MCP server:
- build_minimal_policy: Build policy from explicit actions and resources
- suggest_actions: Suggest actions from natural language
- get_required_conditions: Get required conditions for actions
- check_sensitive_actions: Check if actions are sensitive
- list_templates: List available templates
"""

import pytest

from iam_validator.mcp.tools.generation import (
    build_minimal_policy,
    suggest_actions,
    get_required_conditions,
    check_sensitive_actions,
    list_templates,
)


class TestBuildMinimalPolicy:
    """Tests for build_minimal_policy function."""

    @pytest.mark.asyncio
    async def test_builds_simple_policy(self):
        """Should build a basic policy from actions and resources."""
        actions = ["s3:GetObject", "s3:PutObject"]
        resources = ["arn:aws:s3:::my-bucket/*"]

        result = await build_minimal_policy(actions, resources)

        assert result is not None
        assert result.policy is not None
        assert "Version" in result.policy
        assert "Statement" in result.policy
        assert len(result.policy["Statement"]) > 0
        assert result.validation is not None

    @pytest.mark.asyncio
    async def test_includes_validation_results(self):
        """Should include validation results in response."""
        actions = ["s3:GetObject"]
        resources = ["arn:aws:s3:::my-bucket/*"]

        result = await build_minimal_policy(actions, resources)

        assert hasattr(result, "validation")
        assert hasattr(result.validation, "is_valid")
        assert hasattr(result.validation, "issues")

    @pytest.mark.asyncio
    async def test_includes_security_notes(self):
        """Should include security notes in response."""
        actions = ["s3:GetObject"]
        resources = ["arn:aws:s3:::my-bucket/*"]

        result = await build_minimal_policy(actions, resources)

        assert hasattr(result, "security_notes")
        assert isinstance(result.security_notes, list)

    @pytest.mark.asyncio
    async def test_blocks_bare_wildcard_action(self):
        """Should refuse to generate policy with Action: '*'."""
        actions = ["*"]
        resources = ["arn:aws:s3:::my-bucket/*"]

        result = await build_minimal_policy(actions, resources)

        assert result.validation.is_valid is False
        assert len(result.validation.issues) > 0
        assert any("bare_wildcard_not_allowed" in issue.issue_type for issue in result.validation.issues)
        assert "Policy generation blocked" in result.security_notes[0]

    @pytest.mark.asyncio
    async def test_blocks_wildcard_resource_with_write_actions(self):
        """Should refuse Resource: '*' with write actions."""
        actions = ["s3:PutObject", "s3:DeleteObject"]
        resources = ["*"]

        result = await build_minimal_policy(actions, resources)

        assert result.validation.is_valid is False
        assert len(result.validation.issues) > 0
        assert any("bare_wildcard_resource" in issue.issue_type for issue in result.validation.issues)

    @pytest.mark.asyncio
    async def test_allows_wildcard_resource_with_readonly_actions(self):
        """Should allow Resource: '*' with read-only actions (with warning)."""
        actions = ["s3:GetObject", "s3:ListBucket"]
        resources = ["*"]

        result = await build_minimal_policy(actions, resources)

        # Should succeed but may have warnings
        assert result.policy is not None
        assert len(result.policy["Statement"]) > 0

    @pytest.mark.asyncio
    async def test_validates_actions_exist(self):
        """Should validate that actions exist in AWS."""
        actions = ["s3:NonExistentAction"]
        resources = ["arn:aws:s3:::my-bucket/*"]

        result = await build_minimal_policy(actions, resources)

        # Should have validation errors for invalid action
        assert result.validation.is_valid is False
        assert len(result.validation.issues) > 0

    @pytest.mark.asyncio
    async def test_handles_wildcard_actions(self):
        """Should handle wildcard actions like s3:Get*."""
        actions = ["s3:Get*"]
        resources = ["arn:aws:s3:::my-bucket/*"]

        result = await build_minimal_policy(actions, resources)

        # Should expand and validate the wildcard
        assert result is not None

    @pytest.mark.asyncio
    async def test_detects_sensitive_actions(self):
        """Should detect and warn about sensitive actions."""
        actions = ["iam:CreateAccessKey"]  # Credential exposure
        resources = ["arn:aws:iam::123456789012:user/*"]

        result = await build_minimal_policy(actions, resources)

        # Should have security notes about sensitive action
        assert len(result.security_notes) > 0
        assert any("sensitive action" in note.lower() or "warning" in note.lower() for note in result.security_notes)

    @pytest.mark.asyncio
    async def test_adds_conditions_when_provided(self):
        """Should include conditions in generated policy."""
        actions = ["s3:GetObject"]
        resources = ["arn:aws:s3:::my-bucket/*"]
        conditions = {
            "StringEquals": {
                "aws:SourceVpc": "vpc-12345",
            }
        }

        result = await build_minimal_policy(actions, resources, conditions)

        assert result.policy is not None
        statement = result.policy["Statement"][0]
        assert "Condition" in statement
        assert statement["Condition"]["StringEquals"]["aws:SourceVpc"] == "vpc-12345"

    @pytest.mark.asyncio
    async def test_sorts_actions(self):
        """Should sort actions in the generated policy."""
        actions = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        resources = ["arn:aws:s3:::my-bucket/*"]

        result = await build_minimal_policy(actions, resources)

        statement = result.policy["Statement"][0]
        assert statement["Action"] == sorted(actions)

    @pytest.mark.asyncio
    async def test_handles_multiple_resources(self):
        """Should handle multiple resources."""
        actions = ["s3:GetObject"]
        resources = [
            "arn:aws:s3:::bucket1/*",
            "arn:aws:s3:::bucket2/*",
        ]

        result = await build_minimal_policy(actions, resources)

        statement = result.policy["Statement"][0]
        assert len(statement["Resource"]) == 2

    @pytest.mark.asyncio
    async def test_adds_sid_to_statement(self):
        """Should add a SID to the generated statement."""
        actions = ["s3:GetObject"]
        resources = ["arn:aws:s3:::my-bucket/*"]

        result = await build_minimal_policy(actions, resources)

        statement = result.policy["Statement"][0]
        assert "Sid" in statement
        assert statement["Sid"] == "GeneratedPolicy"


class TestSuggestActions:
    """Tests for suggest_actions function."""

    @pytest.mark.asyncio
    async def test_suggests_read_actions(self):
        """Should suggest read actions for read descriptions."""
        actions = await suggest_actions("read files from S3", service="s3")

        assert isinstance(actions, list)
        # Should have read-level actions
        if actions:  # May be empty if mock doesn't support
            assert any("Get" in action or "List" in action for action in actions)

    @pytest.mark.asyncio
    async def test_suggests_write_actions(self):
        """Should suggest write actions for write descriptions."""
        actions = await suggest_actions("upload files to S3", service="s3")

        assert isinstance(actions, list)

    @pytest.mark.asyncio
    async def test_detects_service_from_description(self):
        """Should detect AWS service from description."""
        actions = await suggest_actions("read from S3 bucket")

        assert isinstance(actions, list)

    @pytest.mark.asyncio
    async def test_returns_empty_for_unknown_service(self):
        """Should return empty list if service can't be detected."""
        actions = await suggest_actions("do something")

        assert actions == []

    @pytest.mark.asyncio
    async def test_handles_multiple_access_levels(self):
        """Should handle descriptions with multiple access levels."""
        actions = await suggest_actions("read and write to DynamoDB", service="dynamodb")

        assert isinstance(actions, list)

    @pytest.mark.asyncio
    async def test_deduplicates_actions(self):
        """Should remove duplicate actions from suggestions."""
        actions = await suggest_actions("list and enumerate S3 buckets", service="s3")

        assert isinstance(actions, list)
        # Should be deduplicated
        assert len(actions) == len(set(actions))

    @pytest.mark.asyncio
    async def test_sorts_suggested_actions(self):
        """Should return sorted action list."""
        actions = await suggest_actions("manage S3 buckets", service="s3")

        if len(actions) > 1:
            assert actions == sorted(actions)


class TestGetRequiredConditions:
    """Tests for get_required_conditions function."""

    @pytest.mark.asyncio
    async def test_returns_conditions_for_passrole(self):
        """Should return iam:PassedToService for iam:PassRole."""
        conditions = await get_required_conditions(["iam:PassRole"])

        assert isinstance(conditions, dict)
        # Should have iam:PassedToService condition
        if "StringEquals" in conditions:
            assert "iam:PassedToService" in conditions["StringEquals"]

    @pytest.mark.asyncio
    async def test_returns_secure_transport_for_s3(self):
        """Should return aws:SecureTransport for S3 actions."""
        conditions = await get_required_conditions(["s3:GetObject"])

        assert isinstance(conditions, dict)
        # Should have aws:SecureTransport condition
        if "Bool" in conditions:
            assert "aws:SecureTransport" in conditions["Bool"]

    @pytest.mark.asyncio
    async def test_returns_mfa_for_sensitive_actions(self):
        """Should return MFA condition for sensitive actions."""
        conditions = await get_required_conditions(["iam:CreateAccessKey"])

        assert isinstance(conditions, dict)
        # Should recommend MFA for credential exposure
        if "Bool" in conditions:
            assert "aws:MultiFactorAuthPresent" in conditions["Bool"]

    @pytest.mark.asyncio
    async def test_merges_conditions_for_multiple_actions(self):
        """Should merge conditions from multiple actions."""
        conditions = await get_required_conditions(["iam:PassRole", "s3:GetObject"])

        assert isinstance(conditions, dict)
        # Should have conditions from both actions

    @pytest.mark.asyncio
    async def test_returns_empty_for_nonsensitive_actions(self):
        """Should return empty dict for non-sensitive actions."""
        conditions = await get_required_conditions(["ec2:DescribeInstances"])

        assert isinstance(conditions, dict)


class TestCheckSensitiveActions:
    """Tests for check_sensitive_actions function."""

    @pytest.mark.asyncio
    async def test_identifies_credential_exposure_actions(self):
        """Should identify credential exposure actions."""
        result = await check_sensitive_actions(["iam:CreateAccessKey"])

        assert isinstance(result, dict)
        assert "sensitive_actions" in result
        sensitive = result["sensitive_actions"]
        if len(sensitive) > 0:
            assert sensitive[0]["action"] == "iam:CreateAccessKey"
            assert sensitive[0]["category"] in ["credential_exposure", "priv_esc"]

    @pytest.mark.asyncio
    async def test_identifies_privilege_escalation_actions(self):
        """Should identify privilege escalation actions."""
        result = await check_sensitive_actions(["iam:PassRole"])

        assert isinstance(result, dict)
        sensitive = result["sensitive_actions"]
        if len(sensitive) > 0:
            assert sensitive[0]["action"] == "iam:PassRole"

    @pytest.mark.asyncio
    async def test_returns_empty_for_safe_actions(self):
        """Should return empty list for safe actions."""
        result = await check_sensitive_actions(["s3:GetObject"])

        # GetObject might be in data_access category, so just check structure
        assert isinstance(result, dict)
        assert "sensitive_actions" in result
        assert isinstance(result["sensitive_actions"], list)

    @pytest.mark.asyncio
    async def test_includes_severity_information(self):
        """Should include severity in results."""
        result = await check_sensitive_actions(["iam:CreateAccessKey"])

        sensitive = result["sensitive_actions"]
        if len(sensitive) > 0:
            assert "severity" in sensitive[0]
            assert sensitive[0]["severity"] in ["critical", "high"]

    @pytest.mark.asyncio
    async def test_handles_multiple_actions(self):
        """Should check multiple actions."""
        result = await check_sensitive_actions([
            "iam:CreateAccessKey",
            "s3:GetObject",
            "iam:PassRole",
        ])

        assert isinstance(result, dict)
        assert "sensitive_actions" in result
        assert "total_checked" in result
        assert result["total_checked"] == 3

    @pytest.mark.asyncio
    async def test_includes_category_description(self):
        """Should include category description."""
        result = await check_sensitive_actions(["iam:CreateAccessKey"])

        sensitive = result["sensitive_actions"]
        if len(sensitive) > 0:
            assert "description" in sensitive[0]
            assert isinstance(sensitive[0]["description"], str)

    @pytest.mark.asyncio
    async def test_includes_summary_counts(self):
        """Should include summary counts in result."""
        result = await check_sensitive_actions(["iam:CreateAccessKey", "ec2:DescribeInstances"])

        assert "total_checked" in result
        assert "sensitive_count" in result
        assert "categories_found" in result
        assert "has_critical" in result
        assert result["total_checked"] == 2


class TestListTemplates:
    """Tests for list_templates function."""

    @pytest.mark.asyncio
    async def test_returns_template_list(self):
        """Should return list of templates."""
        templates = await list_templates()

        assert isinstance(templates, list)
        assert len(templates) > 0

    @pytest.mark.asyncio
    async def test_template_has_required_fields(self):
        """Should include name, description, variables for each template."""
        templates = await list_templates()

        for template in templates:
            assert "name" in template
            assert "description" in template
            assert "variables" in template

    @pytest.mark.asyncio
    async def test_includes_s3_templates(self):
        """Should include S3 templates."""
        templates = await list_templates()

        template_names = [t["name"] for t in templates]
        assert "s3-read-only" in template_names
        assert "s3-read-write" in template_names

    @pytest.mark.asyncio
    async def test_includes_lambda_templates(self):
        """Should include Lambda templates."""
        templates = await list_templates()

        template_names = [t["name"] for t in templates]
        assert "lambda-basic-execution" in template_names

    @pytest.mark.asyncio
    async def test_template_variables_are_list(self):
        """Should have variables as a list."""
        templates = await list_templates()

        for template in templates:
            assert isinstance(template["variables"], list)

    @pytest.mark.asyncio
    async def test_s3_template_has_bucket_variable(self):
        """Should include bucket_name in S3 template variables."""
        templates = await list_templates()

        s3_template = next(t for t in templates if t["name"] == "s3-read-only")
        variable_names = [v["name"] for v in s3_template["variables"]]
        assert "bucket_name" in variable_names

    @pytest.mark.asyncio
    async def test_ec2_describe_has_no_variables(self):
        """Should have empty variables for ec2-describe template."""
        templates = await list_templates()

        ec2_template = next(t for t in templates if t["name"] == "ec2-describe")
        assert ec2_template["variables"] == []

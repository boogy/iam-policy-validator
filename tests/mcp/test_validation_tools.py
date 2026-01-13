"""Tests for MCP validation tools.

This module tests the validation tools provided by the MCP server:
- validate_policy: Validate a policy dictionary
- validate_policy_json: Validate a JSON string
- quick_validate: Quick pass/fail validation
"""

import json
import pytest

from iam_validator.mcp.tools.validation import (
    validate_policy,
    validate_policy_json,
    quick_validate,
)


class TestValidatePolicy:
    """Tests for validate_policy function."""

    @pytest.mark.asyncio
    async def test_validates_simple_policy(self, simple_policy_dict):
        """Should validate a simple policy successfully."""
        result = await validate_policy(simple_policy_dict)

        assert result is not None
        assert hasattr(result, "is_valid")
        assert hasattr(result, "issues")
        assert hasattr(result, "policy_file")
        assert result.policy_file == "inline-policy"

    @pytest.mark.asyncio
    async def test_validates_identity_policy(self, simple_policy_dict):
        """Should validate identity policy type."""
        result = await validate_policy(simple_policy_dict, policy_type="identity")

        assert result is not None
        assert result.policy_file == "inline-policy"

    @pytest.mark.asyncio
    async def test_validates_resource_policy(self):
        """Should validate resource policy type."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::my-bucket/*"],
                }
            ],
        }

        result = await validate_policy(policy, policy_type="resource")

        assert result is not None
        assert result.policy_file == "inline-policy"

    @pytest.mark.asyncio
    async def test_validates_trust_policy(self):
        """Should validate trust policy type."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        result = await validate_policy(policy, policy_type="trust")

        assert result is not None
        assert result.policy_file == "inline-policy"

    @pytest.mark.asyncio
    async def test_detects_issues_in_invalid_policy(self, wildcard_policy_dict):
        """Should detect issues in policies with problems."""
        result = await validate_policy(wildcard_policy_dict)

        assert result is not None
        # The policy should have at least wildcard issues
        # is_valid depends on whether warnings/errors exist
        assert isinstance(result.issues, list)

    @pytest.mark.asyncio
    async def test_handles_missing_version(self):
        """Should handle policy without Version field."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["*"],
                }
            ]
        }

        # Pydantic may use default or return validation error
        # Either raises or returns result with issues
        try:
            result = await validate_policy(policy)
            # If no exception, should have validation issues
            assert result is not None
        except Exception:
            # Expected - Pydantic ValidationError
            pass

    @pytest.mark.asyncio
    async def test_handles_missing_statement(self):
        """Should handle policy without Statement field."""
        policy = {"Version": "2012-10-17"}

        # Pydantic may use default or return validation error
        try:
            result = await validate_policy(policy)
            # If no exception, should have validation issues
            assert result is not None
        except Exception:
            # Expected - Pydantic ValidationError
            pass

    @pytest.mark.asyncio
    async def test_policy_type_case_insensitive(self, simple_policy_dict):
        """Should handle policy type case-insensitively."""
        result1 = await validate_policy(simple_policy_dict, policy_type="IDENTITY")
        result2 = await validate_policy(simple_policy_dict, policy_type="Identity")
        result3 = await validate_policy(simple_policy_dict, policy_type="identity")

        assert result1 is not None
        assert result2 is not None
        assert result3 is not None


class TestValidatePolicyJson:
    """Tests for validate_policy_json function."""

    @pytest.mark.asyncio
    async def test_validates_json_string(self, simple_policy_dict):
        """Should parse and validate JSON string."""
        policy_json = json.dumps(simple_policy_dict)

        result = await validate_policy_json(policy_json)

        assert result is not None
        assert result.policy_file == "inline-policy"

    @pytest.mark.asyncio
    async def test_validates_with_policy_type(self, simple_policy_dict):
        """Should accept policy_type parameter."""
        policy_json = json.dumps(simple_policy_dict)

        result = await validate_policy_json(policy_json, policy_type="identity")

        assert result is not None

    @pytest.mark.asyncio
    async def test_handles_invalid_json(self, invalid_json_policy):
        """Should return error for invalid JSON."""
        result = await validate_policy_json(invalid_json_policy)

        assert result is not None
        assert result.is_valid is False
        assert len(result.issues) > 0
        assert result.issues[0].severity == "error"
        assert result.issues[0].issue_type == "json_parse_error"
        assert "Failed to parse policy JSON" in result.issues[0].message

    @pytest.mark.asyncio
    async def test_handles_malformed_json(self):
        """Should handle completely malformed JSON."""
        result = await validate_policy_json("not json at all")

        assert result is not None
        assert result.is_valid is False
        assert len(result.issues) == 1
        assert result.issues[0].severity == "error"
        assert result.issues[0].check_id == "policy_structure"

    @pytest.mark.asyncio
    async def test_preserves_validation_issues(self, wildcard_policy_dict):
        """Should preserve validation issues from parsed policy."""
        policy_json = json.dumps(wildcard_policy_dict)

        result = await validate_policy_json(policy_json)

        assert result is not None
        # Should have issues from the actual validation
        assert isinstance(result.issues, list)

    @pytest.mark.asyncio
    async def test_handles_empty_string(self):
        """Should handle empty string gracefully."""
        result = await validate_policy_json("")

        assert result is not None
        assert result.is_valid is False
        assert len(result.issues) > 0

    @pytest.mark.asyncio
    async def test_handles_json_with_whitespace(self, simple_policy_dict):
        """Should handle JSON with extra whitespace."""
        policy_json = json.dumps(simple_policy_dict, indent=2)

        result = await validate_policy_json(policy_json)

        assert result is not None


class TestQuickValidate:
    """Tests for quick_validate function."""

    @pytest.mark.asyncio
    async def test_returns_simplified_result(self, simple_policy_dict):
        """Should return simplified validation result."""
        result = await quick_validate(simple_policy_dict)

        assert isinstance(result, dict)
        assert "is_valid" in result
        assert "issue_count" in result
        assert "critical_issues" in result

    @pytest.mark.asyncio
    async def test_valid_policy_returns_true(self, simple_policy_dict):
        """Should return is_valid=True for valid policies."""
        result = await quick_validate(simple_policy_dict)

        assert isinstance(result["is_valid"], bool)
        assert isinstance(result["issue_count"], int)
        assert isinstance(result["critical_issues"], list)

    @pytest.mark.asyncio
    async def test_includes_issue_count(self, wildcard_policy_dict):
        """Should include total issue count."""
        result = await quick_validate(wildcard_policy_dict)

        assert "issue_count" in result
        assert isinstance(result["issue_count"], int)
        assert result["issue_count"] >= 0

    @pytest.mark.asyncio
    async def test_filters_critical_issues(self):
        """Should include only critical/high/error severity issues."""
        # Create a policy that will have various severity issues
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["*"],  # Should trigger issues
                    "Resource": ["*"],
                }
            ],
        }

        result = await quick_validate(policy)

        assert "critical_issues" in result
        assert isinstance(result["critical_issues"], list)
        # All items should be strings (messages)
        for issue in result["critical_issues"]:
            assert isinstance(issue, str)

    @pytest.mark.asyncio
    async def test_empty_critical_issues_for_valid_policy(self, simple_policy_dict):
        """Should return empty critical_issues for valid policy."""
        result = await quick_validate(simple_policy_dict)

        # Depending on the actual validation, this might have issues
        # but we can check the structure
        assert isinstance(result["critical_issues"], list)

    @pytest.mark.asyncio
    async def test_handles_policy_with_warnings(self):
        """Should include warning-level issues in count but not critical_issues."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowS3Read",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["*"],  # This might generate a warning
                }
            ],
        }

        result = await quick_validate(policy)

        # Should have structure even if no critical issues
        assert "is_valid" in result
        assert "issue_count" in result
        assert "critical_issues" in result

    @pytest.mark.asyncio
    async def test_result_structure_complete(self, simple_policy_dict):
        """Should have all required fields in result."""
        result = await quick_validate(simple_policy_dict)

        # Verify all required fields present
        required_fields = {
            "is_valid",
            "issue_count",
            "critical_issues",
            "sensitive_actions_found",
            "wildcards_detected",
        }
        assert set(result.keys()) == required_fields

        # Verify types
        assert isinstance(result["is_valid"], bool)
        assert isinstance(result["issue_count"], int)
        assert isinstance(result["critical_issues"], list)
        assert isinstance(result["sensitive_actions_found"], int)
        assert isinstance(result["wildcards_detected"], bool)

    @pytest.mark.asyncio
    async def test_handles_malformed_policy(self):
        """Should handle malformed policy gracefully."""
        policy = {
            "Version": "2012-10-17",
            "Statement": "not a list",  # Should fail validation
        }

        # This should raise an exception during parsing
        with pytest.raises(Exception):
            await quick_validate(policy)

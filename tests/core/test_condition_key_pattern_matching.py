"""Comprehensive tests for condition key pattern matching.

These tests ensure that condition keys with tag-key placeholders (e.g.,
aws:ResourceTag/${TagKey}) are correctly matched against user-provided condition
keys, including compound tag keys containing forward slashes (e.g., team/owner).

This test file was created after discovering that multiple checks used exact ``in``
lookups against service_detail.condition_keys dicts, which only contain pattern
keys like ``aws:ResourceTag/${TagKey}``. User-provided keys like
``aws:ResourceTag/team/owner`` would silently fail to match.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.aws_service.validators import (
    _is_valid_tag_key,
    condition_key_in_list,
    find_matching_condition_key,
)
from iam_validator.core.models import ConditionKey

# =============================================================================
# Unit tests: condition_key_in_list
# =============================================================================


class TestConditionKeyInList:
    """Tests for condition_key_in_list with focus on compound tag keys."""

    def test_exact_match(self):
        assert condition_key_in_list("ssm:Overwrite", ["ssm:Overwrite", "ssm:Recursive"])

    def test_exact_match_not_found(self):
        assert not condition_key_in_list("ssm:Missing", ["ssm:Overwrite"])

    def test_no_slash_never_matches_patterns(self):
        assert not condition_key_in_list("aws:SourceIp", ["aws:ResourceTag/${TagKey}"])

    # --- Simple tag keys ---

    def test_simple_tag_key_matches_dollar_brace_pattern(self):
        assert condition_key_in_list("aws:ResourceTag/owner", ["aws:ResourceTag/${TagKey}"])

    def test_simple_tag_key_matches_angle_bracket_pattern(self):
        assert condition_key_in_list("s3:ExistingObjectTag/Team", ["s3:ExistingObjectTag/<key>"])

    def test_simple_tag_key_matches_literal_placeholder(self):
        assert condition_key_in_list("ssm:resourceTag/owner", ["ssm:resourceTag/tag-key"])

    # --- Compound tag keys (the critical regression tests) ---

    def test_compound_tag_key_single_slash(self):
        """aws:ResourceTag/team/owner must match aws:ResourceTag/${TagKey}."""
        assert condition_key_in_list("aws:ResourceTag/team/owner", ["aws:ResourceTag/${TagKey}"])

    def test_compound_tag_key_multiple_slashes(self):
        """Tag keys with multiple slashes must still match."""
        assert condition_key_in_list("aws:RequestTag/dept/env/role", ["aws:RequestTag/${TagKey}"])

    def test_compound_tag_key_service_specific(self):
        assert condition_key_in_list("ssm:resourceTag/org/team", ["ssm:resourceTag/tag-key"])

    def test_compound_tag_key_s3_existing_object_tag(self):
        assert condition_key_in_list("s3:ExistingObjectTag/ns/key", ["s3:ExistingObjectTag/<key>"])

    # --- Cross-prefix must NOT match ---

    def test_resource_tag_does_not_match_request_tag(self):
        assert not condition_key_in_list("aws:ResourceTag/team/owner", ["aws:RequestTag/${TagKey}"])

    def test_request_tag_does_not_match_resource_tag(self):
        assert not condition_key_in_list("aws:RequestTag/env", ["aws:ResourceTag/${TagKey}"])

    def test_different_service_prefix_no_match(self):
        assert not condition_key_in_list("ssm:resourceTag/team", ["ec2:ResourceTag/${TagKey}"])

    # --- Edge cases ---

    def test_empty_tag_key_rejected(self):
        """aws:ResourceTag/ (empty tag key) must NOT match."""
        assert not condition_key_in_list("aws:ResourceTag/", ["aws:ResourceTag/${TagKey}"])

    def test_invalid_tag_key_chars_rejected(self):
        """Tag keys with invalid chars must NOT match."""
        assert not condition_key_in_list("aws:ResourceTag/key<bad>", ["aws:ResourceTag/${TagKey}"])
        assert not condition_key_in_list("aws:ResourceTag/key*wild", ["aws:ResourceTag/${TagKey}"])

    def test_tag_key_at_max_length(self):
        """Tag key at exactly 128 chars (max allowed) must match."""
        long_key = "a" * 128
        assert condition_key_in_list(f"aws:ResourceTag/{long_key}", ["aws:ResourceTag/${TagKey}"])

    def test_tag_key_over_max_length_rejected(self):
        """Tag key at 129 chars (over max) must NOT match."""
        long_key = "a" * 129
        assert not condition_key_in_list(f"aws:ResourceTag/{long_key}", ["aws:ResourceTag/${TagKey}"])

    def test_tag_key_with_all_special_chars(self):
        """Tag keys with spaces, +, -, =, ., _, :, /, @ are all valid."""
        assert condition_key_in_list("aws:ResourceTag/key with spaces", ["aws:ResourceTag/${TagKey}"])
        assert condition_key_in_list("aws:ResourceTag/key+value", ["aws:ResourceTag/${TagKey}"])
        assert condition_key_in_list("aws:ResourceTag/key=value", ["aws:ResourceTag/${TagKey}"])
        assert condition_key_in_list("aws:ResourceTag/key.value", ["aws:ResourceTag/${TagKey}"])
        assert condition_key_in_list("aws:ResourceTag/key_value", ["aws:ResourceTag/${TagKey}"])
        assert condition_key_in_list("aws:ResourceTag/key:value", ["aws:ResourceTag/${TagKey}"])
        assert condition_key_in_list("aws:ResourceTag/key@value", ["aws:ResourceTag/${TagKey}"])

    def test_empty_pattern_list(self):
        assert not condition_key_in_list("aws:ResourceTag/owner", [])

    def test_pattern_without_slash_ignored(self):
        """Patterns without '/' should not match keys with '/'."""
        assert not condition_key_in_list("aws:ResourceTag/owner", ["aws:SourceIp"])


# =============================================================================
# Unit tests: find_matching_condition_key
# =============================================================================


class TestFindMatchingConditionKey:
    """Tests for find_matching_condition_key (dict lookup that returns the pattern key)."""

    def test_exact_match_returns_key(self):
        keys = {"aws:SourceIp": MagicMock(), "aws:ResourceTag/${TagKey}": MagicMock()}
        assert find_matching_condition_key("aws:SourceIp", keys) == "aws:SourceIp"

    def test_pattern_match_returns_pattern(self):
        keys = {"aws:ResourceTag/${TagKey}": MagicMock()}
        assert find_matching_condition_key("aws:ResourceTag/owner", keys) == "aws:ResourceTag/${TagKey}"

    def test_compound_tag_key_returns_pattern(self):
        keys = {"aws:ResourceTag/${TagKey}": MagicMock()}
        assert find_matching_condition_key("aws:ResourceTag/team/owner", keys) == "aws:ResourceTag/${TagKey}"

    def test_multiple_slashes_returns_pattern(self):
        keys = {"aws:RequestTag/${TagKey}": MagicMock()}
        assert find_matching_condition_key("aws:RequestTag/a/b/c", keys) == "aws:RequestTag/${TagKey}"

    def test_no_match_returns_none(self):
        keys = {"aws:ResourceTag/${TagKey}": MagicMock()}
        assert find_matching_condition_key("aws:SourceIp", keys) is None

    def test_wrong_prefix_returns_none(self):
        keys = {"aws:ResourceTag/${TagKey}": MagicMock()}
        assert find_matching_condition_key("aws:RequestTag/owner", keys) is None

    def test_empty_dict_returns_none(self):
        assert find_matching_condition_key("aws:ResourceTag/owner", {}) is None

    def test_empty_tag_key_returns_none(self):
        keys = {"aws:ResourceTag/${TagKey}": MagicMock()}
        assert find_matching_condition_key("aws:ResourceTag/", keys) is None

    def test_service_specific_pattern(self):
        keys = {"ssm:resourceTag/tag-key": MagicMock(), "ssm:Overwrite": MagicMock()}
        assert find_matching_condition_key("ssm:resourceTag/ns/key", keys) == "ssm:resourceTag/tag-key"

    def test_caller_can_get_metadata_from_matched_key(self):
        """Verify the intended usage: look up type info from the matched pattern."""
        cond_key_obj = ConditionKey(Name="aws:ResourceTag/${TagKey}", Types=["String"])
        keys = {"aws:ResourceTag/${TagKey}": cond_key_obj}
        matched = find_matching_condition_key("aws:ResourceTag/team/owner", keys)
        assert matched is not None
        assert keys[matched].types == ["String"]


# =============================================================================
# Unit tests: _is_valid_tag_key (allowed characters)
# =============================================================================


class TestIsValidTagKey:
    """Ensure tag key validation covers the full AWS allowed character set."""

    @pytest.mark.parametrize(
        "tag_key",
        [
            "owner",
            "Environment",
            "cost-center",
            "Cost Center",
            "key/with/slashes",
            "key+plus",
            "key=equals",
            "key.dot",
            "key_under",
            "key:colon",
            "key@at",
            "a",
            "a" * 128,
        ],
    )
    def test_valid_tag_keys(self, tag_key):
        assert _is_valid_tag_key(tag_key)

    @pytest.mark.parametrize(
        "tag_key",
        [
            "",
            "a" * 129,
            "key<angle",
            "key>angle",
            "key*star",
            "key?question",
            "key#hash",
            "key$dollar",
            "key%percent",
            "key{brace",
            "key}brace",
            "key|pipe",
            "key\\backslash",
            "key~tilde",
            "key`backtick",
        ],
    )
    def test_invalid_tag_keys(self, tag_key):
        assert not _is_valid_tag_key(tag_key)


# =============================================================================
# Integration: condition_type_mismatch with compound tag keys
# =============================================================================


class TestConditionTypeMismatchPatternMatching:
    """Test that condition_type_mismatch resolves types for compound tag keys."""

    @pytest.mark.asyncio
    async def test_simple_tag_key_type_resolved(self):
        """aws:ResourceTag/owner should resolve to String type."""
        from iam_validator.checks.condition_type_mismatch import ConditionTypeMismatchCheck

        check = ConditionTypeMismatchCheck()
        async with AWSServiceFetcher() as fetcher:
            key_type = await check._get_condition_key_type(
                fetcher, "aws:ResourceTag/owner", ["events:DeleteEventBus"], ["*"]
            )
        assert key_type == "String"

    @pytest.mark.asyncio
    async def test_compound_tag_key_type_resolved(self):
        """aws:ResourceTag/team/owner must also resolve to String type."""
        from iam_validator.checks.condition_type_mismatch import ConditionTypeMismatchCheck

        check = ConditionTypeMismatchCheck()
        async with AWSServiceFetcher() as fetcher:
            key_type = await check._get_condition_key_type(
                fetcher, "aws:ResourceTag/team/owner", ["events:DeleteEventBus"], ["*"]
            )
        assert key_type == "String"

    @pytest.mark.asyncio
    async def test_request_tag_compound_key_type_resolved(self):
        """aws:RequestTag/dept/env should resolve to String for actions that support it."""
        from iam_validator.checks.condition_type_mismatch import ConditionTypeMismatchCheck

        check = ConditionTypeMismatchCheck()
        async with AWSServiceFetcher() as fetcher:
            key_type = await check._get_condition_key_type(
                fetcher, "aws:RequestTag/dept/env", ["iam:CreateRole"], ["*"]
            )
        assert key_type == "String"

    @pytest.mark.asyncio
    async def test_unsupported_tag_key_returns_none(self):
        """A condition key with no matching pattern in any service should return None."""
        from iam_validator.checks.condition_type_mismatch import ConditionTypeMismatchCheck

        check = ConditionTypeMismatchCheck()
        async with AWSServiceFetcher() as fetcher:
            # Use a completely fabricated condition key that no service defines
            key_type = await check._get_condition_key_type(
                fetcher, "custom:NonExistentTag/team/owner", ["sts:GetCallerIdentity"], ["*"]
            )
        assert key_type is None

    @pytest.mark.asyncio
    async def test_type_resolution_with_mock_service_detail(self):
        """Test with mock to verify find_matching_condition_key is called correctly."""
        from iam_validator.checks.condition_type_mismatch import ConditionTypeMismatchCheck

        check = ConditionTypeMismatchCheck()

        fetcher = MagicMock()
        fetcher.parse_action = MagicMock(return_value=("events", "DeleteEventBus"))

        action_detail = MagicMock()
        action_detail.action_condition_keys = []
        action_detail.resources = [{"Name": "event-bus"}]

        resource_type = MagicMock()
        resource_type.condition_keys = ["aws:ResourceTag/${TagKey}"]

        service_detail = MagicMock()
        service_detail.condition_keys = {
            "aws:ResourceTag/${TagKey}": ConditionKey(
                Name="aws:ResourceTag/${TagKey}", Types=["String"]
            ),
        }
        service_detail.actions = {"DeleteEventBus": action_detail}
        service_detail.resources = {"event-bus": resource_type}
        fetcher.fetch_service_by_name = AsyncMock(return_value=service_detail)

        key_type = await check._get_condition_key_type(
            fetcher, "aws:ResourceTag/team/owner", ["events:DeleteEventBus"], ["*"]
        )
        assert key_type == "String"


# =============================================================================
# Integration: set_operator_validation with compound tag keys
# =============================================================================


class TestSetOperatorValidationPatternMatching:
    """Test that set_operator_validation resolves types for compound tag keys."""

    @pytest.mark.asyncio
    async def test_arrayofstring_compound_tag_key_with_mock(self):
        """Mock service with ArrayOfString tag pattern — compound key must resolve."""
        from iam_validator.checks.set_operator_validation import SetOperatorValidationCheck

        check = SetOperatorValidationCheck()

        fetcher = MagicMock()
        fetcher.parse_action = MagicMock(return_value=("svc", "DoThing"))
        service_detail = MagicMock()
        service_detail.condition_keys = {
            "svc:tag/${TagKey}": ConditionKey(
                Name="svc:tag/${TagKey}", Types=["ArrayOfString"]
            ),
        }
        fetcher.fetch_service_by_name = AsyncMock(return_value=service_detail)

        result = await check._is_multivalued_key(
            "svc:tag/team/owner", fetcher, ["svc:DoThing"]
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_string_type_compound_tag_key_is_single_valued(self):
        """Compound tag key with String type (not ArrayOfString) is still single-valued."""
        from iam_validator.checks.set_operator_validation import SetOperatorValidationCheck

        check = SetOperatorValidationCheck()

        fetcher = MagicMock()
        fetcher.parse_action = MagicMock(return_value=("events", "DeleteEventBus"))
        service_detail = MagicMock()
        service_detail.condition_keys = {
            "aws:ResourceTag/${TagKey}": ConditionKey(
                Name="aws:ResourceTag/${TagKey}", Types=["String"]
            ),
        }
        fetcher.fetch_service_by_name = AsyncMock(return_value=service_detail)

        result = await check._is_multivalued_key(
            "aws:ResourceTag/team/owner", fetcher, ["events:DeleteEventBus"]
        )
        assert result is False


# =============================================================================
# Integration: wildcard_resource ABAC with compound tag keys
# =============================================================================


class TestWildcardResourceCompoundTagKeys:
    """Test wildcard_resource ABAC detection with compound tag keys."""

    @pytest.fixture
    def check(self):
        from iam_validator.checks.wildcard_resource import WildcardResourceCheck

        return WildcardResourceCheck()

    @pytest.fixture
    def config(self):
        from iam_validator.core.check_registry import CheckConfig

        return CheckConfig(check_id="wildcard_resource", enabled=True, config={})

    @pytest.fixture
    async def fetcher(self):
        async with AWSServiceFetcher(prefetch_common=False) as f:
            yield f

    @pytest.mark.asyncio
    async def test_compound_resource_tag_lowers_severity(self, check, fetcher, config):
        """aws:ResourceTag/team/owner with events:DeleteEventBus should lower severity."""
        from iam_validator.core.models import Statement

        statement = Statement(
            Effect="Allow",
            Action=["events:DeleteEventBus"],
            Resource=["*"],
            Condition={"StringEquals": {"aws:ResourceTag/team/owner": "my-team"}},
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        assert "ABAC" in issues[0].message

    @pytest.mark.asyncio
    async def test_compound_request_tag_lowers_severity(self, check, fetcher, config):
        """aws:RequestTag/org/team with sqs:CreateQueue should lower severity."""
        from iam_validator.core.models import Statement

        statement = Statement(
            Effect="Allow",
            Action=["sqs:CreateQueue"],
            Resource=["*"],
            Condition={
                "StringEquals": {"aws:RequestTag/org/team": "${aws:PrincipalTag/org/team}"},
                "Null": {"aws:RequestTag/org/team": "false"},
            },
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "low"
        assert "ABAC" in issues[0].message


# =============================================================================
# Backward compatibility: CheckDocumentation
# =============================================================================


class TestCheckDocumentationBackwardCompatibility:
    """Ensure CheckDocumentation works with and without short_description."""

    def test_with_all_fields(self):
        from iam_validator.core.config.check_documentation import CheckDocumentation

        doc = CheckDocumentation(
            check_id="test",
            short_description="Test Check",
            risk_explanation="Risk",
            documentation_url="https://example.com",
            remediation_steps=["Step 1"],
            risk_category="validation",
        )
        assert doc.short_description == "Test Check"

    def test_without_short_description(self):
        """Custom checks written against older API must still work."""
        from iam_validator.core.config.check_documentation import CheckDocumentation

        doc = CheckDocumentation(
            check_id="custom_check",
            risk_explanation="Some risk",
            documentation_url="https://example.com",
        )
        assert doc.short_description == ""
        assert doc.check_id == "custom_check"

    def test_without_optional_fields(self):
        """Minimal construction with only required fields."""
        from iam_validator.core.config.check_documentation import CheckDocumentation

        doc = CheckDocumentation(
            check_id="minimal",
            risk_explanation="Risk",
            documentation_url="https://example.com",
        )
        assert doc.remediation_steps == []
        assert doc.risk_category is None
        assert doc.short_description == ""

    def test_registry_get_short_description_returns_none_for_empty(self):
        """get_short_description should return None when short_description is empty."""
        from iam_validator.core.config.check_documentation import (
            CheckDocumentation,
            CheckDocumentationRegistry,
        )

        CheckDocumentationRegistry.register(
            CheckDocumentation(
                check_id="_test_empty_desc",
                risk_explanation="Risk",
                documentation_url="https://example.com",
            )
        )
        assert CheckDocumentationRegistry.get_short_description("_test_empty_desc") is None

    def test_registry_get_short_description_returns_value_when_set(self):
        from iam_validator.core.config.check_documentation import (
            CheckDocumentation,
            CheckDocumentationRegistry,
        )

        CheckDocumentationRegistry.register(
            CheckDocumentation(
                check_id="_test_with_desc",
                risk_explanation="Risk",
                documentation_url="https://example.com",
                short_description="My Check",
            )
        )
        assert CheckDocumentationRegistry.get_short_description("_test_with_desc") == "My Check"

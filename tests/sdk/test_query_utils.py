"""Tests for SDK query utilities."""

import pytest

from iam_validator.sdk.query_utils import (
    get_actions_by_access_level,
    get_actions_supporting_condition,
    get_wildcard_only_actions,
    query_action_details,
    query_actions,
    query_arn_format,
    query_arn_formats,
    query_arn_types,
    query_condition_key,
    query_condition_keys,
)

# ---------------------------------------------------------------------------
# query_actions
# ---------------------------------------------------------------------------


class TestQueryActions:
    """Tests for query_actions()."""

    async def test_all_actions(self, mock_fetcher):
        actions = await query_actions(mock_fetcher, "s3")
        assert len(actions) == 5
        action_names = [a["action"] for a in actions]
        assert "s3:GetObject" in action_names
        assert "s3:PutObject" in action_names

    async def test_action_dict_shape(self, mock_fetcher):
        actions = await query_actions(mock_fetcher, "s3")
        for action in actions:
            assert "action" in action
            assert "access_level" in action
            assert "description" in action

    async def test_filter_by_access_level_write(self, mock_fetcher):
        actions = await query_actions(mock_fetcher, "s3", access_level="write")
        action_names = [a["action"] for a in actions]
        assert "s3:PutObject" in action_names
        assert "s3:DeleteBucket" in action_names
        # GetObject is read, should be excluded
        assert "s3:GetObject" not in action_names

    async def test_filter_by_access_level_list(self, mock_fetcher):
        actions = await query_actions(mock_fetcher, "s3", access_level="list")
        action_names = [a["action"] for a in actions]
        assert "s3:ListBuckets" in action_names
        assert len(action_names) == 1

    async def test_filter_by_access_level_permissions_management(self, mock_fetcher):
        actions = await query_actions(mock_fetcher, "s3", access_level="permissions-management")
        action_names = [a["action"] for a in actions]
        assert "s3:PutBucketPolicy" in action_names

    async def test_filter_by_resource_type(self, mock_fetcher):
        actions = await query_actions(mock_fetcher, "s3", resource_type="bucket")
        action_names = [a["action"] for a in actions]
        assert "s3:DeleteBucket" in action_names
        # GetObject uses "object", not "bucket"
        assert "s3:GetObject" not in action_names

    async def test_filter_wildcard_only(self, mock_fetcher):
        actions = await query_actions(mock_fetcher, "s3", resource_type="*")
        action_names = [a["action"] for a in actions]
        # ListBuckets has no resources
        assert "s3:ListBuckets" in action_names
        # Actions with resources should be excluded
        assert "s3:GetObject" not in action_names

    async def test_filter_by_condition(self, mock_fetcher):
        actions = await query_actions(mock_fetcher, "s3", condition="s3:x-amz-acl")
        action_names = [a["action"] for a in actions]
        assert "s3:GetObject" in action_names
        assert "s3:PutObject" in action_names
        # ListBuckets has no condition keys
        assert "s3:ListBuckets" not in action_names

    async def test_no_matching_actions(self, mock_fetcher):
        actions = await query_actions(mock_fetcher, "s3", condition="nonexistent:key")
        assert actions == []


# ---------------------------------------------------------------------------
# query_action_details
# ---------------------------------------------------------------------------


class TestQueryActionDetails:
    """Tests for query_action_details()."""

    async def test_valid_action(self, mock_fetcher):
        details = await query_action_details(mock_fetcher, "s3", "GetObject")
        assert details["service"] == "s3"
        assert details["action"] == "GetObject"
        assert "access_level" in details
        assert "resource_types" in details
        assert "condition_keys" in details

    async def test_case_insensitive_lookup(self, mock_fetcher):
        details = await query_action_details(mock_fetcher, "s3", "getobject")
        assert details["action"] == "GetObject"

    async def test_invalid_action_raises(self, mock_fetcher):
        with pytest.raises(ValueError, match="not found"):
            await query_action_details(mock_fetcher, "s3", "NonexistentAction")


# ---------------------------------------------------------------------------
# query_arn_formats / query_arn_types / query_arn_format
# ---------------------------------------------------------------------------


class TestQueryArnFunctions:
    """Tests for ARN query functions."""

    async def test_query_arn_formats(self, mock_fetcher):
        formats = await query_arn_formats(mock_fetcher, "s3")
        assert len(formats) >= 2  # bucket + object
        assert any("BucketName" in f for f in formats)

    async def test_query_arn_types(self, mock_fetcher):
        types = await query_arn_types(mock_fetcher, "s3")
        type_names = [t["resource_type"] for t in types]
        assert "bucket" in type_names
        assert "object" in type_names
        for t in types:
            assert "arn_formats" in t

    async def test_query_arn_format_valid(self, mock_fetcher):
        details = await query_arn_format(mock_fetcher, "s3", "bucket")
        assert details["service"] == "s3"
        assert details["resource_type"] == "bucket"
        assert len(details["arn_formats"]) >= 1
        assert "condition_keys" in details

    async def test_query_arn_format_case_insensitive(self, mock_fetcher):
        details = await query_arn_format(mock_fetcher, "s3", "Bucket")
        assert details["resource_type"] == "bucket"

    async def test_query_arn_format_invalid_raises(self, mock_fetcher):
        with pytest.raises(ValueError, match="not found"):
            await query_arn_format(mock_fetcher, "s3", "nonexistent")


# ---------------------------------------------------------------------------
# query_condition_keys / query_condition_key
# ---------------------------------------------------------------------------


class TestQueryConditionKeys:
    """Tests for condition key query functions."""

    async def test_query_all_condition_keys(self, mock_fetcher):
        keys = await query_condition_keys(mock_fetcher, "s3")
        key_names = [k["condition_key"] for k in keys]
        assert "s3:x-amz-acl" in key_names
        assert "s3:prefix" in key_names
        for k in keys:
            assert "description" in k
            assert "types" in k

    async def test_query_specific_condition_key(self, mock_fetcher):
        details = await query_condition_key(mock_fetcher, "s3", "s3:prefix")
        assert details["condition_key"] == "s3:prefix"
        assert details["service"] == "s3"
        assert "types" in details

    async def test_query_condition_key_case_insensitive(self, mock_fetcher):
        details = await query_condition_key(mock_fetcher, "s3", "S3:Prefix")
        assert details["condition_key"] == "s3:prefix"

    async def test_query_condition_key_invalid_raises(self, mock_fetcher):
        with pytest.raises(ValueError, match="not found"):
            await query_condition_key(mock_fetcher, "s3", "nonexistent:key")


# ---------------------------------------------------------------------------
# get_actions_by_access_level
# ---------------------------------------------------------------------------


class TestGetActionsByAccessLevel:
    """Tests for get_actions_by_access_level()."""

    async def test_returns_action_names(self, mock_fetcher):
        actions = await get_actions_by_access_level(mock_fetcher, "s3", "write")
        assert isinstance(actions, list)
        assert all(isinstance(a, str) for a in actions)
        assert "s3:PutObject" in actions

    async def test_empty_for_no_match(self, mock_fetcher):
        # "tagging" — our mock has no tagging actions
        actions = await get_actions_by_access_level(mock_fetcher, "s3", "tagging")
        assert actions == []


# ---------------------------------------------------------------------------
# get_wildcard_only_actions
# ---------------------------------------------------------------------------


class TestGetWildcardOnlyActions:
    """Tests for get_wildcard_only_actions()."""

    async def test_returns_wildcard_only(self, mock_fetcher):
        actions = await get_wildcard_only_actions(mock_fetcher, "s3")
        assert "s3:ListBuckets" in actions
        assert "s3:GetObject" not in actions


# ---------------------------------------------------------------------------
# get_actions_supporting_condition
# ---------------------------------------------------------------------------


class TestGetActionsSupportingCondition:
    """Tests for get_actions_supporting_condition()."""

    async def test_matching_condition(self, mock_fetcher):
        actions = await get_actions_supporting_condition(mock_fetcher, "s3", "s3:x-amz-acl")
        assert "s3:GetObject" in actions
        assert "s3:PutObject" in actions

    async def test_no_matching_condition(self, mock_fetcher):
        actions = await get_actions_supporting_condition(mock_fetcher, "s3", "nonexistent:key")
        assert actions == []

"""Tests for AWS fetcher wildcard action validation."""

import pytest

from iam_validator.core.aws_service import AWSServiceFetcher


class TestWildcardMatching:
    """Test suite for wildcard pattern matching in actions."""

    @pytest.fixture
    def fetcher(self):
        """Create an AWSServiceFetcher instance."""
        return AWSServiceFetcher()

    def test_match_wildcard_action_prefix(self, fetcher):
        """Test prefix wildcard pattern (e.g., Get*)."""
        actions = [
            "GetObject",
            "GetObjectAcl",
            "GetObjectAttributes",
            "PutObject",
            "ListBuckets",
        ]

        has_matches, matched = fetcher.match_wildcard_action("Get*", actions)

        assert has_matches is True
        assert len(matched) == 3
        assert "GetObject" in matched
        assert "GetObjectAcl" in matched
        assert "GetObjectAttributes" in matched
        assert "PutObject" not in matched
        assert "ListBuckets" not in matched

    def test_match_wildcard_action_suffix(self, fetcher):
        """Test suffix wildcard pattern (e.g., *Object)."""
        actions = [
            "GetObject",
            "PutObject",
            "DeleteObject",
            "GetObjectAcl",
            "ListBuckets",
        ]

        has_matches, matched = fetcher.match_wildcard_action("*Object", actions)

        assert has_matches is True
        assert len(matched) == 3
        assert "GetObject" in matched
        assert "PutObject" in matched
        assert "DeleteObject" in matched
        assert "GetObjectAcl" not in matched
        assert "ListBuckets" not in matched

    def test_match_wildcard_action_middle(self, fetcher):
        """Test middle wildcard pattern (e.g., Get*Acl)."""
        actions = [
            "GetObjectAcl",
            "GetBucketAcl",
            "PutObjectAcl",
            "GetObject",
            "ListBuckets",
        ]

        has_matches, matched = fetcher.match_wildcard_action("Get*Acl", actions)

        assert has_matches is True
        assert len(matched) == 2
        assert "GetObjectAcl" in matched
        assert "GetBucketAcl" in matched
        assert "PutObjectAcl" not in matched
        assert "GetObject" not in matched

    def test_match_wildcard_action_multiple_wildcards(self, fetcher):
        """Test multiple wildcard pattern (e.g., *Get*Object*)."""
        actions = [
            "GetObject",
            "GetObjectAcl",
            "GetObjectAttributes",
            "DescribeGetObjectResults",
            "PutObject",
            "ListBuckets",
        ]

        has_matches, matched = fetcher.match_wildcard_action("*Get*Object*", actions)

        assert has_matches is True
        assert len(matched) == 4
        assert "GetObject" in matched
        assert "GetObjectAcl" in matched
        assert "GetObjectAttributes" in matched
        assert "DescribeGetObjectResults" in matched
        assert "PutObject" not in matched
        assert "ListBuckets" not in matched

    def test_match_wildcard_action_no_matches(self, fetcher):
        """Test wildcard pattern with no matches."""
        actions = [
            "GetObject",
            "PutObject",
            "DeleteObject",
        ]

        has_matches, matched = fetcher.match_wildcard_action("List*", actions)

        assert has_matches is False
        assert len(matched) == 0

    def test_match_wildcard_action_case_insensitive(self, fetcher):
        """Test wildcard matching is case-insensitive."""
        actions = [
            "GetObject",
            "getobject",
            "GETOBJECT",
            "GetOBJECT",
        ]

        has_matches, matched = fetcher.match_wildcard_action("get*", actions)

        assert has_matches is True
        assert len(matched) == 4

    def test_match_wildcard_action_special_chars(self, fetcher):
        """Test wildcard with special regex characters in action names."""
        actions = [
            "Get-Object",
            "Get_Object",
            "Get.Object",
            "Get[Object]",
            "Get(Object)",
        ]

        has_matches, matched = fetcher.match_wildcard_action("Get-*", actions)

        assert has_matches is True
        assert len(matched) == 1
        assert "Get-Object" in matched

    def test_match_wildcard_action_full_wildcard(self, fetcher):
        """Test full wildcard pattern matches everything."""
        actions = [
            "GetObject",
            "PutObject",
            "DeleteObject",
        ]

        has_matches, matched = fetcher.match_wildcard_action("*", actions)

        assert has_matches is True
        assert len(matched) == 3

    def test_match_wildcard_action_exact_match(self, fetcher):
        """Test pattern without wildcards matches exactly."""
        actions = [
            "GetObject",
            "GetObjectAcl",
            "PutObject",
        ]

        # Without wildcard, should match exact only
        has_matches, matched = fetcher.match_wildcard_action("GetObject", actions)

        assert has_matches is True
        assert len(matched) == 1
        assert "GetObject" in matched

    def test_match_wildcard_action_empty_list(self, fetcher):
        """Test wildcard pattern with empty action list."""
        actions = []

        has_matches, matched = fetcher.match_wildcard_action("Get*", actions)

        assert has_matches is False
        assert len(matched) == 0


class TestActionValidationWithWildcards:
    """Integration tests for action validation with wildcards."""

    @pytest.mark.asyncio
    async def test_validate_s3_get_wildcard(self):
        """Test validation of s3:Get* wildcard pattern."""
        async with AWSServiceFetcher() as fetcher:
            is_valid, error_msg, is_wildcard = await fetcher.validate_action("s3:Get*")

            assert is_valid is True
            assert error_msg is None
            assert is_wildcard is True

    @pytest.mark.asyncio
    async def test_validate_ec2_describe_wildcard(self):
        """Test validation of ec2:Describe* wildcard pattern."""
        async with AWSServiceFetcher() as fetcher:
            is_valid, error_msg, is_wildcard = await fetcher.validate_action("ec2:Describe*")

            assert is_valid is True
            assert error_msg is None
            assert is_wildcard is True

    @pytest.mark.asyncio
    async def test_validate_invalid_wildcard_pattern(self):
        """Test validation of wildcard pattern that matches no actions."""
        async with AWSServiceFetcher() as fetcher:
            is_valid, error_msg, is_wildcard = await fetcher.validate_action("s3:InvalidPrefix*")

            assert is_valid is False
            assert "does not match any actions" in error_msg
            assert is_wildcard is True

    @pytest.mark.asyncio
    async def test_validate_exact_action_vs_wildcard(self):
        """Test that exact actions don't return is_wildcard=True."""
        async with AWSServiceFetcher() as fetcher:
            # Exact action
            is_valid, error_msg, is_wildcard = await fetcher.validate_action("s3:GetObject")

            assert is_valid is True
            assert error_msg is None
            assert is_wildcard is False

    @pytest.mark.asyncio
    async def test_validate_full_wildcard(self):
        """Test validation of full wildcard (service:*)."""
        async with AWSServiceFetcher() as fetcher:
            is_valid, error_msg, is_wildcard = await fetcher.validate_action("s3:*")

            assert is_valid is True
            assert error_msg is None
            assert is_wildcard is True

    @pytest.mark.asyncio
    async def test_validate_wildcard_case_variations(self):
        """Test wildcard patterns work with different cases."""
        async with AWSServiceFetcher() as fetcher:
            # Lower case pattern
            is_valid, _, is_wildcard = await fetcher.validate_action("s3:get*")
            assert is_valid is True
            assert is_wildcard is True

            # Upper case pattern
            is_valid, _, is_wildcard = await fetcher.validate_action("s3:GET*")
            assert is_valid is True
            assert is_wildcard is True

            # Mixed case pattern
            is_valid, _, is_wildcard = await fetcher.validate_action("s3:GeT*")
            assert is_valid is True
            assert is_wildcard is True

    @pytest.mark.asyncio
    async def test_validate_wildcard_with_disallow(self):
        """Test wildcard validation when wildcards are not allowed."""
        async with AWSServiceFetcher() as fetcher:
            is_valid, error_msg, is_wildcard = await fetcher.validate_action(
                "s3:Get*", allow_wildcards=False
            )

            assert is_valid is False
            assert "Wildcard actions are not allowed" in error_msg
            assert is_wildcard is True

    @pytest.mark.asyncio
    async def test_validate_suffix_wildcard(self):
        """Test validation of suffix wildcard pattern."""
        async with AWSServiceFetcher() as fetcher:
            is_valid, error_msg, is_wildcard = await fetcher.validate_action("s3:*Object")

            assert is_valid is True
            assert error_msg is None
            assert is_wildcard is True

    @pytest.mark.asyncio
    async def test_validate_middle_wildcard(self):
        """Test validation of middle wildcard pattern."""
        async with AWSServiceFetcher() as fetcher:
            is_valid, error_msg, is_wildcard = await fetcher.validate_action("s3:*Object*")

            assert is_valid is True
            assert error_msg is None
            assert is_wildcard is True

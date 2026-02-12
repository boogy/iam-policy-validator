"""Tests for SDK ARN matching utilities."""

from iam_validator.sdk.arn_matching import (
    arn_matches,
    arn_strictly_valid,
    convert_aws_pattern_to_wildcard,
    is_glob_match,
)

# ---------------------------------------------------------------------------
# is_glob_match
# ---------------------------------------------------------------------------


class TestIsGlobMatch:
    """Tests for the generic glob-matching function."""

    def test_exact_match(self):
        assert is_glob_match("hello", "hello") is True

    def test_no_match(self):
        assert is_glob_match("hello", "world") is False

    def test_wildcard_matches_anything(self):
        assert is_glob_match("*", "anything") is True

    def test_both_wildcards(self):
        assert is_glob_match("*", "*") is True

    def test_prefix_wildcard(self):
        assert is_glob_match("test*", "test123") is True

    def test_prefix_wildcard_no_match(self):
        assert is_glob_match("test*", "other") is False

    def test_suffix_wildcard(self):
        assert is_glob_match("*test", "mytest") is True

    def test_middle_wildcard(self):
        assert is_glob_match("a*c", "abc") is True
        assert is_glob_match("a*c", "axyzc") is True

    def test_wildcard_slash_vs_no_slash(self):
        assert is_glob_match("*/*", "mybucket") is False

    def test_wildcard_slash_match(self):
        assert is_glob_match("*/*", "*personalize*") is True

    def test_both_strings_wildcarded(self):
        assert is_glob_match("*mybucket", "*myotherthing") is False

    def test_empty_strings(self):
        assert is_glob_match("", "") is True

    def test_one_empty(self):
        assert is_glob_match("", "a") is False
        assert is_glob_match("a", "") is False

    def test_all_wildcards_string(self):
        assert is_glob_match("***", "anything") is True


# ---------------------------------------------------------------------------
# arn_matches
# ---------------------------------------------------------------------------


class TestArnMatches:
    """Tests for ARN glob matching."""

    def test_exact_arn_match(self):
        arn = "arn:aws:s3:::my-bucket/key"
        assert arn_matches(arn, arn) is True

    def test_wildcard_pattern_partition(self):
        assert arn_matches("arn:*:s3:::*/*", "arn:aws:s3:::bucket/key") is True

    def test_wildcard_arn(self):
        assert arn_matches("arn:*:s3:::*/*", "*") is True

    def test_wildcard_pattern(self):
        assert arn_matches("*", "arn:aws:s3:::bucket") is True

    def test_service_mismatch(self):
        assert arn_matches("arn:*:s3:::*", "arn:aws:ec2:us-east-1:123:instance/i-123") is False

    def test_bucket_resource_type_no_slash(self):
        assert arn_matches("arn:*:s3:::*", "arn:aws:s3:::bucket/key", resource_type="bucket") is False

    def test_bucket_resource_type_valid(self):
        assert arn_matches("arn:*:s3:::*", "arn:aws:s3:::mybucket", resource_type="bucket") is True

    def test_invalid_arn_format_short(self):
        assert arn_matches("arn:aws", "arn:aws:s3:::bucket") is False

    def test_region_wildcard(self):
        assert arn_matches("arn:*:ec2:*:*:instance/*", "arn:aws:ec2:us-east-1:123:instance/i-1") is True

    def test_account_mismatch(self):
        pattern = "arn:aws:iam::111111111111:role/*"
        arn = "arn:aws:iam::222222222222:role/myrole"
        assert arn_matches(pattern, arn) is False

    def test_arn_with_policy_variable(self):
        assert arn_matches("arn:*:s3:::*/*", "arn:aws:s3:::${aws:username}/*") is True


# ---------------------------------------------------------------------------
# arn_strictly_valid
# ---------------------------------------------------------------------------


class TestArnStrictlyValid:
    """Tests for strict ARN validation."""

    def test_valid_user_arn(self):
        assert arn_strictly_valid("arn:*:iam::*:user/*", "arn:aws:iam::123456789012:user/alice") is True

    def test_invalid_missing_resource_type(self):
        assert arn_strictly_valid("arn:*:iam::*:user/*", "arn:aws:iam::123456789012:u*") is False

    def test_wildcard_arn_does_not_pass_strict(self):
        # A bare "*" doesn't have enough ARN parts to pass strict validation
        assert arn_strictly_valid("arn:*:iam::*:user/*", "*") is False

    def test_colon_in_resource_when_pattern_has_none(self):
        assert arn_strictly_valid("arn:*:s3:::*/*", "arn:aws:s3:::bucket:extra/key") is False

    def test_role_arn_valid(self):
        assert (
            arn_strictly_valid(
                "arn:*:iam::*:role/*",
                "arn:aws:iam::123456789012:role/my-role",
            )
            is True
        )


# ---------------------------------------------------------------------------
# convert_aws_pattern_to_wildcard
# ---------------------------------------------------------------------------


class TestConvertAWSPatternToWildcard:
    """Tests for AWS pattern → wildcard conversion."""

    def test_s3_bucket(self):
        result = convert_aws_pattern_to_wildcard("arn:${Partition}:s3:::${BucketName}")
        assert result == "arn:*:s3:::*"

    def test_s3_object(self):
        result = convert_aws_pattern_to_wildcard("arn:${Partition}:s3:::${BucketName}/${ObjectName}")
        assert result == "arn:*:s3:::*/*"

    def test_iam_user(self):
        result = convert_aws_pattern_to_wildcard("arn:${Partition}:iam::${Account}:user/${UserNameWithPath}")
        assert result == "arn:*:iam::*:user/*"

    def test_ec2_instance(self):
        result = convert_aws_pattern_to_wildcard("arn:${Partition}:ec2:${Region}:${Account}:instance/${InstanceId}")
        assert result == "arn:*:ec2:*:*:instance/*"

    def test_no_placeholders(self):
        plain = "arn:aws:s3:::mybucket"
        assert convert_aws_pattern_to_wildcard(plain) == plain

    def test_multiple_consecutive_placeholders(self):
        result = convert_aws_pattern_to_wildcard("${A}:${B}:${C}")
        assert result == "*:*:*"

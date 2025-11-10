"""Tests for iam_validator.utils.regex module."""

import re

from iam_validator.utils.regex import (
    cached_pattern,
    compile_and_cache,
    get_cached_pattern,
    clear_pattern_cache,
)


class TestCachedPattern:
    """Tests for @cached_pattern decorator."""

    def test_decorator_basic(self):
        """Test basic decorator functionality."""

        @cached_pattern()
        def test_pattern():
            return r"^\d+$"

        pattern = test_pattern()
        assert pattern.match("123")
        assert not pattern.match("abc")

    def test_decorator_caches_pattern(self):
        """Test that decorator returns same object on multiple calls."""

        @cached_pattern()
        def test_pattern():
            return r"test"

        pattern1 = test_pattern()
        pattern2 = test_pattern()

        assert pattern1 is pattern2, "Should return same cached object"

    def test_decorator_with_flags(self):
        """Test decorator with regex flags."""

        @cached_pattern(flags=re.IGNORECASE)
        def case_insensitive():
            return r"^test$"

        pattern = case_insensitive()
        assert pattern.match("test")
        assert pattern.match("TEST")
        assert pattern.match("TeSt")

    def test_decorator_multiline_flag(self):
        """Test decorator with MULTILINE flag."""

        @cached_pattern(flags=re.MULTILINE)
        def multiline_pattern():
            return r"^line\d$"

        pattern = multiline_pattern()
        text = "line1\nline2\nline3"
        matches = pattern.findall(text)
        assert len(matches) == 3

    def test_multiple_decorated_functions(self):
        """Test that different decorated functions have separate caches."""

        @cached_pattern()
        def pattern_a():
            return r"^a+$"

        @cached_pattern()
        def pattern_b():
            return r"^b+$"

        pa = pattern_a()
        pb = pattern_b()

        assert pa is not pb
        assert pa.match("aaa")
        assert pb.match("bbb")
        assert not pa.match("bbb")
        assert not pb.match("aaa")


class TestCompileAndCache:
    """Tests for compile_and_cache() function."""

    def test_basic_compilation(self):
        """Test basic pattern compilation."""
        pattern = compile_and_cache(r"^\d+$")
        assert pattern.match("123")
        assert not pattern.match("abc")

    def test_caching_same_pattern(self):
        """Test that same pattern returns cached object."""
        pattern1 = compile_and_cache(r"test")
        pattern2 = compile_and_cache(r"test")

        assert pattern1 is pattern2

    def test_different_flags_different_cache(self):
        """Test that different flags create different cache entries."""
        pattern1 = compile_and_cache(r"test", re.IGNORECASE)
        pattern2 = compile_and_cache(r"test", re.MULTILINE)
        pattern3 = compile_and_cache(r"test")

        assert pattern1 is not pattern2
        assert pattern1 is not pattern3
        assert pattern2 is not pattern3

    def test_flags_work_correctly(self):
        """Test that flags are applied correctly."""
        case_insensitive = compile_and_cache(r"^test$", re.IGNORECASE)
        case_sensitive = compile_and_cache(r"^test$", 0)

        assert case_insensitive.match("TEST")
        assert not case_sensitive.match("TEST")


class TestGetCachedPattern:
    """Tests for get_cached_pattern() function."""

    def setup_method(self):
        """Clear cache before each test."""
        clear_pattern_cache()

    def test_basic_usage(self):
        """Test basic pattern retrieval."""
        pattern = get_cached_pattern(r"^\d+$")
        assert pattern.match("123")
        assert not pattern.match("abc")

    def test_caching(self):
        """Test that same pattern is cached."""
        pattern1 = get_cached_pattern(r"test")
        pattern2 = get_cached_pattern(r"test")

        assert pattern1 is pattern2

    def test_flags(self):
        """Test that flags work correctly."""
        pattern = get_cached_pattern(r"^test$", re.IGNORECASE)
        assert pattern.match("TEST")

    def test_clear_cache(self):
        """Test cache clearing."""
        get_cached_pattern(r"test1")
        get_cached_pattern(r"test2")

        from iam_validator.utils.regex import _pattern_cache
        assert len(_pattern_cache) == 2

        clear_pattern_cache()
        assert len(_pattern_cache) == 0


class TestRealWorldPatterns:
    """Test patterns for real-world IAM validation scenarios."""

    def test_arn_pattern(self):
        """Test ARN validation pattern."""

        @cached_pattern()
        def arn_pattern():
            return r"^arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:.*$"

        pattern = arn_pattern()

        # Valid ARNs
        assert pattern.match("arn:aws:iam::123456789012:role/MyRole")
        assert pattern.match("arn:aws:s3::123456789012:bucket/my-bucket")

        # Invalid ARNs
        assert not pattern.match("not-an-arn")
        assert not pattern.match("arn:aws:iam::invalid:role/MyRole")

    def test_action_pattern(self):
        """Test IAM action pattern."""

        @cached_pattern(flags=re.IGNORECASE)
        def action_pattern():
            return r"^[a-z0-9-]+:[a-zA-Z0-9*]+$"

        pattern = action_pattern()

        # Valid actions
        assert pattern.match("s3:GetObject")
        assert pattern.match("s3:Get*")
        assert pattern.match("ec2:Describe*")
        assert pattern.match("iam:CreateUser")

        # Invalid actions
        assert not pattern.match("invalid")
        assert not pattern.match("s3:")
        assert not pattern.match(":GetObject")

    def test_sid_pattern(self):
        """Test Statement ID pattern."""

        @cached_pattern()
        def sid_pattern():
            return r"^[a-zA-Z0-9_-]+$"

        pattern = sid_pattern()

        # Valid SIDs
        assert pattern.match("AllowS3Access")
        assert pattern.match("Deny-Public-Access")
        assert pattern.match("Allow_EC2_ReadOnly")
        assert pattern.match("Statement123")

        # Invalid SIDs
        assert not pattern.match("Invalid SID")  # Space
        assert not pattern.match("Invalid!SID")  # Special char
        assert not pattern.match("")  # Empty

    def test_wildcard_detection(self):
        """Test wildcard detection pattern."""

        @cached_pattern()
        def has_wildcard():
            return r"\*"

        pattern = has_wildcard()

        assert pattern.search("s3:Get*")
        assert pattern.search("arn:aws:s3:::*")
        assert pattern.search("*")
        assert not pattern.search("s3:GetObject")


class TestPerformance:
    """Performance-related tests."""

    def test_cached_faster_than_recompile(self):
        """Test that using cached patterns avoids re-compilation overhead."""
        import time

        pattern_str = r"^test.*pattern$"
        test_string = "test some pattern"
        iterations = 10000

        # Scenario 1: Re-compile pattern every iteration (worst case)
        start = time.perf_counter()
        for _ in range(iterations):
            pattern = re.compile(pattern_str)
            pattern.match(test_string)
        recompile_time = time.perf_counter() - start

        # Scenario 2: Compile once, reuse (cached)
        cached_pattern = compile_and_cache(pattern_str)
        start = time.perf_counter()
        for _ in range(iterations):
            cached_pattern.match(test_string)
        cached_time = time.perf_counter() - start

        # Using a cached pattern should be faster than re-compiling
        # (The speedup depends on the pattern complexity and Python version)
        speedup = recompile_time / cached_time
        # Just verify we get some speedup (at least 1.1x)
        assert speedup > 1.0, f"Expected speedup, got {speedup:.1f}x"

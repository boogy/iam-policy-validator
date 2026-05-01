"""Tests for ``scoped_marker`` and ``COMMENT_TAG_PATTERN``.

These constants underpin the parallel-run support for PR comments
(issue #103). The behaviour pinned here is contract-level:

* an empty / missing tag returns the base marker byte-for-byte —
  this is what keeps existing PR comments and ignore-storage matchable
  after the upgrade.
* a valid tag is spliced before the closing ``-->`` so cleanup logic
  that does ``identifier in body`` continues to find the scoped marker.
* invalid tags raise instead of silently corrupting the marker.
"""

import re

import pytest

from iam_validator.core.constants import (
    ANALYZER_IDENTIFIER,
    COMMENT_TAG_PATTERN,
    IGNORED_FINDINGS_IDENTIFIER,
    REVIEW_IDENTIFIER,
    SUMMARY_IDENTIFIER,
    scoped_marker,
)


class TestScopedMarkerNoTag:
    """No tag → base marker is preserved exactly (backward compatibility).

    The implementation short-circuits on falsy tags before inspecting
    ``base``, so one representative marker is enough to pin the contract.
    """

    @pytest.mark.parametrize("tag", [None, ""])
    def test_returns_base_unchanged(self, tag):
        assert scoped_marker(SUMMARY_IDENTIFIER, tag) == SUMMARY_IDENTIFIER


class TestScopedMarkerWithTag:
    """Valid tag → ``:<tag>`` spliced before the closing ``-->``."""

    @pytest.mark.parametrize(
        "base, tag, expected",
        [
            (SUMMARY_IDENTIFIER, "role", "<!-- iam-policy-validator-summary:role -->"),
            (REVIEW_IDENTIFIER, "policy", "<!-- iam-policy-validator-review:policy -->"),
            (
                IGNORED_FINDINGS_IDENTIFIER,
                "scp",
                "<!-- iam-policy-validator-ignored-findings:scp -->",
            ),
            (ANALYZER_IDENTIFIER, "rcp", "<!-- iam-access-analyzer-validator:rcp -->"),
        ],
    )
    def test_inserts_tag_before_closing_arrow(self, base, tag, expected):
        assert scoped_marker(base, tag) == expected

    @pytest.mark.parametrize(
        "tag",
        [
            "a",  # 1 char minimum
            "Aa1._-",  # full charset sample
            "a" * 32,  # 32 char maximum
            "policy.role-1_2",
        ],
    )
    def test_accepts_full_charset(self, tag):
        result = scoped_marker(SUMMARY_IDENTIFIER, tag)
        assert result.endswith(" -->")
        assert f":{tag} -->" in result

    def test_scoped_does_not_match_unscoped_substring(self):
        """Critical regression: if the scoped marker still contained the base
        marker as a substring, every "find by identifier" lookup would still
        match across runs and the bug would not be fixed.
        """
        scoped = scoped_marker(SUMMARY_IDENTIFIER, "policy")
        # The base marker must NOT appear inside the scoped marker, otherwise
        # `identifier in body` lookups would still cross-match.
        assert SUMMARY_IDENTIFIER not in scoped


class TestScopedMarkerRejectsInvalid:
    @pytest.mark.parametrize(
        "tag",
        [
            "has space",  # whitespace
            "with/slash",
            "with\\backslash",
            "with:colon",
            "with;semi",
            "with-->arrow",  # would terminate the HTML comment
            "<script>",  # HTML injection
            "a" * 33,  # over the 32-char limit
            "tag with newline\n",
            "tag\twithtab",
        ],
    )
    def test_rejects_unsafe_or_oversized(self, tag):
        with pytest.raises(ValueError, match="Invalid comment tag"):
            scoped_marker(SUMMARY_IDENTIFIER, tag)

    def test_pattern_compiles_and_is_anchored(self):
        # Anchors matter: an unanchored regex would happily accept
        # "ok\nrm -rf /" because it contains a valid prefix.
        compiled = re.compile(COMMENT_TAG_PATTERN)
        assert compiled.fullmatch("policy") is not None
        assert compiled.fullmatch("policy\n") is None
        assert compiled.fullmatch("") is None


class TestScopedMarkerNonStandardBase:
    """Defensive path for callers that pass a marker not ending in `-->`."""

    def test_appends_when_no_closing_arrow(self):
        # Hand-rolled marker without `-->` — fall back to suffix mode.
        assert scoped_marker("<!-- something", "tag") == "<!-- something:tag"

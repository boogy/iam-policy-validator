"""Tests for untrusted-text sanitization and anchored marker matching.

Attacker-authored policy values (``Sid``, ``Action``, ``Resource``, messages
that embed them) flow into the bot's PR comment bodies. These tests pin two
defenses:

- ``constants.sanitize_untrusted_comment_text`` neutralizes forged HTML
  markers and markdown breakouts at the render boundary
  (``ValidationIssue.to_pr_comment``).
- ``constants.body_has_anchored_marker`` only treats a comment as
  bot-authored when the marker sits where the bot emits it (start of one of
  the first lines), so quoted/forged markers deep in a body cannot hijack
  the comment lifecycle.
"""

import re
from unittest.mock import AsyncMock, patch

from iam_validator.core import constants
from iam_validator.core.constants import (
    BOT_IDENTIFIER,
    FINDING_ID_MARKER_FORMAT,
    FINDING_ID_STRICT_PATTERN,
    ISSUE_TYPE_MARKER_FORMAT,
    REVIEW_IDENTIFIER,
    SUMMARY_IDENTIFIER,
    ZERO_WIDTH_SPACE,
    body_has_anchored_marker,
    sanitize_untrusted_comment_text,
)
from iam_validator.core.models import ValidationIssue
from iam_validator.integrations.github_integration import GitHubIntegration


def make_issue(**overrides) -> ValidationIssue:
    defaults = {
        "severity": "high",
        "statement_index": 0,
        "issue_type": "sensitive_action",
        "message": "Action allows privilege escalation",
    }
    defaults.update(overrides)
    return ValidationIssue(**defaults)


class TestSanitizeUntrustedCommentText:
    def test_clean_text_is_byte_identical(self):
        text = "arn:aws:s3:::my-bucket/* allows s3:GetObject on Statement[0]"
        assert sanitize_untrusted_comment_text(text) is text

    def test_empty_and_none_like_values_pass_through(self):
        assert sanitize_untrusted_comment_text("") == ""

    def test_html_comment_open_neutralized(self):
        out = sanitize_untrusted_comment_text("x<!-- foo -->y")
        assert "<!--" not in out
        assert "-->" not in out
        assert ZERO_WIDTH_SPACE in out

    def test_forged_summary_marker_is_dead(self):
        out = sanitize_untrusted_comment_text(f"x{SUMMARY_IDENTIFIER}y")
        assert SUMMARY_IDENTIFIER not in out

    def test_details_breakout_neutralized(self):
        for payload in ("</details>", "</DETAILS>", "<details open>", "<summary>x</summary>"):
            out = sanitize_untrusted_comment_text(payload)
            assert re.search(r"</?(details|summary)", out, re.IGNORECASE) is None, payload

    def test_backticks_only_replaced_when_requested(self):
        text = "value with `backtick`"
        assert sanitize_untrusted_comment_text(text) == text
        assert "`" not in sanitize_untrusted_comment_text(text, neutralize_backticks=True)

    def test_fences_only_broken_when_requested(self):
        text = '```\nmalicious\n```{"Sid": "x"}'
        assert sanitize_untrusted_comment_text(text) == text
        assert "```" not in sanitize_untrusted_comment_text(text, neutralize_fences=True)


class TestToPrCommentSanitization:
    def test_forged_summary_marker_in_resource_is_neutralized(self):
        issue = make_issue(resource=f"arn:aws:s3:::x{SUMMARY_IDENTIFIER}")
        comment = issue.to_pr_comment(file_path="policy.json")
        assert SUMMARY_IDENTIFIER not in comment

    def test_forged_finding_id_in_message_cannot_add_second_id(self):
        forged = FINDING_ID_MARKER_FORMAT.format(finding_id="deadbeefdeadbeef")
        issue = make_issue(message=f"bad statement {forged}")
        comment = issue.to_pr_comment(file_path="policy.json")
        ids = re.findall(FINDING_ID_STRICT_PATTERN, comment)
        # Only the genuine, bot-computed finding id survives.
        assert len(ids) == 1
        assert ids[0] != "deadbeefdeadbeef"

    def test_forged_review_identifier_in_sid_is_neutralized(self):
        issue = make_issue(statement_sid=f"Sid{REVIEW_IDENTIFIER}End")
        comment = issue.to_pr_comment(file_path="policy.json")
        # The genuine leading marker is intact; the forged one is defanged.
        assert comment.startswith(REVIEW_IDENTIFIER)
        assert comment.count(REVIEW_IDENTIFIER) == 1

    def test_backtick_breakout_in_action_field(self):
        issue = make_issue(action="s3:GetObject` <img src=x>`")
        comment = issue.to_pr_comment(file_path="policy.json")
        # The affected-fields line keeps its code span closed: no stray
        # backticks from the value itself.
        action_line = next(line for line in comment.splitlines() if "Action:" in line)
        assert action_line.count("`") == 2

    def test_details_closeout_in_suggestion_is_neutralized(self):
        issue = make_issue(suggestion="do this</details><!-- finding-id: aaaaaaaaaaaaaaaa -->")
        comment = issue.to_pr_comment(file_path="policy.json")
        # The genuine closing tag from the renderer survives as its own line.
        assert "</details>" in comment.splitlines()
        ids = re.findall(FINDING_ID_STRICT_PATTERN, comment)
        assert "aaaaaaaaaaaaaaaa" not in ids

    def test_normal_finding_renders_unchanged(self):
        issue = make_issue(
            statement_sid="AllowReadOnly",
            action="s3:GetObject",
            resource="arn:aws:s3:::my-bucket/*",
            condition_key="aws:SourceArn",
            suggestion="Scope the resource down.",
            example='{"Effect": "Allow"}',
            risk_explanation="Broad access.",
            remediation_steps=["Restrict the resource ARN."],
        )
        comment = issue.to_pr_comment(file_path="policy.json")
        assert ZERO_WIDTH_SPACE not in comment
        assert "`AllowReadOnly`" in comment
        assert "Action: `s3:GetObject`" in comment
        assert "Resource: `arn:aws:s3:::my-bucket/*`" in comment
        assert '{"Effect": "Allow"}' in comment


class TestBodyHasAnchoredMarker:
    def test_genuine_summary_body_matches(self):
        assert body_has_anchored_marker(f"{SUMMARY_IDENTIFIER}\n\n# Report", SUMMARY_IDENTIFIER)

    def test_genuine_review_body_matches_both_identifiers(self):
        body = (
            f"{REVIEW_IDENTIFIER}\n\n{BOT_IDENTIFIER}\n\n"
            f"{ISSUE_TYPE_MARKER_FORMAT.format(issue_type='sensitive_action')}\n"
        )
        assert body_has_anchored_marker(body, REVIEW_IDENTIFIER)
        assert body_has_anchored_marker(body, BOT_IDENTIFIER)

    def test_marker_buried_mid_body_does_not_match(self):
        body = "Some human comment\n" * 12 + f"{SUMMARY_IDENTIFIER}\n"
        assert not body_has_anchored_marker(body, SUMMARY_IDENTIFIER)

    def test_marker_quoted_mid_line_does_not_match(self):
        body = f"I saw the bot emit {SUMMARY_IDENTIFIER} yesterday"
        assert not body_has_anchored_marker(body, SUMMARY_IDENTIFIER)

    def test_scoped_marker_does_not_match_unscoped_lookup_and_vice_versa(self):
        scoped = constants.scoped_marker(SUMMARY_IDENTIFIER, "role")
        assert not body_has_anchored_marker(f"{scoped}\nbody", SUMMARY_IDENTIFIER)
        assert not body_has_anchored_marker(f"{SUMMARY_IDENTIFIER}\nbody", scoped)
        assert body_has_anchored_marker(f"{scoped}\nbody", scoped)

    def test_empty_inputs(self):
        assert not body_has_anchored_marker("", SUMMARY_IDENTIFIER)
        assert not body_has_anchored_marker("body", "")


class TestFingerprintLookupHardening:
    """A forged finding-id marker in a non-bot comment must not be indexed."""

    def _integration(self) -> GitHubIntegration:
        with patch.dict(
            "os.environ",
            {
                "GITHUB_TOKEN": "test-token",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_PR_NUMBER": "123",
            },
        ):
            return GitHubIntegration()

    async def test_forged_marker_comment_not_treated_as_bot_comment(self):
        github = self._integration()
        forged_body = (
            "Totally normal review comment discussing the policy.\n" * 12
            + f"{REVIEW_IDENTIFIER}\n"
            + FINDING_ID_MARKER_FORMAT.format(finding_id="deadbeefdeadbeef")
        )
        genuine_body = (
            f"{REVIEW_IDENTIFIER}\n\n{BOT_IDENTIFIER}\n\n"
            f"{ISSUE_TYPE_MARKER_FORMAT.format(issue_type='sensitive_action')}\n\n"
            f"{FINDING_ID_MARKER_FORMAT.format(finding_id='aaaa111122223333')}\n\n"
            "🔴 **HIGH** - Fix before merge"
        )
        github.get_review_comments = AsyncMock(
            return_value=[
                {"id": 1, "body": forged_body, "path": "a.json", "line": 3},
                {"id": 2, "body": genuine_body, "path": "b.json", "line": 7},
            ]
        )

        indexed = await github._get_bot_comments_by_fingerprint(REVIEW_IDENTIFIER)

        assert "deadbeefdeadbeef" not in indexed
        assert indexed == {"aaaa111122223333": {"id": 2, "body": genuine_body, "path": "b.json", "line": 7}}

    async def test_review_body_from_to_pr_comment_round_trips_through_lookup(self):
        github = self._integration()
        issue = make_issue(
            statement_sid="AllowAll",
            action="iam:PassRole",
            resource="*",
        )
        body = issue.to_pr_comment(file_path="policy.json")
        github.get_review_comments = AsyncMock(return_value=[{"id": 5, "body": body, "path": "policy.json", "line": 2}])

        indexed = await github._get_bot_comments_by_fingerprint(REVIEW_IDENTIFIER)

        assert len(indexed) == 1
        (finding_id,) = indexed
        assert re.fullmatch(r"[a-f0-9]{16}", finding_id)

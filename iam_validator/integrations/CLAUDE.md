# Integrations Module

GitHub PR commenting + MS Teams webhooks. Extends [../../CLAUDE.md](../../CLAUDE.md).

---

## `github_integration.py`

The single GitHub API client. Use it instead of raw `httpx` calls so retry, rate
limiting, pagination, and identifier-based comment management stay consistent.

Surface organized by concern:

- **General comments** — `post_comment`, `update_or_create_comment`, `post_multipart_comments`
- **Inline review comments** — `create_review_comment`, `create_file_level_comment`,
  `create_review_with_comments`, `update_or_create_review_comments`,
  `cleanup_bot_review_comments`
- **Comment lifecycle helpers** — `_sync_comments_with_identifier` (used by both
  general and multi-part summary paths), `_find_all_comments_with_identifier` (paginated)
- **Deduplication** — `_get_bot_comments_by_fingerprint`, `_extract_finding_id`
- **Labels** — `add_labels`, `remove_label`, `get_labels`, `set_labels`
- **PR info** — `get_pr_info`, `get_pr_files`, `get_pr_commits`
- **Status checks** — `set_commit_status`
- **CODEOWNERS** — `get_codeowners_content`, `get_team_members`, `is_user_codeowner`
- **Ignore commands** — `scan_for_ignore_commands`, `extract_finding_id`, `extract_ignore_reason`

Retry: `MAX_RETRIES`, `INITIAL_BACKOFF_SECONDS` constants on the module. Errors:
`GitHubRateLimitError`, `GitHubRetryableError`. Concurrency cap:
`MAX_CONCURRENT_API_CALLS`. Pagination: `_make_paginated_request`.

Enums: `PRState`, `ReviewEvent`.

---

## Comment-lifecycle invariants (must not regress)

Both summary and inline paths follow the same principle: **update in place,
post only the surplus, delete only what is no longer relevant**. Concretely:

- `update_or_create_review_comments` matches existing comments by fingerprint
  first, then by `(path, line, issue_type)` location. A comment with an unchanged
  body must NOT trigger a `PATCH`. Comments on files outside the PR must NOT be
  deleted.
- `_sync_comments_with_identifier` (used by `post_multipart_comments` and
  `update_or_create_comment`) reconciles oldest-first: updates the canonical comment
  in place, posts only the surplus parts, deletes only orphans past the new count.
- `protected_fingerprints` skips deletion for off-diff comments managed by the
  context-issue pipeline.

Tests pinning these invariants live in `tests/integrations/test_review_comment_noise.py`
and `test_summary_comment_staleness.py`.

All HTML comment markers come from `iam_validator.core.constants` — never hardcode
them in either production or tests.

When the caller passes a `comment_tag` (issue #103, parallel runs on the
same PR), the marker is rewritten via `constants.scoped_marker(base, tag)`
before any lookup or write. Resolve identifiers per-instance in
`__init__` (see `PRCommenter.SUMMARY_IDENTIFIER` / `REVIEW_IDENTIFIER`) and
forward the tag to `IgnoredFindingsStore` / `IgnoreCommandProcessor` —
otherwise the storage helpers and the commenter will read different
canonical comments and the bug from issue #103 returns.

---

## `ms_teams.py`

`MSTeamsIntegration` posts Adaptive Cards via incoming webhook. Methods:
`send_validation_report`, `send_pr_notification`, `send_alert`. Themes:
`CardTheme.{SUCCESS,WARNING,DANGER,INFO}`. Webhook URL is validated on init.

---

## Testing

Mock the API surface — no real HTTP. See `tests/integrations/`:

- `test_github_pagination.py` — paginated request behaviour
- `test_label_manager.py` — severity → label mapping
- `test_comment_deduplication.py` — fingerprint and location matching
- `test_review_comment_noise.py` — inline noise-minimization invariants
- `test_summary_comment_staleness.py` — summary lifecycle (paginated find, orphan cleanup)

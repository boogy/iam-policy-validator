# Integrations Module - External Service Integration

**Purpose**: GitHub PR commenting and MS Teams notifications
**Parent Context**: Extends [../../CLAUDE.md](../../CLAUDE.md)

---

## Module Overview

```
integrations/
├── __init__.py                # Package exports
├── github_integration.py      # GitHub API client for PR commenting
└── ms_teams.py                # Microsoft Teams webhook notifications
```

---

## GitHub Integration (`github_integration.py`)

Full-featured GitHub API client for posting validation results to PRs.

### Key Class: `GitHubIntegration`

```python
from iam_validator.integrations.github_integration import GitHubIntegration

async with GitHubIntegration(
    token="ghp_...",
    repository="owner/repo",
    pr_number=123,
) as gh:
    # Post a comment
    await gh.post_comment("Validation results: ...")

    # Post inline review comments
    await gh.create_review_with_comments(comments=[...])

    # Manage labels
    await gh.add_labels(["iam-validated", "security-review"])

    # Get PR metadata
    pr_info = await gh.get_pr_info()
    files = await gh.get_pr_files()
```

### Capabilities

| Category               | Methods                                                                             |
| ---------------------- | ----------------------------------------------------------------------------------- |
| **Comments**           | `post_comment`, `update_or_create_comment`, `post_multipart_comments`               |
| **Review Comments**    | `create_review_comment`, `create_file_level_comment`, `create_review_with_comments` |
| **Comment Management** | `update_or_create_review_comments`, `cleanup_bot_review_comments`                   |
| **Deduplication**      | `_get_bot_comments_by_fingerprint`, `_extract_finding_id`                           |
| **Labels**             | `add_labels`, `remove_label`, `get_labels`, `set_labels`                            |
| **PR Info**            | `get_pr_info`, `get_pr_files`, `get_pr_commits`                                     |
| **Status**             | `set_commit_status`                                                                 |
| **CODEOWNERS**         | `get_codeowners_content`, `get_team_members`, `is_user_codeowner`                   |
| **Ignore Commands**    | `scan_for_ignore_commands`, `extract_finding_id`, `extract_ignore_reason`           |

### Retry & Rate Limiting

- Automatic retry with exponential backoff (configurable `MAX_RETRIES`, `INITIAL_BACKOFF_SECONDS`)
- `GitHubRateLimitError` raised when rate limit exceeded
- `GitHubRetryableError` for transient failures
- `MAX_CONCURRENT_API_CALLS` controls parallel request limit
- Paginated request support via `_make_paginated_request`

### Error Classes

| Class                  | Purpose                     |
| ---------------------- | --------------------------- |
| `GitHubRateLimitError` | API rate limit exceeded     |
| `GitHubRetryableError` | Transient HTTP errors (5xx) |

### Enums

| Enum          | Values                             |
| ------------- | ---------------------------------- |
| `PRState`     | PR lifecycle states                |
| `ReviewEvent` | Review event types (APPROVE, etc.) |

---

## MS Teams Integration (`ms_teams.py`)

Sends validation results to Microsoft Teams channels via incoming webhooks.

### Key Class: `MSTeamsIntegration`

```python
from iam_validator.integrations.ms_teams import MSTeamsIntegration

async with MSTeamsIntegration(webhook_url="https://...") as teams:
    # Send validation report
    await teams.send_validation_report(results)

    # Send PR notification
    await teams.send_pr_notification(pr_number=123, results=results)

    # Send alert
    await teams.send_alert("Critical finding detected", theme=CardTheme.DANGER)
```

### Features

- Adaptive Card format for rich message rendering
- Configurable card themes (`CardTheme`: SUCCESS, WARNING, DANGER, INFO)
- Message types (`MessageType`): validation reports, PR notifications, alerts
- Webhook URL validation on initialization

---

## Testing

```bash
# Run integration tests
uv run pytest tests/integrations/

# Specific test files
uv run pytest tests/integrations/test_github_pagination.py
uv run pytest tests/integrations/test_label_manager.py
uv run pytest tests/integrations/test_comment_deduplication.py
```

**Key**: All tests mock the GitHub/Teams APIs - no real HTTP requests.

---

## Quick Search

```bash
# Find GitHub API methods
rg -n "async def " iam_validator/integrations/github_integration.py

# Find Teams methods
rg -n "async def " iam_validator/integrations/ms_teams.py

# Find retry/rate limit logic
rg -n "retry|rate_limit|backoff" iam_validator/integrations/

# Find tests
rg -n "test.*github|test.*teams" tests/integrations/
```

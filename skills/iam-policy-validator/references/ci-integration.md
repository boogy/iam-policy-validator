# CI/CD and PR integration

`iam-validator` integrates with GitHub Actions and pull requests via `--ci` mode, the `post-to-pr` command, and several `--github-*` flags on `validate`. The recommended pattern for agent-assisted review is: validate -> inspect JSON -> post-to-pr.

> Always confirm a flag with `iam-validator <command> --help` before relying on it.

## `--ci` mode

`--ci` prints enhanced console output suitable for job logs and writes a JSON report to disk.

Flag: `--ci-output <file>` sets the output filename (default: `validation-report.json`).

```bash
iam-validator validate --path ./policies/ --ci
iam-validator validate --path ./policies/ --ci --ci-output results.json
```

Use the JSON file as input to `post-to-pr` or for agent-side verification before posting.

## `post-to-pr` command

Posts a pre-generated JSON report to a GitHub PR. Separating validation from posting lets you inspect or filter findings before they appear on the PR.

**Required env vars:** `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, and PR number context (normally from `GITHUB_EVENT_PATH` in Actions).

Flags: `--report <file>`, `--create-review`/`--no-review`, `--add-summary`/`--no-summary`, `--config`, `--off-diff-comment-mode`, `--comment-tag`.

```bash
# Full: line-level review comments + summary table
iam-validator post-to-pr --report report.json

# Summary table only (no inline review comments)
iam-validator post-to-pr --report report.json --no-review

# Inline review comments only (no summary table)
iam-validator post-to-pr --report report.json --no-summary
```

## `--github-*` flags on `validate`

Run validation and post to GitHub in a single step.

| Flag               | Effect                                   |
| ------------------ | ---------------------------------------- |
| `--github-comment` | Summary comment on the PR conversation   |
| `--github-review`  | Line-specific review comments            |
| `--github-summary` | GitHub Actions job summary (Actions tab) |

```bash
iam-validator validate --path ./policies/ --github-review --github-comment
```

For agent-assisted review, prefer the two-step flow (`validate --format json` -> verify -> `post-to-pr`) so findings can be checked before posting.

## `--comment-tag`

Scopes PR comment markers so multiple validator runs on the same PR don't overwrite each other. Valid: 1-32 chars, `[A-Za-z0-9._-]`. Available on both `validate` and `post-to-pr`.

```bash
# Run two separate scoped validators on the same PR
iam-validator post-to-pr --report trust.json    --comment-tag trust-policies
iam-validator post-to-pr --report identity.json --comment-tag identity-policies
```

Without `--comment-tag`, a second run overwrites the first run's PR comment.

## `--off-diff-comment-mode`

Controls how findings on unchanged lines are posted to PR reviews.

| Value                      | Behavior                                     |
| -------------------------- | -------------------------------------------- |
| `summary_only` (default)   | Findings appear only in the summary table    |
| `individual`               | Each finding posted as a review comment      |
| `modified_statements_only` | Review comments only for modified statements |

```bash
iam-validator post-to-pr --report report.json --off-diff-comment-mode individual
```

## `--allow-owner-ignore` / `--no-owner-ignore`

Allows CODEOWNERS to reply "ignore" to a review comment to suppress that finding. Enabled by default.

```bash
iam-validator post-to-pr --report report.json --no-owner-ignore
```

## GitHub Actions workflow

```yaml
- uses: actions/checkout@v4
- run: |
    uvx iam-policy-validator validate \
      --path ./policies/ \
      --ci \
      --github-review \
      --github-comment
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

For the two-step pattern:

```yaml
- uses: actions/checkout@v4
- run: uvx iam-policy-validator validate --path ./policies/ --ci --ci-output report.json
- run: uvx iam-policy-validator post-to-pr --report report.json
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

# Exporting findings for PR review (second verification layer)

When findings will land on a pull request, **do not** let the validator post them. Skip `--github-comment`, `--github-review`, `--github-summary`, and `post-to-pr`. Instead export JSON and hand it to a separate reviewing agent that verifies each finding and posts the surviving ones. This inserts a human-style second check between detection and publication.

## Step 1 — export JSON

```bash
iam-validator validate --path ./policies/ --format json --output findings.json
```

(Skill invocation equivalent: `... --export-json findings.json`.) The JSON is produced by `report.model_dump()` and contains the **same** `suggestion`, `example`, `remediation_steps`, `risk_explanation`, and `documentation_url` data the validator would otherwise render into comments — nothing is lost by going through JSON.

## Step 2 — the JSON schema (handoff contract)

Top level:

| Field                           | Type  | Meaning                                               |
| ------------------------------- | ----- | ----------------------------------------------------- |
| `total_policies`                | int   | Policies scanned                                      |
| `valid_policies`                | int   | Policies passing per `fail_on_severity`               |
| `invalid_policies`              | int   | Policies failing                                      |
| `total_issues`                  | int   | All findings across policies                          |
| `validity_issues`               | int   | Count of IAM-validity findings (error/warning/info)   |
| `security_issues`               | int   | Count of security findings (critical/high/medium/low) |
| `policies_with_security_issues` | int   | Policies with a security-categorized finding          |
| `results`                       | array | One entry per policy (see below)                      |
| `parsing_errors`                | array | `[file_path, error_message]` pairs                    |
| `policies_with_errors`          | int   | Structurally AWS-invalid policies (computed)          |
| `policies_with_findings`        | int   | Policies with any non-error finding (computed)        |

Each `results[]` entry:

| Field                    | Type   | Meaning                                 |
| ------------------------ | ------ | --------------------------------------- |
| `policy_file`            | string | Path to the policy                      |
| `is_valid`               | bool   | Whether the policy passed               |
| `policy_type`            | string | `IDENTITY_POLICY`, `TRUST_POLICY`, etc. |
| `issues`                 | array  | Findings (see below)                    |
| `actions_checked`        | int    | Coverage counter                        |
| `condition_keys_checked` | int    | Coverage counter                        |
| `resources_checked`      | int    | Coverage counter                        |

Each `issues[]` finding — **these are the comment fields**:

| Field               | Type           | Role in a PR comment                                       |
| ------------------- | -------------- | ---------------------------------------------------------- |
| `severity`          | string         | `error/warning/info` or `critical/high/medium/low`         |
| `statement_sid`     | string \| null | Statement Sid (for navigation)                             |
| `statement_index`   | int            | Statement position                                         |
| `issue_type`        | string         | e.g. `security_risk`, `invalid_action`                     |
| `message`           | string         | Headline shown immediately                                 |
| `action`            | string \| null | Affected action                                            |
| `resource`          | string \| null | Affected resource                                          |
| `condition_key`     | string \| null | Affected condition key                                     |
| `suggestion`        | string \| null | "💡 Suggested Fix" text                                    |
| `example`           | string \| null | "Example:" JSON snippet shown in a code block              |
| `remediation_steps` | array \| null  | "🔧 How to Fix" numbered list                              |
| `risk_explanation`  | string \| null | "Why this matters" blockquote                              |
| `risk_category`     | string \| null | Category (drives an icon)                                  |
| `documentation_url` | string \| null | Footer "📖 Documentation" link                             |
| `check_id`          | string \| null | Footer "Check: …"                                          |
| `line_number`       | int \| null    | Line for inline placement                                  |
| `field_name`        | string \| null | `action`/`resource`/`condition`/… (precise line targeting) |

A finding's example may live in the `example` field **or** be embedded inside `suggestion` as a trailing `\nExample:\n<code>` block — handle both. Many checks populate `remediation_steps`, `risk_explanation`, and `documentation_url` by default even when `example` is `null`.

## Step 3 — verification checklist (the second layer)

For each finding, before posting:

1. **Confirm the premise** with `query` (see [querying.md](querying.md)): does the action exist? does it support the suggested condition key? is the ARN format real?
2. **Drop false positives** — if the query contradicts the finding (e.g. the action _does_ support the condition the check says to add), discard or downgrade it and note why.
3. **Dedupe** identical findings across statements/files.
4. **Sanity-check severity** against the actual blast radius; keep the validator's severity unless the query evidence justifies a change.
5. **Keep the evidence** — record the query and result so the PR comment can cite it.

Only findings that survive this pass get posted.

## Step 4 — render a comment from a finding

Reproduce the validator's native comment layout (source of truth: `ValidationIssue.to_pr_comment()` in `iam_validator/core/models.py`). Omit the validator's hidden HTML bot/identifier markers — those are only for the validator's own comment cleanup. Build the body in this order:

````markdown
{severity-emoji} **{SEVERITY}** - {action-guidance}{ | risk-category}

**Statement:** `{statement_sid}` (Statement[{statement_index}]) (line {line_number})

{message}

> **Why this matters:** {risk_explanation} ← only if present

<details>
<summary>📋 <b>View Details</b></summary>

**Affected Fields:**

- Action: `{action}`
- Resource: `{resource}`
- Condition Key: `{condition_key}`

**🔧 How to Fix:**

1. {remediation_steps[0]}
2. {remediation_steps[1]}

**💡 Suggested Fix:**

{suggestion}

**Example:**

```json
{example}
```

</details>

---

_Check: `{check_id}`_ | [📖 Documentation]({documentation_url})
````

Include only the sub-blocks whose fields are non-null. The `<details>` block appears only if at least one of action/resource/condition_key/suggestion/example/remediation_steps is present.

## Step 5 — post with `gh` (concrete recipe)

After verification, post from the reviewing agent (requires `gh auth` and a PR context):

```bash
# One summary comment
gh pr comment "$PR_NUMBER" --body-file verified-summary.md

# Per-finding inline review comments (when you have file + line)
gh api \
  --method POST \
  "repos/$OWNER/$REPO/pulls/$PR_NUMBER/comments" \
  -f body="$(cat finding-1.md)" \
  -f commit_id="$HEAD_SHA" \
  -f path="$POLICY_PATH" \
  -F line="$LINE_NUMBER" \
  -f side="RIGHT"
```

Build each `*.md` body with the Step 4 recipe from the verified finding.

## Tool-agnostic contract

The JSON in Step 2 _is_ the interface. Any consumer — a `gh`-based agent, a Slack bot, a dashboard — can read `results[].issues[]`, apply the Step 3 checklist, and render with Step 4. Nothing in the handoff depends on the validator posting. The only rule: the validator detects and exports; a separate verifier decides and posts.

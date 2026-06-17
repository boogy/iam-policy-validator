---
name: iam-policy-validator
description: Validate, analyze, and query AWS IAM policies with the iam-policy-validator CLI, and export findings as JSON for a second agent to verify and post to a GitHub PR. Use when checking, validating, linting, or auditing IAM identity, resource, or trust policies, SCPs, or RCPs; when the user mentions wildcard actions, privilege escalation, sensitive actions, confused deputy, or overly permissive policies; when querying which AWS actions, condition keys, or ARNs a service supports (or which actions support a condition key); when running AWS IAM Access Analyzer; or when exporting SARIF/Markdown/HTML/JSON findings for PR review. CLI-based alternative to the MCP server.
argument-hint: "[validate|query|analyze] <policy-path|dir> [--config <file>] [--export-json <file>]"
---

# IAM Policy Validator (CLI)

Validate AWS IAM policies against 22 built-in checks and query AWS service definitions. Self-contained: needs only the CLI (`uvx`, no install) plus Python 3.10+.

Home: https://github.com/boogy/iam-policy-validator · Docs: https://boogy.github.io/iam-policy-validator/

## What do you need to do?

| Goal                                | Command                                                        |
| ----------------------------------- | -------------------------------------------------------------- |
| Validate a policy file or directory | `iam-validator validate --path <path>`                         |
| Validate and post findings to a PR  | `validate --format json` -> verify -> `post-to-pr` (see below) |
| Query AWS actions, ARNs, conditions | `iam-validator query action\|arn\|condition --service <svc>`   |
| Run AWS IAM Access Analyzer         | `iam-validator analyze --path <path>`                          |
| Manage the AWS service cache        | `iam-validator cache info\|clear\|refresh\|prefetch`           |
| Pre-download for offline/CI         | `iam-validator sync-services --output-dir ./aws_services/`     |
| Generate shell completions          | `iam-validator completion bash\|zsh`                           |

## Quickstart

```bash
# Scan one file (no install needed)
uvx iam-policy-validator validate --path policy.json

# Scan a directory recursively
uvx iam-policy-validator validate --path ./policies/

# Trust policy (auto-detect works, but explicit is safer)
uvx iam-policy-validator validate --path trust.json --policy-type TRUST_POLICY

# JSON output for scripting or PR handoff
uvx iam-policy-validator validate --path ./policies/ --format json --output findings.json
```

## Invocation arguments

| Skill argument         | Maps to CLI                                                                      |
| ---------------------- | -------------------------------------------------------------------------------- |
| `validate` (default)   | `iam-validator validate --path <path>`                                           |
| `query`                | `iam-validator query ...` — see [references/querying.md](references/querying.md) |
| `analyze`              | `iam-validator analyze --path <path>` (AWS IAM Access Analyzer)                  |
| `--config <file>`      | `--config <file>` (forwarded verbatim; YAML)                                     |
| `--export-json <file>` | `--format json --output <file>`, then hand off — do NOT post                     |

Defaults: no verb -> `validate`. With `--export-json`, follow the PR handoff and never post comments directly.

## Install / run

```bash
uvx iam-policy-validator validate --path policy.json   # preferred, no install
uv add iam-policy-validator        # or: pip install iam-policy-validator
iam-validator --version
```

Do not install the `[mcp]` extra — this skill is CLI-only.

## PR workflow (two options)

### Option 1: Native `post-to-pr` (simpler)

```bash
iam-validator validate --path ./policies/ --format json --output report.json
iam-validator post-to-pr --report report.json
```

Posts all findings. Good for CI where you trust the validator's output. See [references/ci-integration.md](references/ci-integration.md).

### Option 2: JSON handoff with verification (recommended for agents)

```bash
# 1. Export findings
iam-validator validate --path ./policies/ --format json --output findings.json

# 2. Verify each finding with query (see verification-protocol.md)
iam-validator query action --name <svc:Action> --has-condition-key <key>

# 3. Render verified findings
python3 scripts/render_pr_comments.py findings.json --format json > comments.json

# 4. Post from a separate agent
```

Full protocol: [references/pr-review-handoff.md](references/pr-review-handoff.md). Verification checklist: [references/verification-protocol.md](references/verification-protocol.md).

## Exit codes

| Code     | Meaning                                                                   |
| -------- | ------------------------------------------------------------------------- |
| `0`      | No error-severity findings (warnings may still exist)                     |
| non-zero | Error-severity findings, or `--fail-on-warnings` + warnings, or CLI error |

Read stderr and findings before drawing conclusions. A non-zero exit does not necessarily mean the policy is dangerous.

## Policy types

`IDENTITY_POLICY` (default), `RESOURCE_POLICY`, `TRUST_POLICY`, `SERVICE_CONTROL_POLICY`, `RESOURCE_CONTROL_POLICY` — auto-detected when `--policy-type` is omitted. Pass it explicitly for trust, resource, SCP, or RCP documents to avoid false positives.

## References

- [checks.md](references/checks.md) — the 22 checks with IDs and severities
- [querying.md](references/querying.md) — query actions / ARNs / condition keys
- [configuration.md](references/configuration.md) — YAML config, ignore patterns, severity overrides
- [output-formats.md](references/output-formats.md) — console / json / sarif / markdown / html / csv / enhanced
- [ci-integration.md](references/ci-integration.md) — `--ci`, `post-to-pr`, `--github-*`, `--comment-tag`, PR workflows
- [advanced-flags.md](references/advanced-flags.md) — `--stdin`, `--custom-checks-dir`, `--stream`, `completion`, and more
- [verification-protocol.md](references/verification-protocol.md) — verify findings before posting (query-based checklist)
- [pr-review-handoff.md](references/pr-review-handoff.md) — export JSON, verify, render + post PR comments
- [common-mistakes.md](references/common-mistakes.md) — agent accuracy: fabricated flags, wrong inputs, hallucination prevention
- [troubleshooting.md](references/troubleshooting.md) — cache, offline mode, rate limits, first-run latency

For authoritative per-check detail, see https://boogy.github.io/iam-policy-validator/user-guide/checks/ rather than inventing specifics.

## Guardrails

- **Verify flags** with `iam-validator <cmd> --help`; don't fabricate them.
- **Show findings before editing** a user's policy; don't silently rewrite.
- **Prefer `uvx`** over global installs; ask before changing the environment.
- **Don't invent findings** — if the validator reports 0 issues, the policy is clean.
- **Don't invent check IDs** — use only the 22 IDs from [checks.md](references/checks.md).
- **Verify before posting** — for PRs, follow [verification-protocol.md](references/verification-protocol.md).
- **Use `--policy-type`** for non-identity policies to avoid false positives.
- **Read [common-mistakes.md](references/common-mistakes.md)** for the full list of agent pitfalls.

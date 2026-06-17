---
name: iam-policy-validator
description: Validate, analyze, and query AWS IAM policies with the iam-policy-validator CLI, and export findings as JSON for a second agent to verify and post to a GitHub PR. Use when checking, validating, linting, or auditing IAM identity, resource, or trust policies, SCPs, or RCPs; when the user mentions wildcard actions, privilege escalation, sensitive actions, confused deputy, or overly permissive policies; when querying which AWS actions, condition keys, or ARNs a service supports (or which actions support a condition key); when running AWS IAM Access Analyzer; or when exporting SARIF/Markdown/HTML/JSON findings for PR review. CLI-based alternative to the MCP server.
argument-hint: "[validate|query|analyze] <policy-path|dir> [--config <file>] [--export-json <file>]"
---

# IAM Policy Validator (CLI)

Validate AWS IAM policies against 22 built-in checks and query AWS service definitions with the `iam-validator` CLI. Self-contained: needs only the CLI (run via `uvx`, no install) plus `python3` for the bundled comment renderer.

Home: https://github.com/boogy/iam-policy-validator · Docs: https://boogy.github.io/iam-policy-validator/

## Invocation arguments

`[validate|query|analyze] <policy-path|dir> [--config <file>] [--export-json <file>]`

| Skill argument         | Maps to CLI                                                                      |
| ---------------------- | -------------------------------------------------------------------------------- |
| `validate` (default)   | `iam-validator validate --path <path>`                                           |
| `query`                | `iam-validator query ...` — see [references/querying.md](references/querying.md) |
| `analyze`              | `iam-validator analyze --path <path>` (AWS IAM Access Analyzer)                  |
| `--config <file>`      | `--config <file>` (forwarded verbatim; YAML)                                     |
| `--export-json <file>` | `--format json --output <file>`, then hand off — do NOT post                     |

Defaults: no verb → `validate`. With `--export-json`, follow the PR handoff below and never post comments with the validator.

## Install / run

```bash
uvx iam-policy-validator validate --path policy.json   # preferred, no install
uv add iam-policy-validator        # or: pip install iam-policy-validator
iam-validator --version
```

Do not install the `[mcp]` extra — this skill is CLI-only.

## Validate

```bash
iam-validator validate --path ./policies/                          # recursive
iam-validator validate --path trust.json --policy-type TRUST_POLICY
iam-validator validate --path ./policies/ --config iam-validator.yaml
iam-validator validate --path policy.json --format sarif --output results.sarif
```

Policy types: `IDENTITY_POLICY` (default), `RESOURCE_POLICY`, `TRUST_POLICY`, `SERVICE_CONTROL_POLICY`, `RESOURCE_CONTROL_POLICY` — auto-detected when `--policy-type` is omitted. Exit `0` on success, non-zero on errors; add `--fail-on-warnings` for strict CI.

Common targets: wildcards (`full_wildcard`, `wildcard_action`, `wildcard_resource`, `service_wildcard`); privilege escalation (`sensitive_action`, 490+ actions); confused deputy on trust policies (`trust_policy_validation`). See [references/checks.md](references/checks.md).

## Agent-to-agent PR workflow (don't post directly)

Two roles. The **producer** validates, verifies, and exports JSON. The **poster** renders and posts. The validator never comments itself.

```bash
# Producer: export findings only — no --github-* flags, no post-to-pr
iam-validator validate --path ./policies/ --format json --output findings.json

# Poster: deterministic render → ready-to-post comment objects
python3 scripts/render_pr_comments.py findings.json --format json > comments.json
```

The JSON carries the same suggestion / example / remediation / risk data the validator shows in comments, and `scripts/render_pr_comments.py` reproduces the exact comment layout (stdlib-only, no install). The producer should verify each finding (use `query`) before handing off. Full protocol, JSON schema, verification checklist, and `gh` posting recipe: [references/pr-review-handoff.md](references/pr-review-handoff.md).

## Query (no policy file needed)

`iam-validator query action|arn|condition` looks up actions, ARN formats, condition keys, and which actions support a given condition key (`--has-condition-key`). Full guide: [references/querying.md](references/querying.md).

## References

- [checks.md](references/checks.md) — the 22 checks with IDs and severities
- [querying.md](references/querying.md) — query actions / ARNs / condition keys and the action↔condition intersection
- [configuration.md](references/configuration.md) — YAML config, ignore patterns, severity overrides
- [output-formats.md](references/output-formats.md) — console / json / sarif / markdown / html / csv / enhanced
- [pr-review-handoff.md](references/pr-review-handoff.md) — export JSON, verify, render + post PR comments from a second agent
- [troubleshooting.md](references/troubleshooting.md) — cache, offline mode, rate limits, common errors

For authoritative per-check detail, see https://boogy.github.io/iam-policy-validator/user-guide/checks/ rather than inventing specifics.

## Guardrails

- Verify flags with `iam-validator <cmd> --help`; don't fabricate them.
- Show findings before editing a user's policy; don't silently rewrite.
- Prefer `uvx iam-policy-validator ...` over global installs; ask before changing the environment.
- For PRs, default to the JSON handoff; post directly with the validator only when the user explicitly asks.

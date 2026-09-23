---
title: MCP Server
description: Use IAM Policy Validator with AI assistants via Model Context Protocol
---

# MCP Server Integration

IAM Policy Validator provides a Model Context Protocol (MCP) server for AI assistants like Claude Desktop, Cursor, Windsurf, etc. This enables AI-powered policy validation, AWS service queries, and AWS Access Analyzer checks from inside your assistant.

## What is MCP?

[Model Context Protocol](https://modelcontextprotocol.io/) is an open protocol that enables AI assistants to interact with external tools and data sources. The IAM Policy Validator MCP server exposes 6 consolidated tools for:

- **Policy Validation** - Validate IAM policies against the same checks as the CLI
- **AWS Queries** - Query AWS service actions, ARN formats, and condition keys
- **AWS Access Analyzer** - Run AWS's own `ValidatePolicy` API against a policy
- **Organization Config** - Read (and, locally, override) which checks run and at what severity

There's no separate policy-generation tool: the assistant drafts policy JSON itself from
its own AWS knowledge plus the `query` tool, then validates the draft with
`validate_policies`. See [Prompts](#prompts-3) below for guided workflows that follow
this pattern.

## Installation

```bash
pip install iam-policy-validator[mcp]
```

Or with uv:

```bash
uv sync --extra mcp
```

### Run Without Installation (uvx)

You can run the MCP server directly from PyPI without installing it using [uvx](https://docs.astral.sh/uv/guides/tools/):

```bash
uvx --from 'iam-policy-validator[mcp]' iam-validator-mcp
```

This is particularly useful for Claude Desktop configuration (see below).

## Claude Desktop Setup

### 1. Configure Claude Desktop

Add the server to your Claude Desktop configuration:

=== "macOS"

    Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "iam-validator-mcp",
          "args": []
        }
      }
    }
    ```

=== "Windows"

    Edit `%APPDATA%\Claude\claude_desktop_config.json`:

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "iam-validator-mcp",
          "args": []
        }
      }
    }
    ```

=== "Linux"

    Edit `~/.config/Claude/claude_desktop_config.json`:

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "iam-validator-mcp",
          "args": []
        }
      }
    }
    ```

=== "Using uvx (No Installation)"

    If you prefer not to install the package globally, use [uvx](https://docs.astral.sh/uv/guides/tools/) to run directly from PyPI:

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "uvx",
          "args": ["--from", "iam-policy-validator[mcp]", "iam-validator-mcp"]
        }
      }
    }
    ```

    This downloads and runs the latest version automatically.

### 2. Restart Claude Desktop

After saving the configuration, restart Claude Desktop completely for changes to take effect.

### 3. Verify Installation

In Claude Desktop, ask:

> "What IAM policy validation tools do you have available?"

Claude should list `validate_policies`, `query`, `describe_checks`, `get_config`,
`set_config`, and `analyze_policy`.

## Tools (6)

All 6 tools are available under the default `--profile full`; a narrower `--profile`
(see [Profiles](#profiles) below) trims this set. Every tool is tagged `validate`,
`query`, `orgconfig`, or `analyze` — see [Profiles](#profiles) for what each tag
controls.

### `validate_policies`

Validate one or more IAM policies against the check registry — the same checks the
CLI runs.

- **`policies`** — inline policies: each a dict, a JSON/YAML string, or
  `{policy, name?, policy_type?}`. `name` is an opaque label used only for
  `policy_types:` glob matching and echoed back in the result.
- **`policy_type`** — `identity`/`resource`/`trust`/`scp`/`rcp`, applied to every
  policy that doesn't set its own. Omit to resolve per policy via
  `policy_types:` glob → content auto-detect → default (`identity`).
- **`detail`** — `summary` (structural stats, no findings), `findings` (default;
  lean issue list), or `full` (verbose issues + summary).
- **`format`** — `json` (default; structured results only) or any other registered
  report format to additionally render a `report` string.
- **`path`, `glob`** — local mode only. Load policies from a file or directory
  instead of (or in addition to) `policies`.

Returns `{results: [...], config_digest, report?, truncated, truncated_count}`. A
response that would exceed `--max-response-bytes` is degraded (dropping `summary`,
then `issues`, then whole entries) before it's ever truncated mid-JSON; `truncated`
and `truncated_count` report what happened.

In local/stdio mode this also accepts `path`/`glob` for on-disk policies; hosted mode
has no filesystem access, so those two parameters aren't present in its schema.

### `query`

One selector for five AWS-reference lookups, chosen via `kind`:

| `kind`            | Required param | Returns                                                    |
| ----------------- | --------------- | ----------------------------------------------------------- |
| `service_actions`  | `service`       | All actions for a service, optionally filtered by `access_level` or `name_filter` |
| `action_details`   | `actions`       | Validity, metadata, and sensitivity classification for each action (batch) |
| `condition_keys`   | `service`       | Condition keys supported by a service                       |
| `arn_formats`      | `service`       | ARN format patterns per resource type                       |
| `expand_wildcard`  | `patterns`      | Actions matching a wildcard pattern, e.g. `s3:Get*` (batch)  |

Each response is `{kind, ...}`, where the rest of the shape is fixed by `kind`. This
one tool replaces what used to be seven separate query tools, including two
that took a batch of actions/patterns at once.

### `describe_checks`

Per-check documentation: id, description, default severity, docstring, and — for the
active config — whether it's enabled, its resolved severity, and its resolved
`config` (e.g. `action_condition_enforcement`'s `requirements` list). Optionally
restrict to specific `check_ids`; omit for the full catalog (23 checks).

Use this instead of a fixed cheat sheet — it always reflects what
`validate_policies` will actually run against the active config.

### `get_config`

Effective validator config, active profile, and custom instructions. Always
available in every mode/transport (unlike `set_config`, local/stdio only).

Returns `{has_config, config, source, config_digest, mode, profile, tool_count,
tool_names, custom_instructions}`. In hosted mode, `source` and `config` describe
the immutable baseline resolved at server startup, not a per-caller override.

### `set_config`

Local mode / stdio transport only. Mutates the current session's validator config
and/or custom instructions:

- **`config`** / **`yaml_content`** / **`clear_config`** — set from a dict (same
  shape as the CLI's YAML config), set by parsing a YAML string, or clear back to
  defaults. Mutually exclusive.
- **`instructions`** / **`clear_instructions`** — set or clear custom instructions
  for the session. Mutually exclusive.

Not exposed on a hosted server — a hosted deployment's config is fixed by its
operator at startup; see [MCP Hosting](mcp-hosting.md).

### `analyze_policy`

Runs AWS Access Analyzer's `ValidatePolicy` API against a policy — AWS's own
checks (deprecated globals, type-specific rules), complementing
`validate_policies`. Requires AWS credentials and a network call, so it's slower
than the other tools and the only one with `openWorldHint=True`.

- **`policy`**, **`policy_type`** (`IDENTITY_POLICY`/`RESOURCE_POLICY`/
  `SERVICE_CONTROL_POLICY`)
- **`partition`** — defaults `region` to that partition's canonical region if
  `region` is omitted.
- **`region`** — must be in `--allowed-regions` when that allowlist is set.
- **`profile`** — local mode only; a hosted server uses its own credentials and
  doesn't let a caller pick among credential profiles.
- **`timeout_seconds`** — hard timeout on the AWS API call (default 30s).

Returns `{findings: [...], finding_count}`; each finding has `finding_type`,
`issue_code`, `message`, `learn_more_link`, `locations`.

## Resources (6)

Resources are static/cacheable data that don't count against per-turn tool-description
token budget the way tools do:

- `iam://checks` — the same check catalog as `describe_checks`, as a resource
- `iam://checks/{check_id}` — per-check docs (parameterized)
- `iam://sensitive-categories` — the 4 sensitive-action category descriptions
- `iam://sensitive-actions/{category}` — sensitive actions in a category (parameterized)
- `iam://config-schema` — JSON Schema for session config, useful for validating a
  config before calling `set_config`
- `iam://config-examples` — example YAML configs for common security postures
  (enterprise/strict, permissive dev, compliance-focused, audit, minimal)

## Prompts (3)

Guided, bounded workflows an assistant can invoke by name:

- **`generate_secure_policy(service, operations, resources, principal_type)`** —
  queries live AWS data, drafts a least-privilege policy, validates it, and fixes
  only blocking (error/critical) issues.
- **`fix_policy_issues_workflow(policy_json, issues_description)`** — fixes
  blocking issues in an existing policy in at most 2 iterations, then stops;
  non-blocking findings are presented as advisory, not looped on.
- **`review_policy_security(policy_json)`** — read-only security review: validates,
  checks action sensitivity, and reports findings without modifying the policy.

## Profiles

`--profile` (or `IAM_VALIDATOR_MCP_PROFILE`) trims the tool/resource surface by tag,
for a smaller per-turn token footprint:

| Profile              | Behavior                                                        |
| --------------------- | ----------------------------------------------------------------- |
| `full`                | All 6 tools (default)                                            |
| `validate-only`       | `validate_policies` + `describe_checks` only — smallest footprint |
| `validate-and-query`  | Adds `query` (still no live AWS API — `analyze_policy` excluded) |
| `read-only`           | Excludes any mutating tool (`set_config`) — useful for CI/sandbox |

```bash
iam-validator-mcp                        # all 6 tools (default, --profile full)
iam-validator-mcp --profile validate-only  # 2 validation tools only
iam-validator-mcp --list-profiles          # print the full profile taxonomy
```

`get_config`'s `tool_count`/`tool_names` fields report the live, profile-filtered
surface, so an assistant can introspect what it actually has access to.

## Pre-loading Organization Configuration

You can pre-load a configuration file when starting the MCP server. This applies
organization-wide validation settings for all operations without requiring the AI to
set them up. The format is identical to the CLI validator's YAML config:

```yaml
# Organization IAM Policy Configuration for MCP Server
settings:
  fail_on_severity:
    - error
    - critical
    - high

wildcard_resource:
  severity: critical

service_wildcard:
  severity: critical

sensitive_action:
  enabled: true
  severity: high
```

```bash
iam-validator-mcp --config ./config.yaml
```

In local/stdio mode, an assistant can still override this per-session with
`set_config`. In hosted mode, the config loaded at startup is immutable for the
life of the process — see [MCP Hosting](mcp-hosting.md).

#### Common Settings

The full configuration reference lives in
[Configuration](../user-guide/configuration.md); these `settings:` keys are the ones
most relevant to MCP usage:

| Setting               | Type | Description                                         |
| ---------------------- | ---- | ---------------------------------------------------- |
| `fail_on_severity`     | list | Severity levels that cause validation to fail       |
| `parallel_execution`   | bool | Enable parallel check execution                     |
| `max_concurrency`      | int  | Max policies validated concurrently (default: 10)   |

## Local vs. Hosted Mode

Everything on this page describes **local mode** (`--mode local`, the default):
one server process per user, launched by the assistant over `stdio`, with no
authentication. For a shared, multi-tenant deployment over HTTP — auth providers,
immutable server-owned config, audit logging, and production ASGI serving — see
[MCP Hosting](mcp-hosting.md).

## Troubleshooting

**Server doesn't appear in Claude Desktop** — verify the config file path for your
OS above, confirm the JSON is valid, and fully restart Claude Desktop (not just
close the window).

**"FastMCP is not installed"** — install the `mcp` extra:
`uv sync --extra mcp` or `pip install 'iam-policy-validator[mcp]'`.

**A tool you expect is missing** — check `get_config`'s `profile`/`tool_names`
fields; a narrower `--profile` may have excluded it (see [Profiles](#profiles)).

**Migrating from an older MCP server version** — the tool surface was
consolidated from a larger set of single-purpose tools down to the 6 above (e.g.
what used to be 7 `query_*`/`check_*` tools is now one `query` tool selected via
`kind`). The break affects MCP server users only (the MCP tools, resources and
prompts, plus the `iam-validator mcp`/`iam-validator-mcp` server flags).
`iam-validator validate`/`analyze` and the other CLI commands, the SDK's
validation API and the GitHub Action are unaffected. See the
`## [Unreleased]` → `### Removed` section of
[CHANGELOG.md](https://github.com/boogy/iam-policy-validator/blob/main/CHANGELOG.md)
for the full old-name → new-name mapping.

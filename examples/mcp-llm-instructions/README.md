# MCP LLM Instructions for Secure IAM Policy Generation

This directory contains best-in-class LLM instructions for generating secure AWS IAM policies with an AI assistant, validated by the IAM Policy Validator MCP server.

## Files

| File                       | Description                                       |
| -------------------------- | ------------------------------------------------- |
| `SYSTEM_PROMPT.md`         | Complete system prompt for LLM configuration      |
| `example_conversation.md`  | Example interactions demonstrating best practices |
| `organization_config.yaml` | Example organization-wide policy constraints      |

## Quick Start

### 1. Install the MCP Server

```bash
# Install with MCP support
pip install iam-policy-validator[mcp]

# Or with uv
uv pip install iam-policy-validator[mcp]
```

### 2. Configure Claude Desktop

Copy the configuration to your Claude Desktop config:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

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

### 3. Use the System Prompt

Copy the contents of `SYSTEM_PROMPT.md` into your AI assistant's system configuration, or use it as a reference for building your own secure policy generation workflow.

## Key Principles

The system prompt enforces these security principles:

1. **Least Privilege** - Grant only minimum required permissions
2. **Validate Everything** - Every policy must pass validation
3. **Condition Everything** - Add conditions to sensitive operations
4. **No Wildcards** - Avoid `*` in actions and resources
5. **Scope Resources** - Always use specific ARNs

## Available MCP Tools

The server exposes 6 consolidated tools (`--profile full`, the default). The
assistant drafts policy JSON itself from AWS knowledge plus `query`, then
validates the draft — there is no separate policy-generation tool.

### Validation

- `validate_policies` - Validate one or more policies; `detail` (`summary`/`findings`/`full`) controls response size

### Query

- `query` - Service actions, action details, condition keys, ARN formats, or wildcard expansion, selected via `kind`
- `describe_checks` - Per-check description, default severity, and resolved config (also carries the guidance a curated per-check example used to)

### Organization config (local/stdio mode)

- `get_config` - Effective config, active profile, and custom instructions (always available)
- `set_config` - Set/clear session config and custom instructions (local mode only; no effect on a hosted server)

### Analysis

- `analyze_policy` - AWS Access Analyzer validation (requires AWS credentials)

## Example Usage

Ask your AI assistant:

> "Create a policy for a Lambda function that needs to read from S3 bucket 'my-data' and write to DynamoDB table 'users'"

The AI will:

1. Query the correct actions and ARN formats with `query`
2. Draft a least-privilege policy from that information
3. Validate it with `validate_policies`
4. Add appropriate conditions
5. Explain what the policy allows

## Security Validation Checks

The MCP server runs the same 23 built-in checks as the CLI, via `describe_checks`:

| Check                          | Severity | Description                          |
| ------------------------------ | -------- | ------------------------------------ |
| `full_wildcard`                | critical | Detects `Action: "*", Resource: "*"` |
| `service_wildcard`             | high     | Detects `s3:*` style wildcards       |
| `wildcard_action`              | medium   | Detects `Action: "*"`                |
| `wildcard_resource`            | medium   | Detects `Resource: "*"`              |
| `sensitive_action`             | medium   | 490+ privilege escalation actions    |
| `action_condition_enforcement` | high     | Missing conditions on sensitive ops  |
| `not_action_not_resource`      | high     | Dangerous NotAction/NotResource      |
| ...                            | ...      | Call `describe_checks` for the rest  |

## Organization Configuration

For enterprise use, configure check severity levels organization-wide:

```yaml
# organization_config.yaml
settings:
  fail_on_severity:
    - critical
    - high
    - error

# Make wildcard checks critical (stricter than defaults)
wildcard_action:
  enabled: true
  severity: critical

wildcard_resource:
  enabled: true
  severity: critical

service_wildcard:
  enabled: true
  severity: critical

sensitive_action:
  enabled: true
  severity: high
```

Load it (local/stdio mode only):

```
Tool: set_config
Input: {"config": {...}}
```

A hosted server's config is fixed at startup by its operator; `set_config` is not
exposed there — see the [MCP Hosting](https://boogy.github.io/iam-policy-validator/integrations/mcp-hosting/) guide.

## Contributing

Found an improvement for the system prompt? Please open a PR!

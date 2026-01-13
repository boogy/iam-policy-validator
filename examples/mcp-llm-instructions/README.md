# MCP LLM Instructions for Secure IAM Policy Generation

This directory contains best-in-class LLM instructions for generating secure AWS IAM policies using the IAM Policy Validator MCP server.

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

### Validation
- `validate_policy` - Comprehensive validation against 19 checks
- `quick_validate` - Fast pass/fail check
- `validate_policies_batch` - Batch validation

### Generation
- `generate_policy_from_template` - 15 secure templates
- `build_minimal_policy` - Build from actions + resources
- `suggest_actions` - NLP-based action suggestions

### Query
- `query_service_actions` - List actions for a service
- `expand_wildcard_action` - Expand `s3:Get*` to actual actions
- `query_arn_formats` - Get correct ARN patterns

### Security
- `check_sensitive_actions` - Identify privilege escalation risks
- `get_required_conditions` - Get mandatory conditions
- `set_organization_config` - Enforce org-wide policies

## Example Usage

Ask your AI assistant:

> "Create a policy for a Lambda function that needs to read from S3 bucket 'my-data' and write to DynamoDB table 'users'"

The AI will:
1. Query the correct actions and ARN formats
2. Generate a least-privilege policy
3. Validate it against security checks
4. Add appropriate conditions
5. Explain what the policy allows

## Security Validation Checks

The MCP server runs 19 built-in checks:

| Check                          | Severity | Description                          |
| ------------------------------ | -------- | ------------------------------------ |
| `full_wildcard`                | critical | Detects `Action: "*", Resource: "*"` |
| `service_wildcard`             | high     | Detects `s3:*` style wildcards       |
| `wildcard_action`              | medium   | Detects `Action: "*"`                |
| `wildcard_resource`            | medium   | Detects `Resource: "*"`              |
| `sensitive_action`             | medium   | 490+ privilege escalation actions    |
| `action_condition_enforcement` | high     | Missing conditions on sensitive ops  |
| `not_action_not_resource`      | high     | Dangerous NotAction/NotResource      |
| ...                            | ...      | 12 more checks                       |

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

Load with:
```
Tool: set_organization_config
Input: {"config": {...}}
```

## Contributing

Found an improvement for the system prompt? Please open a PR!

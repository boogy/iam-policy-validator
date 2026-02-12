# MCP Module - Model Context Protocol Server

**Purpose**: MCP server for AI assistants to generate, validate, and query AWS IAM policies
**Parent Context**: Extends [../../CLAUDE.md](../../CLAUDE.md)

---

## Overview

The MCP (Model Context Protocol) module provides a FastMCP server that exposes the IAM Policy Validator functionality to AI assistants like Claude Desktop. It enables AI-powered policy generation with security-first design, validation, and AWS service queries.

**Key Features**:

- 25+ MCP tools across validation, generation, query, and organization config domains
- 10 built-in policy templates with variable substitution
- 6 MCP Resources for static data (templates, checks, sensitive categories, org config)
- Organization-wide policy configuration with session persistence
- Batch operations for reduced round-trips
- Lifespan management with shared AWSServiceFetcher

**Entry Point**: `iam-validator-mcp` command (runs `iam_validator.mcp:run_server`)

---

## Quick Start

### Running with uvx (Recommended for End Users)

The easiest way to run the MCP server is using `uvx` directly from PyPI - no installation required:

```bash
# Run the MCP server directly from PyPI
uvx --from "iam-policy-validator[mcp]" iam-validator-mcp

# With organization config pre-loaded
uvx --from "iam-policy-validator[mcp]" iam-validator-mcp --org-config ./org-policy.yaml
```

### Running for Local Development

```bash
# Install with MCP extras
uv sync --extra mcp

# Run the MCP server (stdio transport for Claude Desktop)
iam-validator-mcp

# Run with organization config pre-loaded
iam-validator-mcp --org-config ./org-policy.yaml

# Debug with MCP Inspector
make mcp-inspector
```

### Claude Desktop Configuration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

**Option 1: Using uvx (recommended for end users)**

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

**Option 2: Using uv with local development checkout**

```json
{
  "mcpServers": {
    "iam-policy-validator": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/iam-policy-auditor",
        "--extra",
        "mcp",
        "iam-validator-mcp"
      ]
    }
  }
}
```

**Option 3: With organization config**

```json
{
  "mcpServers": {
    "iam-policy-validator": {
      "command": "uvx",
      "args": [
        "--from",
        "iam-policy-validator[mcp]",
        "iam-validator-mcp",
        "--org-config",
        "/path/to/org-policy.yaml"
      ]
    }
  }
}
```

---

## Module Structure

```
iam_validator/mcp/
├── __init__.py            # Package exports (create_server, run_server, models)
├── server.py              # FastMCP server with 25+ tool registrations + 6 resources
├── models.py              # 5 Pydantic models for request/response types
├── session_config.py      # Session configuration manager (ValidatorConfig wrapper)
├── tools/
│   ├── __init__.py        # Tools package (exports all tool implementations)
│   ├── validation.py      # Validation tool implementations
│   ├── generation.py      # Generation tool implementations
│   ├── query.py           # Query tool implementations
│   └── org_config_tools.py # Organization config tool implementations
└── templates/
    ├── __init__.py        # Template loading interface
    └── builtin.py         # 15 built-in policy templates
```

---

## Tools Reference

### Validation Tools (3)

| Tool                      | Purpose                  | Input                                        |
| ------------------------- | ------------------------ | -------------------------------------------- |
| `validate_policy`         | Validate IAM policy dict | policy, policy_type, verbose, use_org_config |
| `quick_validate`          | Quick pass/fail check    | policy                                       |
| `validate_policies_batch` | Batch validate multiple  | policies[], policy_type, verbose             |

### Generation Tools (6)

| Tool                            | Purpose                          | Input                    |
| ------------------------------- | -------------------------------- | ------------------------ |
| `generate_policy_from_template` | Generate from built-in template  | template_name, variables |
| `build_minimal_policy`          | Build from actions + resources   | actions, resources       |
| `list_templates`                | List available templates         | (none)                   |
| `suggest_actions`               | Suggest actions from description | description, service     |
| `get_required_conditions`       | Get required conditions          | actions                  |
| `check_sensitive_actions`       | Check if actions are sensitive   | actions                  |

### Query Tools (10)

| Tool                                    | Purpose                     | Input                 |
| --------------------------------------- | --------------------------- | --------------------- |
| `query_service_actions`                 | Get actions for service     | service, access_level |
| `query_action_details`                  | Get action metadata         | action                |
| `expand_wildcard_action`                | Expand `s3:Get*` to actions | pattern               |
| `query_condition_keys`                  | Get condition keys for svc  | service               |
| `query_arn_formats`                     | Get ARN formats for service | service               |
| `list_checks`                           | List all validation checks  | (none)                |
| `get_policy_summary`                    | Analyze policy structure    | policy                |
| `list_sensitive_actions`                | List sensitive actions      | category, limit       |
| `get_condition_requirements_for_action` | Get condition requirements  | action                |
| `query_actions_batch`                   | Batch query action details  | actions[]             |

### Organization Config Tools (6)

| Tool                                 | Purpose                     | Input          |
| ------------------------------------ | --------------------------- | -------------- |
| `set_organization_config`            | Set session-wide org config | config dict    |
| `get_organization_config`            | Get current org config      | (none)         |
| `clear_organization_config`          | Clear session org config    | (none)         |
| `load_organization_config_from_yaml` | Load org config from YAML   | yaml_content   |
| `check_org_compliance`               | Check policy against org    | policy         |
| `validate_with_config`               | Validate with inline config | policy, config |

---

## Built-in Templates (15)

| Template                    | Description                          | Variables                                      |
| --------------------------- | ------------------------------------ | ---------------------------------------------- |
| `s3-read-only`              | S3 bucket read-only access           | bucket_name, prefix (optional)                 |
| `s3-read-write`             | S3 bucket read-write access          | bucket_name, prefix (optional)                 |
| `lambda-basic-execution`    | Basic Lambda execution role          | account_id, region, function_name              |
| `lambda-s3-trigger`         | Lambda with S3 event trigger         | bucket_name, function_name, account_id, region |
| `dynamodb-crud`             | DynamoDB table CRUD operations       | table_name, region, account_id                 |
| `cloudwatch-logs`           | CloudWatch Logs write permissions    | log_group_prefix, region, account_id           |
| `secrets-manager-read`      | Secrets Manager read access          | secret_prefix, region, account_id              |
| `kms-encrypt-decrypt`       | KMS key encryption/decryption        | key_id, region, account_id                     |
| `ec2-describe`              | EC2 describe-only permissions        | (none)                                         |
| `ecs-task-execution`        | ECS task execution role              | account_id, region                             |
| `sqs-consumer`              | SQS queue consumer permissions       | queue_name, region, account_id                 |
| `sns-publisher`             | SNS topic publisher permissions      | topic_name, region, account_id                 |
| `step-functions-execution`  | Step Functions execution permissions | state_machine_name, region, account_id         |
| `api-gateway-invoke`        | API Gateway invoke permissions       | api_id, stage, region, account_id              |
| `cross-account-assume-role` | Cross-account role trust policy      | trusted_account_id, external_id                |

---

## MCP Resources (6)

| Resource URI                 | Content                             |
| ---------------------------- | ----------------------------------- |
| `iam://templates`            | All policy templates with variables |
| `iam://checks`               | All 21 validation checks            |
| `iam://sensitive-categories` | Sensitive action category metadata  |
| `iam://org-config-schema`    | JSON Schema for OrganizationConfig  |
| `iam://org-config-examples`  | Example org configs for scenarios   |
| `iam://workflow-examples`    | Detailed workflow examples          |

---

## Development

### Adding a New Tool

1. **Define implementation** in `tools/validation.py`, `tools/generation.py`, or `tools/query.py`
2. **Register in server.py** with `@mcp.tool()` decorator
3. **Add docstring** describing parameters and return value
4. **Test** via Claude Desktop or `make mcp-inspector`

```python
# In tools/query.py
async def my_query_tool(param1: str) -> dict[str, Any]:
    """Implementation."""
    return {"result": param1}

# In server.py
@mcp.tool()
async def my_query_tool(param1: str) -> dict[str, Any]:
    """Short description that appears in Claude Desktop.

    Args:
        param1: Description of param1

    Returns:
        Dictionary with result data
    """
    from iam_validator.mcp.tools.query import my_query_tool as _impl
    return await _impl(param1=param1)
```

### Adding a New Resource

```python
# In server.py
@mcp.resource("iam://my-resource")
async def my_resource() -> str:
    """Description of what this resource provides."""
    import json
    data = {"key": "value"}
    return json.dumps(data, indent=2)
```

### Adding a New Template

Add to `templates/builtin.py:TEMPLATES`:

```python
TEMPLATES["my-template"] = {
    "name": "my-template",
    "description": "What this template does",
    "variables": [
        {"name": "param1", "description": "Description", "required": True},
        {"name": "param2", "description": "Optional", "required": False, "default": ""},
    ],
    "policy": {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "MyStatement",
            "Effect": "Allow",
            "Action": ["service:Action"],
            "Resource": "arn:aws:service:region:account:${param1}",
        }]
    }
}
```

---

## Testing

```bash
# Test all MCP tools
uv run pytest tests/mcp/

# Test specific module
uv run pytest tests/mcp/test_validation_tools.py
uv run pytest tests/mcp/test_generation_tools.py
uv run pytest tests/mcp/test_org_config.py
uv run pytest tests/mcp/test_templates.py

# Debug with MCP Inspector
make mcp-inspector
```

---

## Quick Search

```bash
# Find all MCP tools
rg -n "@mcp.tool" server.py

# Find all MCP resources
rg -n "@mcp.resource" server.py

# Find template definitions
rg -n '"name":' templates/builtin.py

# Find model definitions
rg -n "class.*BaseModel" .

# Find all exported functions
rg -n "__all__" .
```

---

## Dependencies

**Required**: `fastmcp>=2.0.0`

**Installation**:

```bash
# Install with MCP support
uv sync --extra mcp

# Or with pip
pip install iam-policy-validator[mcp]
```

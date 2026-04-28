# MCP Module — Model Context Protocol Server

FastMCP server exposing IAM validation, generation, and AWS-query tools to AI
assistants. Entry point: `iam-validator-mcp` (calls `iam_validator.mcp:run_server`).
Extends [../../CLAUDE.md](../../CLAUDE.md).

---

## Run

```bash
# End users (zero install)
uvx --from "iam-policy-validator[mcp]" iam-validator-mcp

# Local dev
uv sync --extra mcp && iam-validator-mcp
mise run mcp:inspector              # debug with MCP Inspector

# With pre-loaded organization config
iam-validator-mcp --org-config ./org-policy.yaml
```

### Claude Desktop config

`~/Library/Application Support/Claude/claude_desktop_config.json`:

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

For local checkouts, swap to `uv run --directory /path --extra mcp iam-validator-mcp`.
Pass `--org-config /path/to/org-policy.yaml` in `args` to pre-load organization config.

---

## Layout

```
mcp/
├── __init__.py            # exports create_server, run_server, models
├── server.py              # FastMCP server: 35+ @mcp.tool, 6 @mcp.resource
├── models.py              # 5 Pydantic request/response models
├── session_config.py      # ValidatorConfig wrapper for session-scoped org config
├── tools/
│   ├── validation.py      # validate_policy, quick_validate, validate_policies_batch
│   ├── generation.py      # generate_policy_from_template, build_minimal_policy, suggest_actions, …
│   ├── query.py           # query_service_actions, query_action_details, expand_wildcard_action, …
│   └── org_config_tools.py # set/get/clear organization_config, check_org_compliance, validate_with_config
└── templates/
    ├── __init__.py
    └── builtin.py         # 15 templates with variable substitution
```

`server.py` lifespan owns one shared `AWSServiceFetcher` so all tool calls reuse
the cache.

---

## Tools (35+)

Categories — see `server.py` for the authoritative list:

- **Validation (3)** — `validate_policy`, `quick_validate`, `validate_policies_batch`
- **Generation (6)** — `generate_policy_from_template`, `build_minimal_policy`,
  `list_templates`, `suggest_actions`, `get_required_conditions`, `check_sensitive_actions`
- **Query (10)** — `query_service_actions`, `query_action_details`,
  `expand_wildcard_action`, `query_condition_keys`, `query_arn_formats`,
  `list_checks`, `get_policy_summary`, `list_sensitive_actions`,
  `get_condition_requirements_for_action`, `query_actions_batch`
- **Organization config (6)** — `set/get/clear_organization_config`,
  `load_organization_config_from_yaml`, `check_org_compliance`, `validate_with_config`

## Resources (6)

`iam://templates`, `iam://checks`, `iam://sensitive-categories`,
`iam://org-config-schema`, `iam://org-config-examples`, `iam://workflow-examples`.

## Templates (15)

`s3-read-only`, `s3-read-write`, `lambda-basic-execution`, `lambda-s3-trigger`,
`dynamodb-crud`, `cloudwatch-logs`, `secrets-manager-read`, `kms-encrypt-decrypt`,
`ec2-describe`, `ecs-task-execution`, `sqs-consumer`, `sns-publisher`,
`step-functions-execution`, `api-gateway-invoke`, `cross-account-assume-role`.

---

## Adding things

### Tool

Implement in `tools/<category>.py`, then register in `server.py` with
`@mcp.tool()` plus a docstring (the docstring becomes the Claude-facing
description). The `server.py` shim is intentionally thin — it just delegates to
the implementation.

### Resource

```python
@mcp.resource("iam://my-resource")
async def my_resource() -> str:
    """What this exposes."""
    return json.dumps({...}, indent=2)
```

### Template

Append to `TEMPLATES` in `templates/builtin.py`:

```python
TEMPLATES["my-template"] = {
    "name": "my-template",
    "description": "What this template does",
    "variables": [
        {"name": "param1", "description": "...", "required": True},
    ],
    "policy": {"Version": "2012-10-17", "Statement": [...]},
}
```

---

## Tests

```bash
uv run pytest tests/mcp/
```

Mock fetcher / network — no real API calls. Debug interactively via `mise run mcp:inspector`.
Requires `fastmcp>=2.0.0` (installed via `uv sync --extra mcp`).

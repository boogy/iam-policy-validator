# MCP Module — Model Context Protocol Server

FastMCP server exposing IAM validation, AWS-query, and Access Analyzer tools
to AI assistants. Entry point: `iam-validator-mcp` (calls
`iam_validator.mcp:run_server`). Extends [../../CLAUDE.md](../../CLAUDE.md).

---

## Run (dev)

```bash
uv sync --extra mcp && iam-validator-mcp
mise run mcp:inspector                                # debug with MCP Inspector
iam-validator-mcp --config ./iam-validator.yaml       # pre-load config
iam-validator-mcp --custom-checks-dir ./my-checks     # CLI parity (custom checks)
iam-validator-mcp --aws-services-dir ./aws-services   # CLI parity (offline AWS data)
iam-validator-mcp --profile validate-only             # token-efficient profile
iam-validator-mcp --list-profiles                     # print profile taxonomy
```

End-user install + Claude Desktop config: see `docs/integrations/mcp-server.md`.

---

## Layout

```
mcp/
├── __init__.py            # CLI argparse, entry-point, profile dispatch
├── server.py              # FastMCP server: 24 @mcp.tool, 7 @mcp.resource
├── settings.py            # ServerSettings — resolves mode/transport/auth/limits from
│                          # IAM_VALIDATOR_MCP_* env vars + defaults; ServerSettings.from_env()
├── models.py              # Pydantic request/response models
├── session_config.py      # ValidatorConfig + CLI-paths storage (custom_checks_dir, aws_services_dir)
└── tools/
    ├── validation.py      # validate_policy, quick_validate (forwards SessionConfigManager paths)
    ├── query.py           # query_service_actions, query_action_details, expand_wildcard_action, …
    ├── analyze.py         # analyze_policy — wraps boto3 Access Analyzer in asyncio.to_thread
    └── org_config_tools.py # set/get/clear organization_config, check_org_compliance, validate_with_config
```

`server.py` lifespan owns one shared `AWSServiceFetcher` AND a per-`(region,
profile)` boto3 session cache so all tool calls reuse them.

`server.py:_get_registry()` builds the metadata registry lazily (not at import — it
loads third-party entry-point plugins). `_get_check_catalog()` and `get_check_details`
resolve each check's `enabled` / `severity` through `SessionConfigManager` on every
call, so the catalog agrees with what `validate_policy` runs; nothing memoizes the
resolved values.

---

## Tools (24) — tagged for `--profile` gating

Every tool carries exactly one functional tag (some also carry `mutating`).
The `--profile` flag uses these tags to enable/disable groups:

| Tag         | Tools                                                                                                                                                                                                                                               |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `validate`  | `validate_policy`, `quick_validate`, `validate_policies_batch`, `get_policy_summary`, `get_active_profile`                                                                                                                                          |
| `query`     | `query_service_actions`, `query_action_details`, `expand_wildcard_action`, `query_condition_keys`, `query_arn_formats`, `get_condition_requirements_for_action`, `query_actions_batch`, `check_actions_batch`                                       |
| `fix`       | `get_issue_guidance`                                                                                                                                                                                                                                |
| `orgconfig` | `set_/get_/clear_organization_config` (set/clear also tagged `mutating`), `load_organization_config_from_yaml` (also `mutating`), `check_org_compliance`, `validate_with_config`, `set_/get_/clear_custom_instructions` (set/clear also `mutating`) |
| `analyze`   | `aws_access_analyzer_validate` (only tool with `openWorldHint=True` — calls live AWS API)                                                                                                                                                           |

### Profiles

| Profile              | Behaviour                                                   |
| -------------------- | ----------------------------------------------------------- |
| `full`               | All tools (default)                                         |
| `validate-only`      | Only `validate` tag — smallest token footprint              |
| `validate-and-query` | `validate` + `query` (no live AWS API; analyze is excluded) |
| `read-only`          | Excludes anything tagged `mutating` — useful for CI/sandbox |

`apply_profile` snapshots `mcp._transforms` (FastMCP private attr) at module
load so successive profile changes can reset cleanly. The
`tests/mcp/test_profiles.py::test_apply_profile_is_not_an_mcp_tool` regression
test guards against accidentally exposing the helper as a tool.

### Token cost

Tags + tool annotations + slimmed `BASE_INSTRUCTIONS` produce these footprints
(instructions + tool descriptions, characters):

| Profile              | Tools | Total | % full |
| -------------------- | ----- | ----- | ------ |
| `full`               | 24    | 3165  | 100%   |
| `validate-only`      | 5     | 1416  | 45%    |
| `validate-and-query` | 13    | 1994  | 63%    |

## Resources (7)

Static resources cache client-side and don't count against per-turn token
budget the way tool descriptions do:

- `iam://checks` — registered check catalog (id, description, default_severity, plus
  the session-config-resolved `severity` and `enabled`)
- `iam://sensitive-categories` — sensitive-action category descriptions
- `iam://sensitive-actions/{category}` — actions for a category (parameterized)
- `iam://checks/{check_id}` — per-check docs, registry-driven (parameterized)
- `iam://config-schema` — JSON Schema for session config
- `iam://config-examples` — example YAML configs by security posture
- `iam://workflow-examples` — guided example workflows

---

## Adding things

### Tool

Implement in `tools/<category>.py`, then register in `server.py` with
`@mcp.tool(tags={"<one-tag>"}, annotations=ToolAnnotations(...))` plus a
docstring (the docstring becomes the Claude-facing description). Pick a single
tag; if it could fit two, the dominant one is right.

### Resource

```python
@mcp.resource("iam://my-resource")
async def my_resource() -> str:
    """What this exposes."""
    return json.dumps({...}, indent=2)
```

Parameterized:

```python
@mcp.resource("iam://my-thing/{name}")
async def my_thing(name: str) -> str:
    return json.dumps({"name": name, "data": ...}, indent=2)
```

`get_issue_guidance` and `get_check_details` are registry-driven only — they
return the check's `description` and `default_severity` from
`_get_registry()`, with no curated per-check example data.

---

## Tests

```bash
uv run pytest tests/mcp/
```

Test files of note:

- `test_constants_alignment.py` — guard rails: MCP must source shared literals from `core/constants`
- `test_profiles.py` — tag-based gating + idempotency
- `test_transport.py` — in-process FastMCP `Client` round-trip (annotations, resources, errors)
- `test_analyze.py` — Access Analyzer wrapper + cached boto3 session

Mock fetcher / network — no real API or AWS calls. Debug interactively via
`mise run mcp:inspector`. Requires `fastmcp>=3.2,<4` (installed via
`uv sync --extra mcp`).

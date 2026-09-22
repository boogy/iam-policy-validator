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
├── __init__.py            # CLI argparse, entry-point, --profile -> IAM_VALIDATOR_MCP_PROFILE
├── settings.py            # ServerSettings — resolves mode/transport/auth/limits from
│                          # IAM_VALIDATOR_MCP_* env vars + defaults; ServerSettings.from_env()
├── component_spec.py      # ComponentSpec/ToolSpec/ResourceSpec/PromptSpec — shared gating fields
├── build.py               # spec_survives() + build_server(settings) -> fresh FastMCP instance;
│                          # sole server-construction path (create_server()/run_server() call it)
├── instructions.py        # BASE_INSTRUCTIONS + get_instructions()
├── resources.py           # RESOURCES: list[ResourceSpec] (7 entries)
├── prompts.py             # PROMPTS: list[PromptSpec] (3 entries)
├── models.py              # Pydantic request/response models
├── context.py             # ServerContext (built once, held in the FastMCP lifespan) +
│                          # SessionState (session-scoped org config / custom instructions)
└── tools/
    ├── validate.py         # TOOLS: validate_policies (mode-gated local/hosted variants,
    │                       # local carries path/glob)
    ├── query.py            # TOOLS: query (kind=service_actions|action_details|
    │                       # condition_keys|arn_formats|expand_wildcard)
    ├── checks.py           # TOOLS: describe_checks (registry-driven check catalog +
    │                       # resolved enabled/severity/config + provenance source)
    ├── analyze.py           # TOOLS: aws_access_analyzer_validate — wraps boto3 Access Analyzer
    │                       # in asyncio.to_thread
    └── config.py           # TOOLS: get_config (always available), set_config
                            # (local/stdio only, mutating)
```

`build_server(settings)` is the only place a `FastMCP` instance is constructed. It
iterates a fixed `_TOOL_MODULES` tuple (`validate`, `query`, `checks`, `config`,
`analyze`) reading each module's `TOOLS` attribute, plus `resources.RESOURCES` and
`prompts.PROMPTS`, filtering every spec through `spec_survives()` before registering
it — never a module-level singleton, so two calls with different `ServerSettings`
(e.g. different `--profile`) return independently configured servers.

The lifespan (`context.py:server_lifespan()`) builds one `ServerContext` at
startup — registry, `ReportGenerator`, shared `AWSServiceFetcher`, and a per-`(region,
profile)` boto3 session cache — and every tool call reaches it via
`ctx.request_context.lifespan_context` (see `context.py:get_server_context()`). No MCP
tool reads a module-level global.

`ServerContext.registry` is built once at startup via `build_registry()` (not lazily —
it loads third-party entry-point plugins once). `validate_policies` reuses
`ServerContext.registry`/`.config` directly and does not rebuild per call, including
when an active session-config override (`set_config`) is present — that
path goes through
`iam_validator.core.policy_checks.overlay_registry_config(base_registry, config)`, which
reuses the startup registry's already-imported check instances (and their `source`
provenance) under the override's settings — no re-import, no temp file. In that
override case, `get_check_catalog()`/`get_check_details()`/`describe_checks()` (in
`context.py`/`tools/checks.py`) resolve each check's `enabled`/`severity` via
`context.py:get_active_config()` — the session override if one is set, else
`ServerContext.config` (the hosted baseline in hosted mode, never a hardcoded
default) — on every call, so the catalog agrees with what `validate_policies` runs;
nothing memoizes the resolved values.

### Hosted config resolution + config_digest

In hosted mode (`--config`/`IAM_VALIDATOR_MCP_CONFIG`), `context.py:build_context()`
resolves the config once at startup into `ServerContext.config` and never rereads or
reloads it (redeploy only) — `set_config`, the sole session-mutating `orgconfig`
tool, is structurally excluded from hosted `build_server()` via
`ToolSpec(modes=frozenset({"local"}), transports=frozenset({"stdio"}))`, so hosted
config is immutable for the process lifetime. A missing/unreadable/schema-invalid config file, or a declared custom check
that fails to import, raises `HostedStartupError` naming the problem and exits non-zero
(`_load_hosted_config`/`_verify_hosted_custom_checks`) — local mode keeps
`ConfigLoader`'s warn-and-continue contract unchanged. `custom_instructions` is also read
from the config's top-level key (or `IAM_VALIDATOR_MCP_INSTRUCTIONS`) at startup via
`_resolve_startup_instructions(settings, config)`.

`ServerContext.config_digest` is a stable SHA-256 (`_compute_config_digest`) over the
resolved config dict plus the sorted `(check_id, source, enabled, severity)` tuples of
the built registry — the registry is included, not just the config dict, because
`create_default_registry`'s `load_entry_point_checks` can add a check via an installed
distribution's entry point without it appearing anywhere in the YAML.
`CheckRegistry.register(check, *, source=...)` records provenance
(`builtin`/`entry_point`/`config_module`/`discovered`); `get_source(check_id)` reads it
back. The digest is returned by `get_config` and attached to
every `validate_policies` response as `config_digest`.

`validate.py` registers two `ToolSpec`s under the same name `validate_policies`, one
per `modes` (`{"local"}` wraps `validate_policies` with `path`/`glob` on its signature;
`{"hosted"}` wraps `_validate_policies_hosted`, which lacks them) — `build_server()`
includes exactly one per process since `modes` is mutually exclusive, so hosted schemas
never expose local-only filesystem parameters.

---

## Tools (6) — tagged for `--profile` gating

Every tool carries exactly one functional tag (some also carry `mutating`).
The `--profile` flag uses these tags to enable/disable groups:

| Tag         | Tools                                                                                                                                                                                                                                                                                                                    |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `validate`  | `validate_policies` (consolidates the former `validate_policy`, `quick_validate`, `validate_policies_batch`, `validate_with_config`, `check_org_compliance`, `get_policy_summary`), `describe_checks` (consolidates the former `get_issue_guidance`, `check_sensitive_actions`, `get_condition_requirements_for_action`) |
| `query`     | `query` (kind-dispatched selector; consolidates the former `query_service_actions`, `query_action_details`, `query_actions_batch`, `check_actions_batch`, `query_condition_keys`, `query_arn_formats`, `expand_wildcard_action`)                                                                                         |
| `orgconfig` | `get_config` (always available; consolidates the former `get_organization_config`, `get_active_profile`, `get_custom_instructions`), `set_config` (local/stdio only, `mutating`; consolidates the former `set_/clear_organization_config`, `load_organization_config_from_yaml`, `set_/clear_custom_instructions`)       |
| `analyze`   | `aws_access_analyzer_validate` (only tool with `openWorldHint=True` — calls live AWS API)                                                                                                                                                                                                                                |

### Profiles

| Profile              | Behaviour                                                   |
| -------------------- | ----------------------------------------------------------- |
| `full`               | All tools (default)                                         |
| `validate-only`      | Only `validate` tag — smallest token footprint              |
| `validate-and-query` | `validate` + `query` (no live AWS API; analyze is excluded) |
| `read-only`          | Excludes anything tagged `mutating` — useful for CI/sandbox |

`--profile` sets `IAM_VALIDATOR_MCP_PROFILE`, which `ServerSettings.from_env()` reads
at startup; `build_server(settings)` runs every spec through `spec_survives()`
before registering it, so an excluded tool is never present in `list_tools()` (not
merely hidden from a client that asks nicely). `get_config()` reports the resolved
`settings.profile` plus the live tool count/names from `await ctx.fastmcp.list_tools()`.
Note `orgconfig` isn't in `_PROFILE_TAGS` for `validate-only`/`validate-and-query`, so
`get_config`/`set_config` only survive under `full` or `read-only`.

### ComponentSpec and build_server

`component_spec.py` declares `ComponentSpec` (shared `tag`/`modes`/
`transports`/`scopes`/`mutating` gating fields) and its `ToolSpec`/
`ResourceSpec`/`PromptSpec` subclasses. Each `tools/*.py` module exposes a
`TOOLS: tuple[ToolSpec, ...]`; `resources.py`/`prompts.py` expose `RESOURCES`/
`PROMPTS` the same way — every resource carries the tag of whatever tool
returns equivalent data, so gating a tool can't be bypassed by reading its
resource twin. `ToolSpec.output_schema` is computed via
`component_spec.infer_output_schema(fn)` (wraps
`FunctionTool.from_function(fn).output_schema`) rather than hand-written, so it
can't drift from the function signature.

`build.py::build_server(settings)` filters every spec through
`spec_survives()` — by `mode`, `transport`, and `profile` (`read-only`
filters on `mutating` instead of `tag`) — and registers survivors on a fresh
`FastMCP` instance, iterating each module's `TOOLS` list (via
`getattr(module, "TOOLS", ())`) in a fixed order so two calls with identical
settings produce an identical tool-name sequence (MCP 2026-07-28 requires
this for client-side list caching).

The six `validate`-tagged validation tools were consolidated into
`validate_policies`; seven of the eight `query`-tagged tools into a single
`query` selector (`kind` = `service_actions` | `action_details` |
`condition_keys` | `arn_formats` | `expand_wildcard`); `get_issue_guidance`,
`check_sensitive_actions`, and `get_condition_requirements_for_action` into
`describe_checks`; and the seven `orgconfig` tools into `get_config`/
`set_config`. The local `full` surface has reached the target 6-tool surface
(down from 19).

### Token cost

Tags + tool annotations + slimmed `BASE_INSTRUCTIONS` produce these footprints
(instructions + tool descriptions, characters):

| Profile              | Tools | Total | % full |
| -------------------- | ----- | ----- | ------ |
| `full`               | 6     | 2976  | 100%   |
| `validate-only`      | 2     | 1515  | 51%    |
| `validate-and-query` | 3     | 1776  | 60%    |

## Resources (7)

Static resources cache client-side and don't count against per-turn token
budget the way tool descriptions do:

- `iam://checks` (tag `validate`) — registered check catalog (id, description,
  default_severity, plus the session-config-resolved `severity` and `enabled`)
- `iam://sensitive-categories` (tag `validate`) — sensitive-action category descriptions
- `iam://sensitive-actions/{category}` (tag `validate`) — actions for a category (parameterized)
- `iam://checks/{check_id}` (tag `validate`) — per-check docs, registry-driven (parameterized)
- `iam://config-schema` (tag `orgconfig`) — JSON Schema for session config
- `iam://config-examples` (tag `orgconfig`) — example YAML configs by security posture
- `iam://workflow-examples` (tag `validate`) — guided example workflows

All four `validate`-tagged resources survive under `--profile validate-only`, matching
the tools that produce equivalent data — a resource's gating tag must never be looser
than the tool it mirrors.

## Prompts (3)

- `generate_secure_policy` — guided workflow for building a least-privilege policy
- `fix_policy_issues_workflow` — bounded (2-iteration) issue-fixing workflow
- `review_policy_security` — read-only security review of a supplied policy

---

## Adding things

### Tool

Implement in `tools/<category>.py`, add it to that module's `TOOLS` tuple as a
`ToolSpec(tag="<one-tag>", name=..., fn=..., annotations=ToolAnnotations(...),
output_schema=infer_output_schema(fn))`, plus a docstring on the function (the
docstring becomes the Claude-facing description). Pick a single tag; if it
could fit two, the dominant one is right. If a module already has an impl
function under the desired tool name, register a distinct wrapper function
(see the `_..._tool` convention above) rather than renaming the impl.

### Resource

```python
async def my_resource() -> str:
    """What this exposes."""
    return json.dumps({...}, indent=2)


RESOURCES.append(ResourceSpec(tag="<one-tag>", uri="iam://my-resource", name="my_resource", fn=my_resource))
```

Parameterized (uri contains `{name}`, function takes a matching parameter):

```python
async def my_thing(name: str) -> str:
    return json.dumps({"name": name, "data": ...}, indent=2)
```

`describe_checks` (tool) and `get_check_details` (resource, via `iam://checks/{check_id}`)
are registry-driven only — they return each check's `description` and
`default_severity` from `ServerContext.registry` (falling back to
`create_default_registry()` outside an MCP request), with no curated per-check
example data.

### Prompt

```python
def my_prompt(arg: str) -> str:
    """What this prompt is for."""
    return f"...{arg}..."


PROMPTS.append(PromptSpec(tag="<one-tag>", name="my_prompt", fn=my_prompt))
```

---

## Tests

```bash
uv run pytest tests/mcp/
```

Test files of note:

- `test_constants_alignment.py` — guard rails: MCP must source shared literals from `core/constants`
- `test_build.py` — `spec_survives()` mutating/transport gating with fixture specs, a
  `build_server()` determinism test that derives the expected tool-name order from a
  monkeypatched `_TOOL_MODULES` and fails under a hash-based sort, and
  `TestOrgConfigToolGating` (real `config.py` specs: hosted registers `get_config` not
  `set_config`; `set_config` absent over `http` even in local mode; present over `stdio`)
- `test_profiles.py` — `spec_survives()` profile-tag semantics with fixture specs, plus
  `build_server()`'s live tool catalog (`iam://checks` demotion, `get_config()`)
- `test_transport.py` — in-process FastMCP `Client` round-trip (annotations, resources, errors)
  against a `build_server(ServerSettings())` instance
- `test_server_integration.py` — check catalog (incl. the hosted-baseline-not-stock-defaults
  regression), server metadata, tool/resource registration
- `test_dynamic_checks.py` — a check registered at runtime (not built in) reaches both
  `iam://checks` and `describe_checks`, across all four provenance `source` values, with
  no `iam_validator/mcp/` file hardcoding a check list
- `test_prompt_schema.py` — guards prompt argument descriptions against FastMCP's generic
  schema fallback (triggered by a stray `from __future__ import annotations` in `prompts.py`)
- `test_analyze.py` — Access Analyzer wrapper + cached boto3 session
- `test_accuracy_fixes.py` — `validate_policies` wildcard detection, Access Analyzer
  partition/timeout defaults, malformed-input error shape
- `test_validation_tools.py` — `validate_policies`: input forms (dict/JSON/YAML/object),
  detail levels, format enum (rejects `console`/`enhanced`), `fails_policy` derivation,
  policy-type resolution (`cli-flag`/config-glob/auto-detect/default) incl. per-entry
  override, session-config overlay, the five `ServerSettings` request limits (each
  raising `ToolError`, except `max_response_bytes` which degrades + sets `truncated`),
  hosted schema excludes `path`/`glob`
- `test_immutable_config.py` — hosted-mode mutating-tool exclusion + config/digest
  unchanged after every hosted-surviving tool call
- `test_hosted_startup_custom_checks.py` — a declared custom check that fails to
  import exits hosted startup non-zero naming it; local mode boots with a warning
- `test_config_digest.py` — `config_digest` stability across processes, and change on
  severity edit / disable / entry-point check addition
- `test_no_tempfile.py` — `validate_policies` never calls `tempfile.NamedTemporaryFile`
  for an inline config override

Mock fetcher / network — no real API or AWS calls. Debug interactively via
`mise run mcp:inspector`. Requires `fastmcp>=3.2,<5` (installed via
`uv sync --extra mcp`).

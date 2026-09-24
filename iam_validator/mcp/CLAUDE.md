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
iam-validator-mcp --transport http --host 127.0.0.1 --port 8000  # Streamable HTTP
```

`iam-validator mcp` (the subcommand) takes the identical flag set — both entry points
build their parser from `iam_validator.mcp.cli.add_arguments()` and resolve it to a
`ServerSettings` via `iam_validator.mcp.cli.resolve_settings()`, so the same flags on
either produce the same settings. `--transport` accepts only `stdio`/`http`; `sse` is
rejected with a message naming `http` (MCP spec 2026-07-28 defines only stdio and
Streamable HTTP — HTTP+SSE was replaced in 2025-03-26 and has since been removed from
the spec, not merely deprecated).

End-user install + Claude Desktop config: see `docs/integrations/mcp-server.md`.

---

## Layout

```
mcp/
├── __init__.py            # run_server()/create_server() -- iam-validator-mcp entry point,
│                          # builds its parser from cli.add_arguments()
├── cli.py                 # add_arguments()/resolve_settings() -- the one argparse builder
│                          # both entry points (iam-validator-mcp, iam-validator mcp) share;
│                          # merges flags over IAM_VALIDATOR_MCP_* env vars, flags win
├── settings.py            # ServerSettings — resolves mode/transport/auth/limits from
│                          # IAM_VALIDATOR_MCP_* env vars + defaults; ServerSettings.from_env()
├── component_spec.py      # ComponentSpec/ToolSpec/ResourceSpec/PromptSpec — shared gating fields
├── build.py               # spec_survives() + build_server(settings) -> fresh FastMCP instance;
│                          # sole server-construction path (create_server()/run_server() call it)
├── auth.py                 # get_auth_provider(settings) -> AuthProvider | None, dispatched on
│                           # settings.auth (none/token/jwt/<idp>); SCOPE_TO_TAG constant.
│                           # Wired into build_server()'s FastMCP(auth=...) and per-component gating.
├── instructions.py        # BASE_INSTRUCTIONS + get_instructions()
├── resources.py           # RESOURCES: list[ResourceSpec] (6 entries)
├── prompts.py             # PROMPTS: list[PromptSpec] (3 entries)
├── models.py              # Pydantic request/response models
├── context.py             # ServerContext (built once, held in the FastMCP lifespan) +
│                          # SessionState (session-scoped org config / custom instructions)
├── audit.py               # audited_call() -- one structured JSON log record per hosted
│                          # tool call, across all five tools (see "Audit logging" below)
├── asgi.py                # create_app(settings) -- production ASGI app factory (uvicorn
│                          # entrypoint); mounts the FastMCP app under outer /health, /ready
└── tools/
    ├── validate.py         # TOOLS: validate_policies (mode-gated local/hosted variants,
    │                       # local carries path/glob)
    ├── query.py            # TOOLS: query (kind=service_actions|action_details|
    │                       # condition_keys|arn_formats|expand_wildcard)
    ├── checks.py           # TOOLS: describe_checks (registry-driven check catalog +
    │                       # resolved enabled/severity/config + provenance source)
    ├── analyze.py           # TOOLS: analyze_policy (mode-gated local/hosted variants,
    │                       # local carries profile) — wraps boto3 Access Analyzer in
    │                       # asyncio.to_thread, bounded by allowed_regions + AnalyzeRateLimiter
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

### Production serving (ASGI, Docker)

`iam-validator-mcp --transport http`/`iam-validator mcp --transport http` call
`FastMCP.run()`/`run_async()` for local, single-process serving. `asgi.py:create_app()`
is a separate, production path: it builds one `ServerContext`, passes it into
`build_server(settings, context=...)`, and returns a plain `Starlette` ASGI app —
`mcp.http_app(stateless_http=True, host_origin_protection="auto")` mounted at `/` under
two outer routes, `/health` (liveness) and `/ready` (readiness: config resolved,
registry built, `context.ready` — flips true when the lifespan's `prewarm()`
completes). The Docker image's `CMD` runs it via
`uvicorn iam_validator.mcp.asgi:create_app --factory`, so a process manager can run
multiple workers behind a reverse proxy.

`/health`/`/ready` are declared as top-level routes on the _outer_ app, not
`@mcp.custom_route`s on the FastMCP app itself, specifically so they never pass through
the mounted sub-app's middleware stack — FastMCP's Origin/Host DNS-rebinding guard
(`host_origin_protection="auto"`, required by the MCP spec) and its `auth` provider both
live there. A `custom_route` would share that stack and 403/401 a load balancer probe
that sends no `Origin` header and no bearer token; mounting makes both checks
structurally unreachable from `/health`/`/ready` while `/mcp` itself still enforces
both (see `tests/mcp/test_health_routes.py`'s bypass tests and their `/mcp` controls).

The server binds `127.0.0.1` by default; `0.0.0.0` (what the Docker image sets) is an
explicit opt-in via `--host`/`IAM_VALIDATOR_MCP_HOST`. Behind a reverse proxy, disable
response buffering for the `/mcp` SSE stream (`proxy_buffering off` on nginx, plus
`X-Accel-Buffering: no`) and raise `proxy_read_timeout`.

See the repo-root `Dockerfile` for the hosted image: it bakes AWS service reference
data at build time (`iam-validator sync-services`) so the running container makes no
outbound calls, installs the package as a built wheel rather than an editable source
tree, runs as a non-root user, and never sets `PYTHONOPTIMIZE`/`-O` (would strip the
docstrings `describe_checks` reads as each check's description). It deliberately leaves
`IAM_VALIDATOR_MCP_AUTH` and any config file unset — an operator must supply
`--auth`/`IAM_VALIDATOR_MCP_AUTH` and `--config`/`IAM_VALIDATOR_MCP_CONFIG` explicitly,
same as any other hosted-mode deployment. `IAM_VALIDATOR_MCP_CACHE_DIRECTORY` points at
`/tmp/iam-validator-cache`, but the image does not mount a tmpfs there — under a
read-only container root filesystem, an operator must mount a writable volume or run
the container with `--tmpfs /tmp`, or startup fails with `HostedStartupError`.

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

`analyze.py` follows the same pattern under the shared name `analyze_policy`: the
local `ToolSpec` wraps `_analyze_policy_tool` (has `profile`), the hosted one wraps
`_analyze_policy_tool_hosted` (no `profile` — a client must not select among
credential profiles on a shared host). Both funnel through `_analyze_policy_tool_impl`,
which rejects a `region` outside `ServerSettings.allowed_regions` (default: the
server's own region only) before a boto3 session is created, and enforces
`ServerContext.analyze_rate_limiter` — a best-effort in-process sliding-window counter
from `ServerSettings.analyze_rate_limit`, not a quota; reserved concurrency, API
Gateway usage plans, and `iam:analyze`-scope gating are external/future controls.

### Auth providers

`auth.py:get_auth_provider(settings)` is the only place a FastMCP `AuthProvider` is
constructed, dispatched on `ServerSettings.auth`: `"none"` -> `None` (hosted mode
refuses this unless `auth_explicitly_set`, re-enforcing the check `settings.py`
already makes at construction time, since `ServerSettings` has no
`validate_assignment`), `"token"` -> `StaticTokenVerifier`, `"jwt"` -> `JWTVerifier`,
or an IdP name (`azure`/`google`/`github`/`keycloak`/`auth0`/`workos`). All provider
material comes from `IAM_VALIDATOR_MCP_AUTH_*` env vars or a file path they name,
never a CLI flag; every failure prints to stderr and exits non-zero. `SCOPE_TO_TAG`
is the canonical `iam:validate`/`iam:query`/`iam:analyze`/`iam:config` -> tag mapping
for scope-based gating. `SCOPE_FREE_TAGS` declares tags deliberately left ungated
(`fix`) — a declaration `test_scope_gating.py`'s tag-coverage guard enforces, not
something production code consults.

### Scope gating

`build_server()` passes `get_auth_provider(settings)` straight into
`FastMCP(auth=...)`, and attaches a `fastmcp.server.auth.restrict_tag(tag,
scopes=[...])` check to every tool/resource/prompt whose tag has a scope (via
`_component_auth()`, `spec.scopes` overriding a `SCOPE_TO_TAG`-derived default per
tag) — but only when `auth_provider is not None`. Outside a real request (e.g. a
test calling `list_tools()` directly) or under `auth="none"`, FastMCP has no
token to check, so the gate is skipped entirely rather than denying everyone.

FastMCP hides a component a caller's token lacks scope for — `list_tools()`/
`list_resources()`/`list_prompts()` omit it and `get_tool()`/`get_resource()`/
`get_prompt()` return `None` — rather than returning an explicit authorization
error, which would leak the scope taxonomy to an unauthorized caller. Every
`validate`/`query`/`analyze`/`orgconfig`-tagged resource carries the same tag
(and therefore the same gate) as its tool twin, so a caller who can't see
`describe_checks` also can't read `iam://checks` directly. A tag absent from
`SCOPE_TO_TAG` must appear in `SCOPE_FREE_TAGS` instead (currently just `fix`,
covering the `fix_policy_issues_workflow` prompt) so an ungated tag is always a
deliberate declaration, never an omission; `test_scope_gating.py` enforces every
tag lands in one set or the other. Per MCP 2026-07-28, the tool set may vary
per-request by presented authorization (this); `spec_survives()`'s profile
filtering must not vary per-connection, and doesn't — it's fixed at
`build_server()` call time.

### Audit logging

`audit.py:audited_call(tool_name, ctx, policy_count, call)` wraps every tool's
body — `validate_policies`, `analyze_policy`, `query`, `describe_checks`, and
`get_config` all route every call through it unconditionally — and is itself
mode-aware rather than requiring a separate hosted-only wrapper: it checks
`ServerContext.settings.mode` and, outside hosted mode (including when there
is no `ServerContext` at all, e.g. a test calling a tool function directly
with `ctx=None`), just awaits and returns `call()` with no side effect. This
is what lets `query`/`describe_checks`/`get_config` — each a single `ToolSpec`
shared across local and hosted, unlike `validate_policies`/`analyze_policy`'s
mode-gated variants — go through the same wrapper unconditionally while local
stdio mode still emits no audit records.

In hosted mode it emits exactly one JSON record per call on the
`iam_validator.mcp.audit` logger, in a `try`/`except`/`finally` so success, a
`ToolError`, a caller-side `asyncio.CancelledError`, or any other exception
all still produce a record. Fields: `timestamp`, `tool`, `subject` (the
verified `AccessToken.subject`, falling back to `client_id`, or `"anonymous"`
under `--auth none` — via `fastmcp.server.dependencies.get_access_token()`),
`scopes`, `config_digest` (`ServerContext.config_digest`), `policy_count`,
`duration_s`, `outcome` (`success`/`tool_error`/`cancelled`/`internal_error`),
and `severity_counts` (summed from each response entry's own pre-aggregated
`severity_counts`; `0`/`{}` for the three tools that submit no policies —
that's the correct value, not a reason to skip them). The record is built
only from primitives and that summed count dict — it never touches the input
policy, a finding `message`, or any other request/response field, so policy
content can't reach the log at any level. `analyze_policy` always attributes
to the caller's subject even though it spends the server's own AWS
credentials with no other per-caller attribution. Building or emitting the
record is itself wrapped in a `try`/`except`: a failure there (e.g. a broken
log sink) is logged separately at warning level and never fails the call
being observed. Local stdio mode has one user and no central aggregation, so
it never emits audit records regardless of which tool is called.

---

## Tools (6) — tagged for `--profile` gating

Every tool carries exactly one functional tag (some also carry `mutating`).
The `--profile` flag uses these tags to enable/disable groups:

| Tag         | Tools                                                                                                                                                                                                                                                                                                                    |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `validate`  | `validate_policies` (consolidates the former `validate_policy`, `quick_validate`, `validate_policies_batch`, `validate_with_config`, `check_org_compliance`, `get_policy_summary`), `describe_checks` (consolidates the former `get_issue_guidance`, `check_sensitive_actions`, `get_condition_requirements_for_action`) |
| `query`     | `query` (kind-dispatched selector; consolidates the former `query_service_actions`, `query_action_details`, `query_actions_batch`, `check_actions_batch`, `query_condition_keys`, `query_arn_formats`, `expand_wildcard_action`)                                                                                         |
| `orgconfig` | `get_config` (always available; consolidates the former `get_organization_config`, `get_active_profile`, `get_custom_instructions`), `set_config` (local/stdio only, `mutating`; consolidates the former `set_/clear_organization_config`, `load_organization_config_from_yaml`, `set_/clear_custom_instructions`)       |
| `analyze`   | `analyze_policy` (mode-gated local/hosted variants, local carries `profile`; only tool with `openWorldHint=True` — calls live AWS API; `region` bound by `ServerSettings.allowed_regions`, calls bound by `ServerSettings.analyze_rate_limit`)                                                                           |

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

## Resources (6)

Static resources cache client-side and don't count against per-turn token
budget the way tool descriptions do:

- `iam://checks` (tag `validate`) — registered check catalog (id, description,
  default_severity, plus the session-config-resolved `severity` and `enabled`)
- `iam://sensitive-categories` (tag `validate`) — sensitive-action category descriptions
- `iam://sensitive-actions/{category}` (tag `validate`) — actions for a category (parameterized)
- `iam://checks/{check_id}` (tag `validate`) — per-check docs, registry-driven (parameterized)
- `iam://config-schema` (tag `orgconfig`) — JSON Schema for session config
- `iam://config-examples` (tag `orgconfig`) — example YAML configs by security posture

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
  `set_config`; `set_config` absent over `http` even in local mode; present over `stdio`),
  and `TestToolCounts` (hosted registers exactly the 5 tools minus `set_config`; local
  registers exactly the 6 including it)
- `test_profiles.py` — `spec_survives()` profile-tag semantics with fixture specs, plus
  `build_server()`'s live tool catalog (`iam://checks` demotion, `get_config()`)
- `test_transport.py` — in-process FastMCP `Client` round-trip (annotations, resources, errors)
  against a `build_server(ServerSettings())` instance, plus a test pinning the negotiated
  `mcp.types.LATEST_PROTOCOL_VERSION` to `"2026-07-28"`
- `test_cli.py` — the shared `cli.py` argparse layer: both entry points resolve identical
  flags to an identical `ServerSettings`, `--transport sse` fails naming `http` (not
  argparse's generic "invalid choice"), `--host` defaults to `127.0.0.1`, flags win over
  `IAM_VALIDATOR_MCP_*` env vars which win over defaults, and `--auth`/`auth_explicitly_set`
  semantics, including that no `IAM_VALIDATOR_MCP_*` env var named after the field itself
  can forge `auth_explicitly_set` and unlock `mode=hosted`+`auth=none`
- `test_server_integration.py` — check catalog (incl. the hosted-baseline-not-stock-defaults
  regression), server metadata, tool/resource registration
- `test_dynamic_checks.py` — a check registered at runtime (not built in) reaches both
  `iam://checks` and `describe_checks`, across all four provenance `source` values, with
  no `iam_validator/mcp/` file hardcoding a check list; also guards that `validate_policies`'
  `format` enum tracks `FormatterRegistry.list_formatters()` minus `TERMINAL_FORMATS`, and
  that its `policy_type` short-form mapping covers every `PolicyType` literal
- `test_no_hardcoded_ids.py` — prompts/instructions and every docs page (excluding
  `docs/api-reference`, `docs/developer-guide/sdk`) never reference a retired MCP tool
  name, and every documented `--format` example / per-check YAML config stanza names a
  formatter/check the current build actually registers
- `test_tool_provenance.py` — every registered MCP tool maps to a CLI command or SDK
  export, `set_config` the sole named exemption (edits session state, an MCP-only
  concept); the deleted `templates/` package and `tools/generation.py` never reappear
- `test_no_globals.py` — `SessionConfigManager`, `CustomInstructionsManager`, and
  `merge_conditions` never reappear anywhere under `iam_validator/mcp/` (AST-checked, not
  grepped, so a docstring mention doesn't false-positive); no `global` statement or
  `lru_cache`/`cache`-memoized function reintroduces module-level mutable state
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
- `test_policy_type_input.py` — per-entry `policy_type` precedence beyond the
  single-policy cases in `test_validation_tools.py`: entry override wins over a
  run-wide override, a `name` hint resolves through a `policy_types:` config glob,
  and an SCP-shaped policy is never auto-detected without an explicit hint
- `test_hosted_startup.py` — a valid custom check still lets hosted startup verify
  and boot; an explicitly-set, unwritable `cache_directory` fails startup with
  `HostedStartupError` naming it (`_verify_writable_cache_directory`'s own
  mkdir/write probe, ahead of `AWSServiceFetcher` construction), covering both a
  non-directory path and a permission-denied directory; the writability check is
  skipped when `cache_directory` is left unset; local mode defaults to `auth="none"`
  unset
- `test_no_policy_in_logs.py` — a policy-content marker reaches no log record at
  any level, beyond the hosted-`validate_policies`-only slice `test_audit.py`
  covers: local-mode `validate_policies` and hosted `analyze_policy`
- `test_registry_reuse.py` — `_resolve_run_context` reuses `ServerContext.registry`
  across repeat `validate_policies` calls rather than rebuilding it, and a
  discovered custom check is instantiated once at startup, not per call
- `test_hosted_startup_custom_checks.py` — a declared custom check that fails to
  import exits hosted startup non-zero naming it; local mode boots with a warning
- `test_config_digest.py` — `config_digest` stability across processes, and change on
  severity edit / disable / entry-point check addition
- `test_no_tempfile.py` — `validate_policies` never calls `tempfile.NamedTemporaryFile`
  for an inline config override
- `test_auth.py` — `get_auth_provider()` per-`auth` value dispatch (none/token/jwt/
  unknown), the hosted-open guard proven load-bearing via `ServerSettings.model_construct()`
  (bypassing the constructor-time check), token source precedence/rejection, and JWT
  scope enforcement via `RSAKeyPair`-minted tokens (no network calls)
- `test_scope_gating.py` — component-level scope gating end to end: a token missing a
  scope sees neither the tool nor its equivalent resource/prompt in any list response,
  and direct `get_tool()`/`get_resource()`/`get_prompt()` return `None` rather than an
  authorization error; two tokens against the same server see different surfaces; the
  same token sees the same surface twice; `auth="none"` keeps today's unfiltered
  behavior. Uses `conftest.as_caller(*scopes)`, which sets the SDK's
  `auth_context_var` directly to simulate a request-bound token for direct
  `list_tools()`-style calls that bypass FastMCP's real transport dispatch.
- `test_audit.py` — hosted `validate_policies`/`analyze_policy`/`query`/
  `describe_checks`/`get_config` each emit exactly one audit record carrying
  every field (the latter three with `policy_count=0`/`severity_counts={}`);
  the redaction test (a marker unique to the request reaches no emitted
  record, checked at `DEBUG`); a `ToolError` path still emits a record with
  `outcome="tool_error"`; a cancelled call emits `outcome="cancelled"` rather
  than the default `success`; a raising log sink doesn't break the call it's
  observing; a malformed response shape doesn't break severity counting;
  `analyze_policy`'s record carries the caller's subject; local mode emits no
  audit record at all, for any of the five tools. The `query`/`describe_checks`/
  `get_config` multi-call test asserts the raw record count before keying by tool
  name, so a double-emission regression for one tool can't be silently collapsed
  and hidden.
- `test_cli_parity.py` — `validate_policies` and the CLI agree on findings for
  the same policy against a config that disables one check and retunes another's
  severity; the load-bearing test that the two entry points share one validation path
- `test_isolation.py` — concurrent in-process callers against one hosted server are
  never attributed to each other's identity in logs or audit records
- `test_output_schemas.py` — every registered tool declares an `output_schema`, and a
  real response validates against it and mirrors the client-facing text content
- `test_protocol_version.py` — the negotiated `mcp.types.LATEST_PROTOCOL_VERSION` is
  identical across local and hosted mode, not just the one `test_transport.py` pins
- `test_query_schema.py` — each `query` `kind` branch's required parameter is enforced
  by the declared `inputSchema` (schema-level, not just a runtime `ToolError`)
- `test_health_routes.py` — `asgi.py`'s `/health`/`/ready`: payload shape
  (`version`/`config_digest`/`config_source`), `/ready`'s 503→200 transition tracking
  `context.ready` across the lifespan's `prewarm()`, and — with `/mcp` itself as the
  control — that both routes bypass the Origin guard and the hosted auth provider that
  `/mcp` still enforces

Mock fetcher / network — no real API or AWS calls. `conftest.py`'s three autouse
fixtures: `_no_real_aws_fetcher`/`_no_real_aws_fetcher_in_context` redirect
`policy_checks.AWSServiceFetcher`/`context.AWSServiceFetcher` construction to
`mock_fetcher`, so a test driving `validate_policies()` or a real server lifespan
never reaches `servicereference.us-east-1.amazonaws.com`; `_no_real_aws_cache_dir`
patches `AWSServiceFetcher.__init__` itself, so a test that constructs the real class
directly (bypassing the two module-scoped patches above by importing the class itself)
still gets a `tmp_path` cache directory instead of `~/Library/Caches/iam-validator`
whenever it leaves `cache_dir` unset. Debug interactively via `mise run mcp:inspector`.
Requires `fastmcp>=4.0,<5` (installed via `uv sync --extra mcp`).

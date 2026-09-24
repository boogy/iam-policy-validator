---
title: MCP Hosting
description: Deploy the IAM Policy Validator MCP server as a shared, multi-tenant HTTP service
---

# Hosting the MCP Server

[MCP Server Integration](mcp-server.md) covers **local mode**: one process per user,
launched by an AI assistant over `stdio`, with no authentication. This page covers
**hosted mode** (`--mode hosted` / `IAM_VALIDATOR_MCP_MODE=hosted`): a shared server
over HTTP, with authentication, an operator-owned immutable config, audit logging,
and a production ASGI entry point. For running that same hosted server on AWS Lambda
instead of a container, see [MCP Lambda](mcp-lambda.md).

## Local vs. hosted, at a glance

| | Local | Hosted |
| --- | --- | --- |
| Transport | `stdio` | HTTP (Streamable HTTP) |
| Auth | none | required (`--auth` must be set explicitly) |
| Config | can be overridden per session via `set_config` | resolved once at startup, immutable for the process lifetime |
| Filesystem access | `validate_policies` accepts `path`/`glob` | not available — inline policies only |
| `analyze_policy` credentials | caller's own AWS profile (`profile` param) | the server's own credentials; no `profile` param |
| Audit logging | none | one JSON record per tool call |

## Enabling hosted mode

```bash
iam-validator-mcp --mode hosted --transport http --auth token --config ./config.yaml
```

`mode='hosted'` refuses to start with `auth='none'` unless `--auth none` was passed
*explicitly* — there's no way to silently end up with an unauthenticated IAM tool
exposed over HTTP.

## Auth providers

Set with `--auth`/`IAM_VALIDATOR_MCP_AUTH`: `none` (hosted mode requires this be
explicit), `token` (static bearer tokens), `jwt`, or an identity provider name —
`azure`, `google`, `github`, `keycloak`, `auth0`, `workos`.

All provider material (token files, JWT keys, IdP client secrets) comes from
`IAM_VALIDATOR_MCP_AUTH_*` environment variables or a file path they name — **never**
a CLI flag, which would land in shell history, `ps` output, and container-inspect
output. For example, `--auth token` requires `IAM_VALIDATOR_MCP_AUTH_TOKEN_FILE` (a
path) or `IAM_VALIDATOR_MCP_AUTH_TOKENS` (inline JSON mapping token → `{client_id,
scopes?}`); `--auth jwt` requires `IAM_VALIDATOR_MCP_AUTH_JWT_ISSUER`,
`_JWT_AUDIENCE`, and exactly one of `_JWT_JWKS_URI` / `_JWT_PUBLIC_KEY`.

### Scope-based tool gating

A token's scopes determine which tools/resources/prompts it can see, via a
scope → tag mapping:

| Scope | Tag | Gates |
| --- | --- | --- |
| `iam:validate` | `validate` | `validate_policies`, `describe_checks` |
| `iam:query` | `query` | `query` |
| `iam:analyze` | `analyze` | `analyze_policy` |
| `iam:config` | `orgconfig` | `get_config` (`set_config` never registers in hosted mode) |

A caller missing a scope doesn't see an authorization error — the tool (and its
resource twin, e.g. `iam://checks` for `iam:validate`) is simply absent from
`list_tools()`/`list_resources()`, so an unauthorized caller can't even discover the
scope taxonomy.

## Immutable config and `config_digest`

In hosted mode, the config named by `--config`/`IAM_VALIDATOR_MCP_CONFIG` is resolved
once at process startup and never reread — `set_config` doesn't register at all in
hosted mode, so there is no way to mutate it short of redeploying. A missing,
unreadable, schema-invalid config file, or a declared custom check that fails to
import, fails startup outright rather than falling back to defaults.

Every startup computes a `config_digest`: a stable SHA-256 over the resolved config
plus each check's `(id, source, enabled, severity)` — the registry is included, not
just the YAML, because a check can be added via an installed package's entry point
without appearing in the config file at all. `get_config` returns it, and every
`validate_policies` response carries it as `config_digest`, so a finding can always
be traced back to the exact config version that produced it.

## Request limits

Five `ServerSettings` limits bound what a hosted `validate_policies`/`analyze_policy`
call can cost, each raising a client-visible error when exceeded (`max_response_bytes`
degrades the response instead — dropping `summary`, then `issues`, then whole
entries — before falling back to truncation):

| Setting | Env var | Default |
| --- | --- | --- |
| `--max-policies` | `IAM_VALIDATOR_MCP_MAX_POLICIES` | 50 |
| `--max-policy-bytes` | `IAM_VALIDATOR_MCP_MAX_POLICY_BYTES` | 1 MiB |
| `--max-request-bytes` | `IAM_VALIDATOR_MCP_MAX_REQUEST_BYTES` | 8 MiB |
| `--request-timeout-s` | `IAM_VALIDATOR_MCP_REQUEST_TIMEOUT_S` | 60s |
| `--max-response-bytes` | `IAM_VALIDATOR_MCP_MAX_RESPONSE_BYTES` | 4 MiB |

`analyze_policy` is separately bounded by `--allowed-regions` (default: the server's
own AWS region only) and `--analyze-rate-limit` (default 10/min — a best-effort
in-process guard, not an AWS quota), since it spends the server's own AWS credentials
and `access-analyzer:ValidatePolicy` quota on every call.

## Audit logging

Every hosted tool call emits exactly one JSON record on the
`iam_validator.mcp.audit` logger — on success, a tool error, a cancellation, or any
other exception. Fields: `timestamp`, `tool`, `subject` (the authenticated caller, or
`"anonymous"` under `--auth none`), `scopes`, `config_digest`, `policy_count`,
`duration_s`, `outcome`, and `severity_counts`. The record is built only from these
primitives — it never includes policy content, a finding message, or any other
request/response field, so policy content cannot reach the audit log at any level.
Local/stdio mode never emits audit records.

## Production ASGI serving

`iam-validator-mcp --transport http` (or `iam-validator mcp --transport http`) is a
local, single-process server suitable for development. For production, run the ASGI
app factory under a real server:

```bash
uvicorn iam_validator.mcp.asgi:create_app --factory --host 0.0.0.0 --port 8000
```

`create_app()` builds one `ServerContext` and mounts the FastMCP app (with
`stateless_http=True` and `host_origin_protection="auto"`, the MCP-required
DNS-rebinding guard) under `/mcp`, alongside two outer, unauthenticated routes:

- **`GET /health`** — liveness only: `{status, uptime_s, version, config_digest,
  config_source}`.
- **`GET /ready`** — readiness: config resolved, registry built, AWS service data
  warm; 503 until all three are true, 200 after.

`config_source` in both payloads reports only the **kind** of config source
(`"file"` or `"none"`) — never the filesystem path — since these routes are
deliberately unauthenticated for load-balancer/orchestrator probes. They're declared
as routes on the *outer* Starlette app rather than `@mcp.custom_route`s specifically
so they never pass through the mounted FastMCP app's Origin guard or auth provider;
`/mcp` itself still enforces both.

The server binds `127.0.0.1` by default; `0.0.0.0` is an explicit opt-in via
`--host`/`IAM_VALIDATOR_MCP_HOST` (the Docker image below sets it).

## Docker image

The repository root `Dockerfile` builds a hosted-mode image: it bakes AWS service
reference data at build time (`iam-validator sync-services`) so the running container
makes no outbound calls, installs the package as a built wheel rather than an
editable source tree, runs as a non-root user, and never sets `PYTHONOPTIMIZE`/`-O`
(would strip the docstrings `describe_checks` reads as each check's description). It
deliberately leaves `IAM_VALIDATOR_MCP_AUTH` and any config file unset — you must
supply `--auth`/`IAM_VALIDATOR_MCP_AUTH` and, if needed,
`--config`/`IAM_VALIDATOR_MCP_CONFIG` yourself. `IAM_VALIDATOR_MCP_CACHE_DIRECTORY`
points at `/tmp/iam-validator-cache`; under a read-only container root filesystem,
mount a writable volume there or run with `--tmpfs /tmp`, or startup fails.

```bash
docker build -t iam-validator-mcp .
docker run -p 8000:8000 \
  -e IAM_VALIDATOR_MCP_AUTH=token \
  -e IAM_VALIDATOR_MCP_AUTH_TOKENS='{"secret-token": {"client_id": "example"}}' \
  iam-validator-mcp
```

## Reverse proxy requirements

Behind a reverse proxy, disable response buffering for the `/mcp` Streamable HTTP
stream (`proxy_buffering off;` on nginx, plus `X-Accel-Buffering: no`) and raise
`proxy_read_timeout` — a buffered or prematurely closed connection breaks the MCP
protocol's server-sent-event stream.

## Offline operation

`iam-validator sync-services --output-dir ./aws_services` downloads AWS service
reference data ahead of time; point `--aws-services-dir`/
`IAM_VALIDATOR_MCP_AWS_SERVICES_DIR` at that directory so a hosted deployment (or an
air-gapped one) makes no outbound calls to `servicereference.us-east-1.amazonaws.com`
at runtime. The Docker image does this at build time.

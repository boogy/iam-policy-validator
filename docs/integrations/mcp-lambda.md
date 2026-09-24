---
title: MCP Lambda
description: Run the hosted MCP server as an AWS Lambda function behind a Function URL or API Gateway
---

# Running the MCP Server on AWS Lambda

[MCP Hosting](mcp-hosting.md) covers the container/uvicorn deployment. This page covers the
alternative: `iam_validator.mcp.awslambda`, an AWS Lambda entry point for the same hosted
server, fronted by a Lambda Function URL or API Gateway instead of a long-running process.

## When to choose it

Bursty, low-volume internal traffic where a container's idle cost (and the cluster it runs
on) isn't worth it. Lambda also removes one hosted-mode wrinkle: `analyze_policy`'s AWS
credentials come from the function's execution role via the default credential chain,
rather than a profile mounted into a container.

It is still **hosted mode** underneath — the same immutable startup config,
`config_digest`, request limits, audit logging and scope gating described in
[MCP Hosting](mcp-hosting.md) apply unchanged. This page only covers what changes under
Lambda.

## The handler module

`iam_validator/mcp/awslambda.py` wraps `asgi.py`'s `create_app()` in a
[Mangum](https://mangum.io/) adapter. Install it with the `lambda` extra (adds Mangum on
top of `mcp`):

```bash
pip install "iam-policy-validator[mcp,lambda]"
```

There is no command line under Lambda — `create_handler()` always resolves configuration
from `IAM_VALIDATOR_MCP_*` environment variables via `ServerSettings.from_env()`. The
Lambda runtime resolves the handler as `iam_validator.mcp.awslambda.handler`, built lazily
on first attribute access so importing the module has no side effect.

## `json_response=True`, and what it forbids

The handler builds its app with `json_response=True`. Python's managed Lambda runtime
cannot stream a response body (only Node.js managed runtimes and custom runtimes on
Function URLs can), and API Gateway buffers the body regardless of what the app sends — so
a `text/event-stream` response never reaches the caller usably.

This constrains every tool call to a single request/response: no progress notification, no
logging notification, no sampling request may be sent mid-call, or it is silently dropped.
An AST-based test (`tests/mcp/test_json_response.py`) statically forbids any handler under
`iam_validator/mcp/` from calling a server-initiated `Context` method, so this can't regress
unnoticed. `GET /mcp` — the optional SSE-only channel — answers `405`, which is conformant:
the MCP spec never requires it.

## `/tmp` is the only writable path

`/tmp` is the only writable filesystem in the Lambda execution environment.
`IAM_VALIDATOR_MCP_CACHE_DIRECTORY` must point under it. Treat this as a
within-environment optimization, not a cache: a cold-started (recycled) environment starts
with an empty `/tmp`, so a cache miss on AWS service data after a cold start is expected,
not a bug.

Bake the AWS service reference data into the image at build time
(`iam-validator sync-services`) and point `IAM_VALIDATOR_MCP_AWS_SERVICES_DIR` at it — the
provided `Dockerfile`'s `lambda` target already does both. This is **mandatory** here, not
just an optimization: a VPC-attached function with no NAT gateway or VPC endpoint has no
outbound network access at all, so a runtime fetch from
`servicereference.us-east-1.amazonaws.com` would simply fail.

## Timeouts

Set `IAM_VALIDATOR_MCP_REQUEST_TIMEOUT_S` (default 60s) below the Lambda function's own
configured timeout, so an over-long validation returns a `ToolError` the calling model can
act on, rather than the function being killed mid-response and the caller seeing a bare 502.

**An HTTP API Gateway integration hard-caps at 30 seconds**, regardless of the function's
own timeout. Prefer a **Lambda Function URL** as the front end — it allows up to the
function's own configured timeout — and reserve API Gateway for deployments that need its
authorizers or usage plans and can live within that 30s cap.

## Auth: two supported shapes

Both are set via `IAM_VALIDATOR_MCP_AUTH`, same as any other hosted deployment (see
[Auth providers](mcp-hosting.md#auth-providers)):

- **`jwt`** — self-contained: the process verifies the bearer JWT itself
  (`IAM_VALIDATOR_MCP_AUTH_JWT_ISSUER`, `_JWT_AUDIENCE`, and one of `_JWT_JWKS_URI` /
  `_JWT_PUBLIC_KEY`). A JWKS URI needs outbound access to the IdP, or a VPC endpoint if the
  function has no NAT gateway; the fetched JWKS is cached in-process (an hour's TTL), so —
  like the AWS service data above — that cache lives only as long as the execution
  environment does, and a cold start pays a fresh JWKS fetch.
- **`aws-gateway`** — auth terminates *upstream* of this process, at a Function URL with
  `AuthType: AWS_IAM`, or at an API Gateway route with a JWT authorizer. The provider
  (`auth.py:AwsGatewayAuthProvider`) never reads a bearer token itself; it reads
  already-verified claims out of the Lambda event's `requestContext.authorizer` — the
  `jwt.claims` shape for an API Gateway JWT authorizer, or the `iam` shape for
  `AuthType: AWS_IAM`. A JWT authorizer's claims carry scopes, same as any other `jwt`
  auth; `AuthType: AWS_IAM` authenticates the caller but carries no OAuth scopes at all,
  so every one of hosted mode's five tools — all scope-gated (see [Scope-based tool
  gating](mcp-hosting.md#scope-based-tool-gating)) — is hidden from that caller's
  `list_tools()`.

`--auth none` behind a gateway authorizer is **wrong**, not just weaker: API Gateway or the
Function URL still authenticates the caller, but with `--auth none` this process then hands
every authenticated caller the *entire* tool surface, silently discarding the scope model —
the authorizer did real work and this process throws its result away.

`aws-gateway` must never be paired with a Function URL configured `AuthType: NONE` — that
would let an unauthenticated caller reach the adapter directly, with no `requestContext.authorizer`
block for it to trust (which the backend already treats as an unauthenticated request, but
silently, not as a startup failure). `create_handler()` makes a best-effort check of this at
startup (`lambda:GetFunctionUrlConfig` against the function's own name) and refuses to start
if it detects `AuthType: NONE`. When it *can't* check — no `AWS_LAMBDA_FUNCTION_NAME`, no
`lambda:GetFunctionUrlConfig` permission, no network — it logs a warning and starts anyway.
Verifying the Function URL's `AuthType` is then the operator's responsibility.

!!! note "Why aws-gateway needs a placeholder header"

    FastMCP's own `RequireAuthMiddleware` rejects any request with no `Authorization`
    header before it ever looks at the authenticated user — which would reject every
    legitimate `aws-gateway` request, since that provider is designed to never send one.
    The handler wraps the app in `_SatisfyBearerPresenceGate`, which adds a fixed,
    non-secret placeholder `Authorization` header only when the request has none. Nothing
    ever reads that header back for identity; identity and scopes still come solely from
    `requestContext`.

## `analyze_rate_limit` is not a quota

`ServerSettings.analyze_rate_limit` (default 10/min) is a best-effort, in-process,
per-worker counter. Under Lambda, "per-worker" means per execution environment: N
concurrent environments give you N independent counters, effectively multiplying the limit
by N. The same caveat applies to any multi-replica container deployment — this isn't
Lambda-specific, Lambda just makes the concurrency more elastic and therefore the multiplier
larger and less predictable.

The controls that actually hold a ceiling are Lambda reserved concurrency, API Gateway usage
plans, and the `iam:analyze` OAuth scope — the scope is the only one of the three this
server enforces exactly, since it's a yes/no gate rather than a counter.

## Cold start

Config resolution, registry construction, custom-check imports, and the `config_digest`
computation all run once per cold execution environment. Mangum runs the ASGI `lifespan` on
the *first invocation* an environment handles (`lifespan="on"`), not before the environment
is ready to accept requests — so that cost lands on a request's latency, not on a separate
init phase. Provisioned concurrency removes it entirely where latency matters.

**AWS SnapStart is not enabled by default.** A restored snapshot would resurrect a cached
JWKS set, a live httpx connection pool, and any seeded RNG state — none of which should
survive a snapshot restore unexamined. Adopting SnapStart safely needs restore hooks that
reset all three; that work isn't done here.

## Packaging

Lambda deployment is a **container image**, not a zip archive: boto3, httpx, pydantic,
fastmcp and the baked AWS service reference data don't fit comfortably inside the 250 MB
unzipped zip-package limit. The container image path has no equivalent size pressure (10 GB
per image), so it isn't a constraint here.

One `Dockerfile` serves both deployment targets: `docker build --target lambda` builds the
Lambda image (`public.ecr.aws/lambda/python:3.13` base, the `lambda` extra pulled in on top
of `mcp`); the default target (no `--target`) builds the uvicorn container from [MCP
Hosting](mcp-hosting.md). `/health` and `/ready` stay registered in the Lambda image — they
come along for free since both targets share `asgi.py:create_app()` — but nothing calls
them: Lambda has no liveness/readiness probes of its own.

## Worked deployment

This walks through building the Lambda image, pushing it to ECR, creating the function
behind a Function URL, and confirming it answers an `initialize` call. It uses `--auth jwt`
to keep the `curl` step a plain bearer token; see [Auth](#auth-two-supported-shapes) above
for `aws-gateway`, which needs a SigV4-signed request instead of a bearer token once the
Function URL is `AuthType: AWS_IAM`.

Hosted mode always requires an explicit config file (`IAM_VALIDATOR_MCP_CONFIG`) — there's
no ambient discovery. Bake one into the image on top of the repo's `lambda` target:

```dockerfile
# Dockerfile.lambda-with-config — layered on top of the repo's own lambda target
FROM iam-validator-mcp:lambda-base
COPY my-config.yaml ${LAMBDA_TASK_ROOT}/my-config.yaml
```

```bash
# Build and push
export AWS_REGION=us-east-1
export ACCOUNT_ID=123456789012
export REPO=iam-validator-mcp

aws ecr create-repository --repository-name "$REPO" --region "$AWS_REGION"
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

docker build --target lambda -t iam-validator-mcp:lambda-base .
docker build -f Dockerfile.lambda-with-config -t "$REPO:lambda" .
docker tag "$REPO:lambda" "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO:lambda"
docker push "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO:lambda"

# Create the function
aws lambda create-function \
  --function-name iam-validator-mcp \
  --package-type Image \
  --code ImageUri="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO:lambda" \
  --role arn:aws:iam::"$ACCOUNT_ID":role/iam-validator-mcp-lambda-role \
  --timeout 60 \
  --memory-size 512 \
  --environment "Variables={
    IAM_VALIDATOR_MCP_CONFIG=/var/task/my-config.yaml,
    IAM_VALIDATOR_MCP_AUTH=jwt,
    IAM_VALIDATOR_MCP_AUTH_JWT_ISSUER=https://idp.example.com/,
    IAM_VALIDATOR_MCP_AUTH_JWT_AUDIENCE=iam-validator-mcp,
    IAM_VALIDATOR_MCP_AUTH_JWT_JWKS_URI=https://idp.example.com/.well-known/jwks.json,
    IAM_VALIDATOR_MCP_REQUEST_TIMEOUT_S=45
  }"

# Expose it — AuthType=NONE is correct here because --auth jwt does its own
# verification at the application layer; nothing downstream is unauthenticated.
aws lambda create-function-url-config --function-name iam-validator-mcp --auth-type NONE
aws lambda add-permission \
  --function-name iam-validator-mcp \
  --action lambda:InvokeFunctionUrl \
  --principal "*" \
  --function-url-auth-type NONE \
  --statement-id FunctionURLAllowPublicAccess
```

Confirm it answers an `initialize` call (the server accepts a request whether or not the
requested `protocolVersion` matches exactly — it negotiates down to a version it supports):

```bash
FUNCTION_URL=$(aws lambda get-function-url-config --function-name iam-validator-mcp --query FunctionUrl --output text)

curl -sS -X POST "${FUNCTION_URL}mcp" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2026-07-28",
      "capabilities": {},
      "clientInfo": {"name": "curl-example", "version": "0.1"}
    }
  }'
```

A healthy server responds `200` with a JSON-RPC `result` carrying its negotiated
`protocolVersion`, `capabilities`, and `serverInfo` — as a single JSON body, never an
event stream.

## See also

- [MCP Hosting](mcp-hosting.md) — the container/uvicorn deployment this page builds on:
  auth providers, scope-based tool gating, immutable config and `config_digest`, request
  limits, and audit logging all apply unchanged under Lambda.

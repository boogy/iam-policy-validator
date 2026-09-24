# syntax=docker/dockerfile:1
#
# Hosted MCP server image. See iam_validator/mcp/CLAUDE.md.

FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# WORKDIR must match the runtime stage: venv console-script shebangs are baked to this path.
WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY iam_validator ./iam_validator

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --extra mcp --no-dev --no-editable

# Invoked directly, not via `uv run` -- `uv run` re-syncs and reverts to an editable install.
RUN /app/.venv/bin/iam-validator sync-services --output-dir /app/aws_services --max-concurrent 10

FROM python:3.13-slim AS runtime

# Never PYTHONOPTIMIZE/-O: strips docstrings that describe_checks reads as catalog descriptions.

RUN groupadd --system --gid 1000 iamvalidator \
    && useradd --system --uid 1000 --gid iamvalidator --no-create-home iamvalidator

WORKDIR /app

# Source tree is deliberately not copied here -- it would shadow the installed wheel.
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/aws_services /app/aws_services

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    IAM_VALIDATOR_MCP_MODE=hosted \
    IAM_VALIDATOR_MCP_AWS_SERVICES_DIR=/app/aws_services \
    IAM_VALIDATOR_MCP_CACHE_DIRECTORY=/tmp/iam-validator-cache \
    IAM_VALIDATOR_MCP_HOST=0.0.0.0 \
    IAM_VALIDATOR_MCP_PORT=8000

USER iamvalidator

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

# Reverse-proxy requirements (SSE buffering, timeouts) are documented separately;
# see iam_validator/mcp/CLAUDE.md.
CMD ["uvicorn", "iam_validator.mcp.asgi:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]

# --- AWS Lambda container image (`docker build --target lambda`) ---
# Separate builder stage: adds the `lambda` extra (Mangum) on top of `mcp`, kept out
# of the uvicorn `runtime` image above since it's unused there.
FROM python:3.13-slim AS builder-lambda

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY iam_validator ./iam_validator

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --extra mcp --extra lambda --no-dev --no-editable

RUN /app/.venv/bin/iam-validator sync-services --output-dir /app/aws_services --max-concurrent 10

FROM public.ecr.aws/lambda/python:3.13 AS lambda

# Never PYTHONOPTIMIZE/-O: strips docstrings that describe_checks reads as catalog descriptions.

COPY --from=builder-lambda /app/.venv/lib/python3.13/site-packages/. ${LAMBDA_TASK_ROOT}/
COPY --from=builder-lambda /app/aws_services ${LAMBDA_TASK_ROOT}/aws_services

ENV IAM_VALIDATOR_MCP_MODE=hosted \
    IAM_VALIDATOR_MCP_AWS_SERVICES_DIR=${LAMBDA_TASK_ROOT}/aws_services \
    IAM_VALIDATOR_MCP_CACHE_DIRECTORY=/tmp/iam-validator-cache

# An operator must still supply IAM_VALIDATOR_MCP_AUTH and IAM_VALIDATOR_MCP_CONFIG
# (hosted mode refuses to start without an explicit config file); see
# iam_validator/mcp/CLAUDE.md's Lambda section for the AuthType=NONE self-check and
# the json_response/no-streaming constraints this handler runs under.
CMD ["iam_validator.mcp.awslambda.handler"]

"""AWS Access Analyzer integration for MCP.

Wraps the sync :class:`AccessAnalyzerValidator` in ``asyncio.to_thread`` so an
async MCP tool can call it without blocking the event loop. ``analyze_policy``
is the only registered tool with ``openWorldHint=True`` (it calls a live AWS
API) and the only one that spends the server's own AWS credentials: the
``region`` allowlist (``ServerSettings.allowed_regions``) and
``AnalyzeRateLimiter`` (``ServerSettings.analyze_rate_limit``) bound that
exposure. ``profile`` is local-mode only -- a client must not select among
credential profiles on a shared host.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from fastmcp import Context
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from iam_validator.mcp.component_spec import ToolSpec, infer_output_schema
from iam_validator.mcp.context import get_aws_session, get_server_context

if TYPE_CHECKING:
    import boto3


async def analyze_policy(
    policy: dict[str, Any],
    policy_type: str = "IDENTITY_POLICY",
    region: str = "us-east-1",
    profile: str | None = None,
    session: boto3.Session | None = None,
) -> dict[str, Any]:
    """Run AWS Access Analyzer ValidatePolicy on a policy dict.

    Args:
        policy: Policy as a dict (Version + Statement).
        policy_type: One of "IDENTITY_POLICY", "RESOURCE_POLICY",
            "SERVICE_CONTROL_POLICY". RESOURCE_CONTROL_POLICY and TRUST_POLICY
            are not currently exposed by the underlying enum.
        region: AWS region for the Access Analyzer API call. Ignored for
            session/client construction when ``session`` is provided; only
            recorded on the validator for logging.
        profile: Optional AWS profile name. Same: ignored when ``session`` is
            provided.
        session: Pre-built boto3.Session. When supplied, the boto3 client is
            created from this session and ``region``/``profile`` are NOT used
            to construct the session (they're still passed through to the
            validator's ``self.region`` / ``self.profile`` for log lines).

    Returns:
        ``{findings, finding_count}``. Each finding has finding_type, issue_code,
        message, learn_more_link, locations.

    Raises:
        ToolError: AWS credentials missing, bad policy_type, or API failure.
    """
    from iam_validator.core.access_analyzer import AccessAnalyzerValidator, PolicyType

    try:
        pt = PolicyType(policy_type)
    except ValueError as e:
        raise ToolError(
            f"Invalid policy_type '{policy_type}'. Allowed: IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY."
        ) from e

    try:
        if session is not None:
            validator = AccessAnalyzerValidator(region=region, policy_type=pt, session=session)
        else:
            validator = AccessAnalyzerValidator(region=region, policy_type=pt, profile=profile)
        findings = await asyncio.to_thread(validator.validate_policy, policy)
    except NoCredentialsError as e:
        raise ToolError(
            f"AWS credentials required. Configure AWS_PROFILE/env vars or pass profile=. Detail: {e}"
        ) from e
    except ClientError as e:
        err = e.response.get("Error", {})
        raise ToolError(f"AWS API error {err.get('Code', '?')}: {err.get('Message', str(e))}") from e
    except BotoCoreError as e:
        raise ToolError(f"AWS SDK error: {e}") from e

    return {
        "findings": [
            {
                "finding_type": (f.finding_type.value if hasattr(f.finding_type, "value") else str(f.finding_type)),
                "issue_code": f.issue_code,
                "message": f.message,
                "learn_more_link": f.learn_more_link,
                "locations": f.locations,
            }
            for f in findings
        ],
        "finding_count": len(findings),
    }


# =============================================================================
# MCP tool wrapper (registered via TOOLS below)
# =============================================================================


async def _analyze_policy_tool_impl(
    policy: dict[str, Any],
    ctx: Context,
    policy_type: str,
    partition: str,
    region: str | None,
    profile: str | None,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Shared body for the local and hosted ``analyze_policy`` tool variants.

    Raises:
        ToolError: bad policy_type, unsupported partition, region outside
            ``ServerSettings.allowed_regions``, rate limit exceeded, missing
            AWS credentials, AWS API failure, or timeout.
    """
    from iam_validator.core.constants import PARTITION_DEFAULT_REGION

    if partition not in PARTITION_DEFAULT_REGION:
        raise ToolError(f"Unsupported partition '{partition}'. Allowed: {', '.join(sorted(PARTITION_DEFAULT_REGION))}.")

    effective_region = region or PARTITION_DEFAULT_REGION[partition]

    context = get_server_context(ctx)
    if context is not None:
        allowed_regions = context.settings.allowed_regions
        if allowed_regions and effective_region not in allowed_regions:
            raise ToolError(
                f"region '{effective_region}' is not allowed on this server. "
                f"Allowed regions: {', '.join(sorted(allowed_regions))}."
            )
        if not context.analyze_rate_limiter.allow():
            raise ToolError(
                f"analyze_policy rate limit exceeded ({context.settings.analyze_rate_limit}/min). "
                "This is a best-effort per-process guard, not a quota; retry shortly."
            )

    session = get_aws_session(ctx, effective_region, profile)
    try:
        return await asyncio.wait_for(
            analyze_policy(
                policy=policy,
                policy_type=policy_type,
                region=effective_region,
                profile=profile,
                session=session,
            ),
            timeout=timeout_seconds,
        )
    except asyncio.TimeoutError as e:
        raise ToolError(f"AWS Access Analyzer call timed out after {timeout_seconds}s.") from e


async def _analyze_policy_tool(
    policy: dict[str, Any],
    ctx: Context,
    policy_type: str = "IDENTITY_POLICY",
    partition: str = "aws",
    region: str | None = None,
    profile: str | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Run AWS Access Analyzer ValidatePolicy against the policy.

    This tool calls the live AWS Access Analyzer API and requires AWS
    credentials. Complements ``validate_policies`` by surfacing AWS-only
    checks (deprecated globals, type-specific rules). Slower than
    ``validate_policies`` because it incurs an HTTP round-trip per call.

    Args:
        policy: IAM policy dict (Version + Statement).
        policy_type: One of "IDENTITY_POLICY", "RESOURCE_POLICY",
            "SERVICE_CONTROL_POLICY".
        partition: AWS partition (aws, aws-cn, aws-us-gov, aws-eusc,
            aws-iso, aws-iso-b, aws-iso-e, aws-iso-f). Used to default
            ``region`` if omitted.
        region: AWS region for the API call. When omitted, defaults to the
            canonical region for the chosen ``partition`` (e.g. ``aws-cn`` →
            ``cn-north-1``). Must be one of ``ServerSettings.allowed_regions``
            when that allowlist is non-empty.
        profile: Optional AWS credential profile name on the local host.
        timeout_seconds: Hard timeout on the AWS API call (default 30s).
            Prevents an unresponsive AWS endpoint from blocking the MCP server.

    Returns:
        ``{findings: [...], finding_count: int}``. Each finding has
        ``finding_type``, ``issue_code``, ``message``, ``learn_more_link``,
        ``locations``.
    """
    return await _analyze_policy_tool_impl(policy, ctx, policy_type, partition, region, profile, timeout_seconds)


async def _analyze_policy_tool_hosted(
    policy: dict[str, Any],
    ctx: Context,
    policy_type: str = "IDENTITY_POLICY",
    partition: str = "aws",
    region: str | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Run AWS Access Analyzer ValidatePolicy against the policy.

    This tool calls the live AWS Access Analyzer API using the server's own
    AWS credentials and spends the account's ``access-analyzer:ValidatePolicy``
    quota on every call, with no per-caller attribution. There is no
    ``profile`` parameter in hosted mode: a client cannot select among
    credential profiles on the server host. Complements ``validate_policies``
    by surfacing AWS-only checks (deprecated globals, type-specific rules).

    Args:
        policy: IAM policy dict (Version + Statement).
        policy_type: One of "IDENTITY_POLICY", "RESOURCE_POLICY",
            "SERVICE_CONTROL_POLICY".
        partition: AWS partition (aws, aws-cn, aws-us-gov, aws-eusc,
            aws-iso, aws-iso-b, aws-iso-e, aws-iso-f). Used to default
            ``region`` if omitted.
        region: AWS region for the API call. When omitted, defaults to the
            canonical region for the chosen ``partition``. Must be one of
            ``ServerSettings.allowed_regions`` when that allowlist is
            non-empty (default: the server's own region only).
        timeout_seconds: Hard timeout on the AWS API call (default 30s).
            Prevents an unresponsive AWS endpoint from blocking the MCP server.

    Returns:
        ``{findings: [...], finding_count: int}``. Each finding has
        ``finding_type``, ``issue_code``, ``message``, ``learn_more_link``,
        ``locations``.

    Emits one audit record per call, carrying the authenticated subject (see
    mcp/audit.py); local mode does not.
    """
    from iam_validator.mcp.audit import audited_call

    return await audited_call(
        "analyze_policy",
        ctx,
        1,
        lambda: _analyze_policy_tool_impl(policy, ctx, policy_type, partition, region, None, timeout_seconds),
    )


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        tag="analyze",
        name="analyze_policy",
        fn=_analyze_policy_tool,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
        output_schema=infer_output_schema(_analyze_policy_tool),
        modes=frozenset({"local"}),
    ),
    ToolSpec(
        tag="analyze",
        name="analyze_policy",
        fn=_analyze_policy_tool_hosted,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
        output_schema=infer_output_schema(_analyze_policy_tool_hosted),
        modes=frozenset({"hosted"}),
    ),
)


__all__ = ["analyze_policy", "TOOLS"]

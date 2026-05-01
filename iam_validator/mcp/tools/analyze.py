"""AWS Access Analyzer integration for MCP.

Wraps the existing sync :class:`AccessAnalyzerValidator` in
``asyncio.to_thread`` so an MCP async tool can call it without blocking the
event loop. The MCP wrapper in ``server.py`` passes a cached
:class:`boto3.Session` to avoid re-creating sessions per call.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from fastmcp.exceptions import ToolError

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


__all__ = ["analyze_policy"]

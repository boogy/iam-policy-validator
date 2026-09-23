"""Per-entry policy_type resolution beyond the single-policy cases in test_validation_tools.py."""

from types import SimpleNamespace

from iam_validator.core.config.config_loader import ValidatorConfig
from iam_validator.core.policy_checks import build_registry
from iam_validator.core.report import ReportGenerator
from iam_validator.mcp.context import ServerContext
from iam_validator.mcp.settings import ServerSettings
from iam_validator.mcp.tools.validate import validate_policies

_IDENTITY_SHAPED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
}


def _fake_ctx(context: ServerContext) -> SimpleNamespace:
    return SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))


def _build_context(config: ValidatorConfig) -> ServerContext:
    return ServerContext(
        config=config,
        registry=build_registry(config),
        formatters=ReportGenerator(),
        fetcher=None,
        aws_sessions={},
        settings=ServerSettings(),
        mutable=None,
        config_digest="test-digest",
    )


async def test_entry_override_wins_over_run_wide_policy_type():
    response = await validate_policies(
        policies=[{"policy": _IDENTITY_SHAPED_POLICY, "policy_type": "trust"}],
        policy_type="resource",
    )
    entry = response["results"][0]
    assert entry["policy_type"] == "TRUST_POLICY"
    assert entry["policy_type_source"] == "cli-flag"


async def test_name_hint_resolves_rcp_through_config_glob():
    config = ValidatorConfig({"policy_types": [{"pattern": "**/rcp/*.json", "type": "RESOURCE_CONTROL_POLICY"}]})
    ctx = _fake_ctx(_build_context(config))

    response = await validate_policies(
        policies=[{"policy": _IDENTITY_SHAPED_POLICY, "name": "policies/rcp/deny-region.json"}],
        ctx=ctx,
    )
    entry = response["results"][0]
    assert entry["policy_type"] == "RESOURCE_CONTROL_POLICY"
    assert entry["policy_type_source"] == "config-glob"


async def test_scp_shaped_policy_without_hints_is_never_auto_detected():
    response = await validate_policies(policies=[_IDENTITY_SHAPED_POLICY])
    entry = response["results"][0]
    assert entry["policy_type"] == "IDENTITY_POLICY"
    assert entry["policy_type_source"] == "default"

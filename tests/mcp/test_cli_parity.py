"""The hosted server must validate exactly the way the CLI does, config overrides included."""

from types import SimpleNamespace

from iam_validator.core.config.config_loader import ConfigLoader
from iam_validator.core.models import IAMPolicy
from iam_validator.core.policy_checks import build_registry
from iam_validator.core.policy_checks import validate_policies as sdk_validate_policies
from iam_validator.core.report import ReportGenerator
from iam_validator.mcp.context import ServerContext
from iam_validator.mcp.settings import ServerSettings
from iam_validator.mcp.tools.validate import validate_policies

_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "WildcardEverything", "Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Sid": "CreateKey", "Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
    ],
}


def _fake_ctx(context: ServerContext) -> SimpleNamespace:
    return SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))


async def test_cli_and_mcp_agree_under_a_retuned_config(tmp_path, mock_fetcher):
    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text("wildcard_action:\n  enabled: false\nsensitive_action:\n  severity: critical\n")
    config = ConfigLoader.load_config(explicit_path=str(config_file))
    registry = build_registry(config)

    cli_results = await sdk_validate_policies(
        [("policy.json", IAMPolicy.model_validate(_POLICY))], config=config, registry=registry
    )
    cli_findings = {(i.check_id, i.severity, i.message) for i in cli_results[0].issues}

    context = ServerContext(
        config=config,
        registry=registry,
        formatters=ReportGenerator(),
        fetcher=mock_fetcher,
        aws_sessions={},
        settings=ServerSettings(),
        mutable=None,
        config_digest="test-digest",
    )
    mcp_response = await validate_policies(policies=[_POLICY], ctx=_fake_ctx(context))
    mcp_findings = {(i["check_id"], i["severity"], i["message"]) for i in mcp_response["results"][0]["issues"]}

    assert cli_findings
    assert mcp_findings == cli_findings
    assert not any(f[0] == "wildcard_action" for f in mcp_findings)
    assert any(f[0] == "sensitive_action" and f[1] == "critical" for f in mcp_findings)

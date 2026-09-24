"""Tests for the consolidated MCP validation tool.

Covers ``validate_policies`` (absorbs the former validate_policy, quick_validate,
validate_policies_batch, validate_with_config, check_org_compliance, and
get_policy_summary tools).
"""

import asyncio
import json
from types import SimpleNamespace

import pytest
import yaml
from fastmcp.exceptions import ToolError

from iam_validator.core.config.config_loader import ConfigLoader, ValidatorConfig
from iam_validator.core.policy_checks import build_registry
from iam_validator.core.report import ReportGenerator
from iam_validator.mcp.context import ServerContext, SessionState
from iam_validator.mcp.settings import ServerSettings
from iam_validator.mcp.tools.validate import validate_policies

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")


def _fake_ctx(context: ServerContext) -> SimpleNamespace:
    return SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))


def _build_context(
    *,
    config: ValidatorConfig | None = None,
    settings: ServerSettings | None = None,
    mutable: SessionState | None = None,
) -> ServerContext:
    resolved_config = config if config is not None else ConfigLoader.load_config(allow_missing=True)
    return ServerContext(
        config=resolved_config,
        registry=build_registry(resolved_config),
        formatters=ReportGenerator(),
        fetcher=None,
        aws_sessions={},
        settings=settings or ServerSettings(),
        mutable=mutable,
        config_digest="test-digest",
    )


WILDCARD_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


class TestInputForms:
    async def test_accepts_dict(self, simple_policy_dict):
        response = await validate_policies(policies=[simple_policy_dict])
        assert len(response["results"]) == 1
        assert response["results"][0]["is_valid"] is True

    async def test_accepts_json_string(self, simple_policy_dict):
        response = await validate_policies(policies=[json.dumps(simple_policy_dict)])
        assert len(response["results"]) == 1

    async def test_accepts_yaml_string(self, simple_policy_dict):
        response = await validate_policies(policies=[yaml.safe_dump(simple_policy_dict)])
        assert len(response["results"]) == 1

    async def test_accepts_object_with_name_and_policy_type(self, simple_policy_dict):
        response = await validate_policies(
            policies=[{"policy": simple_policy_dict, "name": "roles/foo.json", "policy_type": "identity"}]
        )
        entry = response["results"][0]
        assert entry["name"] == "roles/foo.json"
        assert entry["policy_type"] == "IDENTITY_POLICY"
        assert entry["policy_type_source"] == "cli-flag"

    async def test_mixed_batch_per_entry_policy_type_override(self, simple_policy_dict):
        scp_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        response = await validate_policies(
            policies=[
                simple_policy_dict,
                {"policy": scp_policy, "policy_type": "scp"},
            ]
        )
        assert response["results"][0]["policy_type"] == "IDENTITY_POLICY"
        assert response["results"][1]["policy_type"] == "SERVICE_CONTROL_POLICY"
        assert response["results"][1]["policy_type_source"] == "cli-flag"

    async def test_invalid_text_raises_tool_error(self, invalid_json_policy):
        with pytest.raises(ToolError, match="could not parse policy text"):
            await validate_policies(policies=[invalid_json_policy])

    async def test_malformed_iam_policy_raises_tool_error(self):
        with pytest.raises(ToolError, match="Malformed IAM policy"):
            await validate_policies(policies=[{"Version": "2012-10-17", "Statement": 12345}])

    async def test_no_policies_or_path_raises_tool_error(self):
        with pytest.raises(ToolError, match="at least one policy is required"):
            await validate_policies(policies=[])


class TestDetailLevels:
    async def test_findings_default_includes_issues_not_summary(self, wildcard_policy_dict):
        response = await validate_policies(policies=[wildcard_policy_dict])
        entry = response["results"][0]
        assert entry["issues"] is not None
        assert entry["summary"] is None

    async def test_summary_excludes_issues(self, wildcard_policy_dict):
        response = await validate_policies(policies=[wildcard_policy_dict], detail="summary")
        entry = response["results"][0]
        assert entry["issues"] is None
        assert entry["summary"] is not None

    async def test_full_includes_both(self, wildcard_policy_dict):
        response = await validate_policies(policies=[wildcard_policy_dict], detail="full")
        entry = response["results"][0]
        assert entry["issues"] is not None
        assert entry["summary"] is not None
        assert "statement_index" in entry["issues"][0]

    async def test_invalid_detail_raises_tool_error(self, simple_policy_dict):
        with pytest.raises(ToolError, match="detail"):
            await validate_policies(policies=[simple_policy_dict], detail="bogus")  # type: ignore[arg-type]


class TestFormat:
    async def test_json_format_has_no_report(self, simple_policy_dict):
        response = await validate_policies(policies=[simple_policy_dict], format="json")
        assert "report" not in response or response.get("report") is None

    async def test_markdown_adds_report_results_unchanged(self, wildcard_policy_dict):
        json_response = await validate_policies(policies=[wildcard_policy_dict], format="json")
        md_response = await validate_policies(policies=[wildcard_policy_dict], format="markdown")

        assert md_response.get("report")
        assert isinstance(md_response["report"], str)
        assert json.dumps(md_response["results"], sort_keys=True) == json.dumps(
            json_response["results"], sort_keys=True
        )

    @pytest.mark.parametrize("terminal_format", ["console", "enhanced"])
    async def test_terminal_formats_rejected(self, simple_policy_dict, terminal_format):
        with pytest.raises(ToolError, match="format"):
            await validate_policies(policies=[simple_policy_dict], format=terminal_format)  # type: ignore[arg-type]


class TestFailsPolicy:
    async def test_flips_with_fail_on_severity_change_findings_identical(self, wildcard_policy_dict):
        strict_config = ValidatorConfig({"settings": {"fail_on_severity": ["critical"]}})
        lenient_config = ValidatorConfig({"settings": {"fail_on_severity": ["medium"]}})

        strict_ctx = _fake_ctx(_build_context(config=strict_config))
        lenient_ctx = _fake_ctx(_build_context(config=lenient_config))

        strict_response = await validate_policies(policies=[wildcard_policy_dict], ctx=strict_ctx)
        lenient_response = await validate_policies(policies=[wildcard_policy_dict], ctx=lenient_ctx)

        assert strict_response["results"][0]["fails_policy"] is True
        assert lenient_response["results"][0]["fails_policy"] is False
        assert strict_response["results"][0]["issues"] == lenient_response["results"][0]["issues"]


class TestPolicyTypeResolution:
    async def test_config_glob_resolves_policy_type(self, simple_policy_dict):
        config = ValidatorConfig({"policy_types": [{"pattern": "**/scp/*.json", "type": "SERVICE_CONTROL_POLICY"}]})
        ctx = _fake_ctx(_build_context(config=config))

        response = await validate_policies(
            policies=[{"policy": simple_policy_dict, "name": "x/scp/prod.json"}],
            ctx=ctx,
        )

        entry = response["results"][0]
        assert entry["policy_type"] == "SERVICE_CONTROL_POLICY"
        assert entry["policy_type_source"] == "config-glob"

    async def test_auto_detect_trust_policy(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        response = await validate_policies(policies=[trust_policy])
        entry = response["results"][0]
        assert entry["policy_type"] == "TRUST_POLICY"
        assert entry["policy_type_source"] == "auto-detect"

    async def test_default_identity_policy(self, simple_policy_dict):
        response = await validate_policies(policies=[simple_policy_dict])
        entry = response["results"][0]
        assert entry["policy_type"] == "IDENTITY_POLICY"
        assert entry["policy_type_source"] == "default"


class TestSessionConfigOverlay:
    async def test_session_config_overrides_fail_on_severity(self, wildcard_policy_dict):
        session = SessionState()
        session.set_config({"settings": {"fail_on_severity": ["medium"]}}, source="session")
        ctx = _fake_ctx(_build_context(mutable=session))

        response = await validate_policies(policies=[wildcard_policy_dict], ctx=ctx)

        assert response["results"][0]["fails_policy"] is False


class TestRequestLimits:
    async def test_max_policies_limit(self, simple_policy_dict):
        settings = ServerSettings(max_policies=2)
        ctx = _fake_ctx(_build_context(settings=settings))

        with pytest.raises(ToolError, match="max_policies"):
            await validate_policies(policies=[simple_policy_dict] * 3, ctx=ctx)

    async def test_max_policy_bytes_limit(self):
        settings = ServerSettings(max_policy_bytes=200)
        ctx = _fake_ctx(_build_context(settings=settings))
        large_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": [f"arn:aws:s3:::b{i}/*" for i in range(50)]}
            ],
        }

        with pytest.raises(ToolError, match="max_policy_bytes"):
            await validate_policies(policies=[large_policy], ctx=ctx)

    async def test_max_request_bytes_limit(self, simple_policy_dict):
        settings = ServerSettings(max_policy_bytes=10_000, max_request_bytes=100)
        ctx = _fake_ctx(_build_context(settings=settings))

        with pytest.raises(ToolError, match="max_request_bytes"):
            await validate_policies(policies=[simple_policy_dict, simple_policy_dict], ctx=ctx)

    async def test_request_timeout(self, simple_policy_dict, monkeypatch):
        from iam_validator.mcp.tools import validate as validation_mod

        async def slow_validate(**kwargs):
            await asyncio.sleep(5)
            return []

        monkeypatch.setattr(validation_mod, "sdk_validate_policies", slow_validate)
        settings = ServerSettings(request_timeout_s=1)
        ctx = _fake_ctx(_build_context(settings=settings))

        with pytest.raises(ToolError, match="request_timeout_s"):
            await validate_policies(policies=[simple_policy_dict], ctx=ctx)

    async def test_max_response_bytes_degrades_instead_of_raising(self, wildcard_policy_dict):
        settings = ServerSettings(max_response_bytes=50)
        ctx = _fake_ctx(_build_context(settings=settings))

        response = await validate_policies(policies=[wildcard_policy_dict], detail="full", ctx=ctx)

        assert response["truncated"] is True


class TestHostedSchema:
    async def test_hosted_tool_excludes_path_and_glob(self):
        from iam_validator.mcp.build import build_server

        hosted = build_server(ServerSettings(mode="hosted", auth="none", auth_explicitly_set=True))
        tools = await hosted.list_tools()
        vp = next(t for t in tools if t.name == "validate_policies")
        params = set(vp.parameters.get("properties", {}).keys())
        assert "path" not in params
        assert "glob" not in params

    async def test_local_tool_includes_path_and_glob(self):
        from iam_validator.mcp.build import build_server

        local = build_server(ServerSettings(mode="local"))
        tools = await local.list_tools()
        vp = next(t for t in tools if t.name == "validate_policies")
        params = set(vp.parameters.get("properties", {}).keys())
        assert "path" in params
        assert "glob" in params


class TestPathGlob:
    async def test_loads_policies_from_directory(self, tmp_path, simple_policy_dict):
        (tmp_path / "a.json").write_text(json.dumps(simple_policy_dict))
        (tmp_path / "b.json").write_text(json.dumps(simple_policy_dict))

        response = await validate_policies(path=str(tmp_path))

        assert len(response["results"]) == 2

    async def test_glob_restricts_directory_scan(self, tmp_path, simple_policy_dict):
        (tmp_path / "keep.json").write_text(json.dumps(simple_policy_dict))
        (tmp_path / "skip.yaml").write_text(yaml.safe_dump(simple_policy_dict))

        response = await validate_policies(path=str(tmp_path), glob="*.json")

        assert len(response["results"]) == 1

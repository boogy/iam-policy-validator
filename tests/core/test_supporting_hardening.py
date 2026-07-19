"""Tests for supporting-surface hardening.

Covers:
- service-name -> filename sanitization (path-traversal guard on the AWS
  service definition write/read paths)
- redirect-following disabled on the fixed-host AWS service client
- SRI-pinned Chart.js in the HTML formatter
- custom-check auto-discovery gated on explicit opt-in when the directory
  comes from the YAML config file
"""

import pytest

from iam_validator.core.aws_service.client import AWSServiceClient
from iam_validator.core.aws_service.storage import service_filename
from iam_validator.core.formatters.html import HTMLFormatter
from iam_validator.core.policy_checks import validate_policies


class TestServiceFilename:
    @pytest.mark.parametrize("name", ["s3", "ec2", "lambda", "iam"])
    def test_normal_names_unchanged(self, name):
        assert service_filename(name) == f"{name}.json"

    def test_spaces_become_underscores(self):
        assert service_filename("Elastic Beanstalk") == "elastic_beanstalk.json"

    def test_path_traversal_is_neutralized(self):
        result = service_filename("../../etc/cron.d/evil")
        assert "/" not in result
        assert "\\" not in result
        assert not result.startswith(".")
        assert result.endswith(".json")

    def test_backslash_and_absolute_paths_neutralized(self):
        for evil in ("..\\..\\windows\\evil", "/etc/passwd", "C:\\evil"):
            result = service_filename(evil)
            assert "/" not in result and "\\" not in result, evil
            assert not result.startswith("."), evil

    def test_all_unsafe_input_rejected(self):
        with pytest.raises(ValueError):
            service_filename("....")
        with pytest.raises(ValueError):
            service_filename("///")


class TestClientRedirects:
    async def test_follow_redirects_disabled(self):
        async with AWSServiceClient(base_url="https://servicereference.us-east-1.amazonaws.com") as client:
            assert client._client is not None
            assert client._client.follow_redirects is False


class TestHtmlFormatterSri:
    def test_chart_js_is_pinned_with_integrity(self):
        formatter = HTMLFormatter()
        scripts = formatter._get_scripts(include_charts=True)
        assert "chart.js@" in scripts  # version-pinned, not floating latest
        assert 'integrity="sha384-' in scripts
        assert 'crossorigin="anonymous"' in scripts

    def test_no_scripts_without_charts(self):
        formatter = HTMLFormatter()
        assert formatter._get_scripts(include_charts=False) == ""


class TestConfigCustomChecksGate:
    """custom_checks_dir from the YAML config alone must not execute code."""

    @pytest.fixture
    def config_with_checks_dir(self, tmp_path):
        checks_dir = tmp_path / "my-checks"
        checks_dir.mkdir()
        config = tmp_path / "iam-validator.yaml"
        config.write_text(f'custom_checks_dir: "{checks_dir}"\n')
        return config, checks_dir

    async def test_config_dir_ignored_without_opt_in(self, config_with_checks_dir, monkeypatch):
        config, _checks_dir = config_with_checks_dir
        calls: list = []
        monkeypatch.setattr(
            "iam_validator.core.policy_checks.ConfigLoader.discover_checks_in_directory",
            lambda *a, **k: calls.append(a) or [],
        )
        await validate_policies([], config_path=str(config))
        assert calls == []

    async def test_config_dir_honoured_with_opt_in(self, config_with_checks_dir, monkeypatch):
        config, _checks_dir = config_with_checks_dir
        calls: list = []
        monkeypatch.setattr(
            "iam_validator.core.policy_checks.ConfigLoader.discover_checks_in_directory",
            lambda *a, **k: calls.append(a) or [],
        )
        await validate_policies([], config_path=str(config), allow_config_custom_checks=True)
        assert len(calls) == 1

    async def test_explicit_dir_always_honoured(self, tmp_path, monkeypatch):
        checks_dir = tmp_path / "explicit-checks"
        checks_dir.mkdir()
        calls: list = []
        monkeypatch.setattr(
            "iam_validator.core.policy_checks.ConfigLoader.discover_checks_in_directory",
            lambda *a, **k: calls.append(a) or [],
        )
        await validate_policies([], custom_checks_dir=str(checks_dir))
        assert len(calls) == 1

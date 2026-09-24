"""Tests for ServerSettings."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from iam_validator.mcp.settings import ServerSettings


class TestDefaults:
    def test_defaults(self):
        s = ServerSettings()
        assert s.mode == "local"
        assert s.transport == "stdio"
        assert s.host == "127.0.0.1"
        assert s.port == 8000
        assert s.config_source is None
        assert s.auth == "none"
        assert s.auth_explicitly_set is False
        assert s.profile == "full"
        assert s.instructions is None
        assert s.instructions_file is None
        assert s.analyze_rate_limit == 10
        assert s.max_policies == 50
        assert s.max_policy_bytes == 1_048_576
        assert s.max_request_bytes == 8_388_608
        assert s.request_timeout_s == 60
        assert s.max_response_bytes == 4_194_304


class TestUrlRejection:
    @pytest.mark.parametrize("bad", ["https://x/c.yaml", "http://x/c.yaml", "ftp://x/c.yaml"])
    def test_rejects_url_config_source(self, bad):
        with pytest.raises(ValidationError):
            ServerSettings(config_source=bad)

    def test_accepts_filesystem_path(self):
        s = ServerSettings(config_source="./config.yaml")
        assert str(s.config_source) == "config.yaml"

    def test_rejects_url_as_path_object(self):
        """A pre-constructed Path must be rejected too, not just a raw str.

        pathlib collapses "//" to "/" at construction, so checking the original
        string for the "://" substring misses this: str(Path("https://x")) ==
        "https:/x", with no "://" left to find.
        """
        with pytest.raises(ValidationError):
            ServerSettings(config_source=Path("https://x/c.yaml"))

    def test_accepts_windows_drive_letter_path(self):
        s = ServerSettings(config_source="C:/Users/x/config.yaml")
        assert str(s.config_source) == "C:/Users/x/config.yaml"

    def test_rejects_url_with_leading_whitespace(self):
        """A leading-space URL (easy to introduce via a compose/.env file) must not
        bypass the check by defeating the `^`-anchored pattern."""
        with pytest.raises(ValidationError):
            ServerSettings(config_source=" https://x/c.yaml")

    def test_rejects_colon_bearing_filesystem_path(self):
        """pathlib gives no way to tell a collapsed URL apart from a genuine
        colon-bearing path, so any two-or-more-char scheme-like prefix is rejected
        rather than allowlisted by scheme name (an operator can rename the path;
        a silently-accepted URL would defeat the "no remote config" invariant)."""
        with pytest.raises(ValidationError):
            ServerSettings(config_source="notes:/backup.yaml")

    @pytest.mark.parametrize("bad", [Path("HTTPS://x/c.yaml"), Path("gopher://x/c.yaml"), Path("sftp://x/c")])
    def test_rejects_url_as_path_object_any_scheme_any_case(self, bad):
        """No scheme is allowlisted, so an uppercase scheme and an unusual scheme
        (not just http/https/s3/...) must both be rejected when passed as a Path."""
        with pytest.raises(ValidationError):
            ServerSettings(config_source=bad)


class TestInstructionsExclusivity:
    def test_both_set_raises(self):
        with pytest.raises(ValidationError):
            ServerSettings(instructions="hi", instructions_file="/tmp/instructions.md")

    def test_only_instructions_ok(self):
        assert ServerSettings(instructions="hi").instructions == "hi"

    def test_only_instructions_file_ok(self):
        s = ServerSettings(instructions_file="/tmp/instructions.md")
        assert str(s.instructions_file) == "/tmp/instructions.md"


class TestHostedAuth:
    def test_hosted_without_explicit_auth_raises(self):
        with pytest.raises(ValidationError):
            ServerSettings(mode="hosted")

    def test_hosted_with_explicit_auth_none_ok(self):
        s = ServerSettings(mode="hosted", auth="none", auth_explicitly_set=True)
        assert s.mode == "hosted"

    def test_hosted_with_token_auth_ok(self):
        s = ServerSettings(mode="hosted", auth="token")
        assert s.auth == "token"

    def test_local_with_default_auth_ok(self):
        s = ServerSettings(mode="local")
        assert s.auth == "none"


class TestFromEnv:
    def test_config_source_env_override(self, monkeypatch):
        monkeypatch.setenv("IAM_VALIDATOR_MCP_CONFIG", "/etc/iam-validator/config.yaml")
        s = ServerSettings.from_env()
        assert str(s.config_source) == "/etc/iam-validator/config.yaml"

    def test_mode_env_override(self, monkeypatch):
        monkeypatch.setenv("IAM_VALIDATOR_MCP_MODE", "hosted")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH", "token")
        s = ServerSettings.from_env()
        assert s.mode == "hosted"
        assert s.auth == "token"
        assert s.auth_explicitly_set is True

    def test_transport_env_override(self, monkeypatch):
        monkeypatch.setenv("IAM_VALIDATOR_MCP_TRANSPORT", "http")
        assert ServerSettings.from_env().transport == "http"

    def test_numeric_limit_env_override(self, monkeypatch):
        monkeypatch.setenv("IAM_VALIDATOR_MCP_MAX_POLICIES", "5")
        assert ServerSettings.from_env().max_policies == 5

    def test_instructions_env_var_name(self, monkeypatch):
        monkeypatch.setenv("IAM_VALIDATOR_MCP_INSTRUCTIONS", "Always require MFA")
        assert ServerSettings.from_env().instructions == "Always require MFA"

    def test_no_env_matches_defaults(self):
        assert ServerSettings.from_env({}) == ServerSettings()

    def test_empty_config_env_resolves_to_none(self):
        """IAM_VALIDATOR_MCP_CONFIG='' (the ordinary way to blank a var in compose/k8s)
        must fall back to the None default, not resolve Path("") to the cwd."""
        s = ServerSettings.from_env({"IAM_VALIDATOR_MCP_CONFIG": ""})
        assert s.config_source is None

    def test_whitespace_only_config_env_resolves_to_none(self):
        s = ServerSettings.from_env({"IAM_VALIDATOR_MCP_CONFIG": "   "})
        assert s.config_source is None

    def test_empty_instructions_file_env_resolves_to_none(self):
        s = ServerSettings.from_env({"IAM_VALIDATOR_MCP_INSTRUCTIONS_FILE": ""})
        assert s.instructions_file is None

    def test_empty_numeric_env_resolves_to_default(self):
        s = ServerSettings.from_env({"IAM_VALIDATOR_MCP_MAX_POLICIES": ""})
        assert s.max_policies == 50

    def test_ignores_argv(self, monkeypatch):
        """from_env() must not be influenced by sys.argv."""
        monkeypatch.setattr(
            "sys.argv",
            ["prog", "--mode", "hosted", "--port", "1234"],
        )
        s = ServerSettings.from_env({})
        assert s.mode == "local"
        assert s.port == 8000

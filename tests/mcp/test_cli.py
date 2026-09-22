"""Tests for the shared argparse layer in ``iam_validator.mcp.cli``."""

import argparse

import pytest

from iam_validator.mcp.cli import add_arguments, resolve_settings
from iam_validator.mcp.settings import ServerSettings


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="test")
    add_arguments(parser)
    return parser.parse_args(argv)


class TestBothEntryPointsAgree:
    def test_identical_settings_for_identical_flags(self):
        """Both entry points share the one builder, so a top-level parser (standing in
        for iam-validator-mcp) and a subparser (standing in for `iam-validator mcp`)
        must resolve the same flags to the same ServerSettings."""
        argv = [
            "--mode",
            "hosted",
            "--transport",
            "http",
            "--host",
            "0.0.0.0",
            "--port",
            "9000",
            "--auth",
            "none",
            "--profile",
            "read-only",
            "--max-policies",
            "5",
        ]

        top_level = argparse.ArgumentParser(prog="iam-validator-mcp")
        add_arguments(top_level)
        top_level_args = top_level.parse_args(argv)

        cli_parser = argparse.ArgumentParser(prog="iam-validator")
        subparsers = cli_parser.add_subparsers(dest="command")
        mcp_subparser = subparsers.add_parser("mcp")
        add_arguments(mcp_subparser)
        subcommand_args = cli_parser.parse_args(["mcp", *argv])

        assert resolve_settings(top_level_args, env={}) == resolve_settings(subcommand_args, env={})

    def test_defaults_agree_with_no_flags(self):
        assert resolve_settings(_parse([]), env={}) == ServerSettings()


class TestTransportSseRejected:
    def test_sse_exits_naming_http(self, capsys):
        parser = argparse.ArgumentParser(prog="test")
        add_arguments(parser)
        with pytest.raises(SystemExit):
            parser.parse_args(["--transport", "sse"])
        assert "http" in capsys.readouterr().err

    def test_sse_message_explains_removal_not_generic_choice_error(self, capsys):
        parser = argparse.ArgumentParser(prog="test")
        add_arguments(parser)
        with pytest.raises(SystemExit):
            parser.parse_args(["--transport", "sse"])
        err = capsys.readouterr().err
        assert "invalid choice" not in err
        assert "removed" in err

    def test_stdio_and_http_accepted(self):
        assert _parse(["--transport", "stdio"]).transport == "stdio"
        assert _parse(["--transport", "http"]).transport == "http"


class TestHostDefault:
    def test_host_defaults_to_loopback(self):
        settings = resolve_settings(_parse([]), env={})
        assert settings.host == "127.0.0.1"

    def test_flag_overrides_default(self):
        settings = resolve_settings(_parse(["--host", "0.0.0.0"]), env={})
        assert settings.host == "0.0.0.0"


class TestEnvAndFlagPrecedence:
    @pytest.mark.parametrize(
        ("flag", "flag_value", "env_name", "env_value", "field", "expected_env_only", "expected_both"),
        [
            ("--mode", "local", "IAM_VALIDATOR_MCP_MODE", "hosted", "mode", "hosted", "local"),
            ("--transport", "stdio", "IAM_VALIDATOR_MCP_TRANSPORT", "http", "transport", "http", "stdio"),
            ("--host", "10.0.0.1", "IAM_VALIDATOR_MCP_HOST", "10.0.0.2", "host", "10.0.0.2", "10.0.0.1"),
            ("--port", "9001", "IAM_VALIDATOR_MCP_PORT", "9002", "port", 9002, 9001),
            ("--profile", "full", "IAM_VALIDATOR_MCP_PROFILE", "read-only", "profile", "read-only", "full"),
            (
                "--analyze-rate-limit",
                "3",
                "IAM_VALIDATOR_MCP_ANALYZE_RATE_LIMIT",
                "7",
                "analyze_rate_limit",
                7,
                3,
            ),
            ("--max-policies", "11", "IAM_VALIDATOR_MCP_MAX_POLICIES", "22", "max_policies", 22, 11),
        ],
    )
    def test_env_used_when_flag_absent_flag_wins_when_both_set(
        self, flag, flag_value, env_name, env_value, field, expected_env_only, expected_both
    ):
        env = {env_name: env_value}

        # env var alone (matches "hosted" mode's auth requirement where relevant)
        args_no_flag = _parse(["--auth", "none"])
        settings_env_only = resolve_settings(args_no_flag, env=env)
        assert getattr(settings_env_only, field) == expected_env_only

        # flag + env var set together: flag wins
        args_with_flag = _parse(["--auth", "none", flag, flag_value])
        settings_both = resolve_settings(args_with_flag, env=env)
        assert getattr(settings_both, field) == expected_both


class TestAuthExplicitlySet:
    def test_unset_by_default(self):
        settings = resolve_settings(_parse([]), env={})
        assert settings.auth_explicitly_set is False

    def test_set_when_flag_passed_even_with_default_value(self):
        settings = resolve_settings(_parse(["--auth", "none"]), env={})
        assert settings.auth_explicitly_set is True

    def test_set_when_env_var_passed(self):
        settings = resolve_settings(_parse([]), env={"IAM_VALIDATOR_MCP_AUTH": "none"})
        assert settings.auth_explicitly_set is True


class TestListProfilesFlag:
    def test_flag_present_and_not_a_settings_field(self):
        args = _parse(["--list-profiles"])
        assert args.list_profiles is True
        # Must never reach ServerSettings (extra="forbid" would raise).
        resolve_settings(_parse([]), env={})

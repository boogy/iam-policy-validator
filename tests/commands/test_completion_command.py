"""Tests for completion command."""

import argparse
import os
import pathlib
from unittest.mock import MagicMock, patch

import pytest

from iam_validator.commands.completion import CompletionCommand


@pytest.fixture
def completion_cmd() -> CompletionCommand:
    """Create completion command instance."""
    return CompletionCommand()


class TestCompletionCommand:
    """Test suite for CompletionCommand."""

    def test_name(self, completion_cmd: CompletionCommand) -> None:
        """Test command name."""
        assert completion_cmd.name == "completion"

    def test_help(self, completion_cmd: CompletionCommand) -> None:
        """Test command help text."""
        assert "shell completion" in completion_cmd.help.lower()

    def test_add_arguments(self, completion_cmd: CompletionCommand) -> None:
        """Test argument parsing setup."""
        parser = argparse.ArgumentParser()
        completion_cmd.add_arguments(parser)

        # Test bash
        args = parser.parse_args(["bash"])
        assert args.shell == "bash"
        assert args.install is False

        # Test zsh
        args = parser.parse_args(["zsh"])
        assert args.shell == "zsh"

    @pytest.mark.asyncio
    async def test_execute_bash(self, completion_cmd: CompletionCommand) -> None:
        """Test generating bash completion."""
        args = argparse.Namespace(shell="bash", install=False)

        with patch("builtins.print") as mock_print:
            result = await completion_cmd.execute(args)
            assert result == 0

            # Verify bash completion was printed
            assert mock_print.called
            output = mock_print.call_args[0][0]
            assert "# Bash completion" in output
            assert "_iam_validator_completion()" in output
            assert "complete -F _iam_validator_completion iam-validator" in output

    @pytest.mark.asyncio
    async def test_execute_zsh(self, completion_cmd: CompletionCommand) -> None:
        """Test generating zsh completion."""
        args = argparse.Namespace(shell="zsh", install=False)

        with patch("builtins.print") as mock_print:
            result = await completion_cmd.execute(args)
            assert result == 0

            # Verify zsh completion was printed
            assert mock_print.called
            output = mock_print.call_args[0][0]
            assert "#compdef iam-validator" in output
            assert "_iam_validator()" in output

    @pytest.mark.asyncio
    async def test_bash_completion_includes_commands(self, completion_cmd: CompletionCommand) -> None:
        """Test bash completion includes all commands."""
        args = argparse.Namespace(shell="bash", install=False)

        with patch("builtins.print") as mock_print:
            await completion_cmd.execute(args)
            output = mock_print.call_args[0][0]

            # Check for main commands
            assert "validate" in output
            assert "query" in output
            assert "completion" in output

    @pytest.mark.asyncio
    async def test_zsh_completion_includes_commands(self, completion_cmd: CompletionCommand) -> None:
        """Test zsh completion includes all commands."""
        args = argparse.Namespace(shell="zsh", install=False)

        with patch("builtins.print") as mock_print:
            await completion_cmd.execute(args)
            output = mock_print.call_args[0][0]

            # Check for main commands
            assert "validate" in output
            assert "query" in output
            assert "completion" in output

    @pytest.mark.asyncio
    async def test_bash_completion_includes_query_subcommands(self, completion_cmd: CompletionCommand) -> None:
        """Test bash completion includes query subcommands."""
        args = argparse.Namespace(shell="bash", install=False)

        with patch("builtins.print") as mock_print:
            await completion_cmd.execute(args)
            output = mock_print.call_args[0][0]

            # Check for query subcommands
            assert "action" in output
            assert "arn" in output
            assert "condition" in output

    @pytest.mark.asyncio
    async def test_bash_completion_includes_access_levels(self, completion_cmd: CompletionCommand) -> None:
        """Test bash completion includes access levels."""
        args = argparse.Namespace(shell="bash", install=False)

        with patch("builtins.print") as mock_print:
            await completion_cmd.execute(args)
            output = mock_print.call_args[0][0]

            # Check for access levels
            assert "read write list tagging permissions-management" in output

    @pytest.mark.asyncio
    async def test_get_cached_services_empty(self, completion_cmd: CompletionCommand) -> None:
        """Test getting cached services when cache is empty."""
        with patch("iam_validator.commands.completion.ServiceFileStorage") as mock_storage_class:
            mock_storage = MagicMock()
            mock_storage.cache_directory.exists.return_value = False
            mock_storage_class.return_value = mock_storage

            services = completion_cmd._get_cached_services()
            assert services == []

    @pytest.mark.asyncio
    async def test_get_cached_services_with_cache(self, completion_cmd: CompletionCommand, tmp_path) -> None:
        """Test getting cached services when cache has files."""
        # Create fake cache files
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        (cache_dir / "s3_abc123.json").touch()
        (cache_dir / "iam_def456.json").touch()
        (cache_dir / "ec2_ghi789.json").touch()
        (cache_dir / "services_list.json").touch()  # Should be ignored

        with patch("iam_validator.commands.completion.ServiceFileStorage") as mock_storage_class:
            mock_storage = MagicMock()
            mock_storage.cache_directory = cache_dir
            mock_storage_class.return_value = mock_storage

            services = completion_cmd._get_cached_services()
            assert sorted(services) == ["ec2", "iam", "s3"]

    @pytest.mark.asyncio
    async def test_bash_completion_includes_cached_services(self, completion_cmd: CompletionCommand) -> None:
        """Test bash completion includes cached services."""
        with patch.object(completion_cmd, "_get_cached_services", return_value=["s3", "iam", "ec2"]):
            args = argparse.Namespace(shell="bash", install=False)

            with patch("builtins.print") as mock_print:
                await completion_cmd.execute(args)
                output = mock_print.call_args[0][0]

                # Check that services are in the completion
                assert "s3 iam ec2" in output

    @pytest.mark.asyncio
    async def test_zsh_completion_includes_cached_services(self, completion_cmd: CompletionCommand) -> None:
        """Test zsh completion includes cached services."""
        with patch.object(completion_cmd, "_get_cached_services", return_value=["s3", "iam", "ec2"]):
            args = argparse.Namespace(shell="zsh", install=False)

            with patch("builtins.print") as mock_print:
                await completion_cmd.execute(args)
                output = mock_print.call_args[0][0]

                # Check that services are in the completion (zsh format with quotes)
                assert "'s3' 'iam' 'ec2'" in output

    @pytest.mark.asyncio
    async def test_execute_handles_exceptions(self, completion_cmd: CompletionCommand) -> None:
        """Test that execute handles exceptions gracefully."""
        args = argparse.Namespace(shell="bash", install=False)

        with patch.object(completion_cmd, "_generate_bash_completion", side_effect=Exception("Test error")):
            result = await completion_cmd.execute(args)
            assert result == 1


class TestCompletionInstall:
    """Test suite for `completion <shell> --install`."""

    @pytest.fixture(autouse=True)
    def _xdg(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        return tmp_path

    def test_install_flag_parsed(self, completion_cmd: CompletionCommand) -> None:
        parser = argparse.ArgumentParser()
        completion_cmd.add_arguments(parser)
        assert parser.parse_args(["zsh", "--install"]).install is True

    @pytest.mark.parametrize(
        ("shell", "relative"),
        [
            ("zsh", "zsh/site-functions/_iam-validator"),
            ("bash", "bash-completion/completions/iam-validator"),
        ],
    )
    async def test_install_writes_completion_file(
        self, completion_cmd: CompletionCommand, _xdg, shell: str, relative: str
    ) -> None:
        result = await completion_cmd.execute(argparse.Namespace(shell=shell, install=True))

        target = _xdg / relative
        assert result == 0
        assert target.is_file()
        assert target.read_text(encoding="utf-8").endswith("\n")

    async def test_install_does_not_print_the_script(self, completion_cmd: CompletionCommand, capsys) -> None:
        await completion_cmd.execute(argparse.Namespace(shell="zsh", install=True))

        out = capsys.readouterr().out
        assert "#compdef" not in out
        assert "installed to " in out

    async def test_install_overwrites_even_when_already_current(
        self, completion_cmd: CompletionCommand, _xdg, capsys
    ) -> None:
        await completion_cmd.execute(argparse.Namespace(shell="zsh", install=True))
        first = capsys.readouterr().out
        target = _xdg / "zsh/site-functions/_iam-validator"
        os.utime(target, (0, 0))

        await completion_cmd.execute(argparse.Namespace(shell="zsh", install=True))
        second = capsys.readouterr().out

        assert "already up to date" not in first
        assert "already up to date" in second
        assert "installed to" not in second
        assert target.stat().st_mtime_ns != 0

    async def test_install_rewrites_stale_file(self, completion_cmd: CompletionCommand, _xdg, capsys) -> None:
        target = _xdg / "zsh/site-functions/_iam-validator"
        target.parent.mkdir(parents=True)
        target.write_text("#compdef iam-validator\n# stale\n", encoding="utf-8")

        await completion_cmd.execute(argparse.Namespace(shell="zsh", install=True))

        assert "stale" not in target.read_text(encoding="utf-8")
        assert "already up to date" not in capsys.readouterr().out

    async def test_zsh_install_prints_fpath_hint(self, completion_cmd: CompletionCommand, _xdg, capsys) -> None:
        await completion_cmd.execute(argparse.Namespace(shell="zsh", install=True))

        out = capsys.readouterr().out
        assert "${ZDOTDIR:-$HOME}/.zshrc" in out
        assert f"fpath+=('{_xdg / 'zsh/site-functions'}')" in out
        assert "autoload -Uz compinit && compinit" in out

    async def test_bash_install_prints_source_hint(self, completion_cmd: CompletionCommand, _xdg, capsys) -> None:
        await completion_cmd.execute(argparse.Namespace(shell="bash", install=True))

        out = capsys.readouterr().out
        assert ".bashrc" in out
        assert f"source '{_xdg / 'bash-completion/completions/iam-validator'}'" in out

    def test_install_path_falls_back_to_local_share(
        self, completion_cmd: CompletionCommand, monkeypatch, tmp_path
    ) -> None:
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)

        assert completion_cmd._install_path("zsh") == (tmp_path / ".local/share/zsh/site-functions/_iam-validator")

    @pytest.mark.parametrize("shell", ["bash", "zsh"])
    async def test_generated_script_offers_install_flag(
        self, completion_cmd: CompletionCommand, shell: str, capsys
    ) -> None:
        await completion_cmd.execute(argparse.Namespace(shell=shell, install=False))

        assert "--install" in capsys.readouterr().out

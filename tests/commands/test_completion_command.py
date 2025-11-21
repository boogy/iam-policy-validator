"""Tests for completion command."""

import argparse
from unittest.mock import AsyncMock, MagicMock, patch

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

        # Test zsh
        args = parser.parse_args(["zsh"])
        assert args.shell == "zsh"

    @pytest.mark.asyncio
    async def test_execute_bash(self, completion_cmd: CompletionCommand) -> None:
        """Test generating bash completion."""
        args = argparse.Namespace(shell="bash")

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
        args = argparse.Namespace(shell="zsh")

        with patch("builtins.print") as mock_print:
            result = await completion_cmd.execute(args)
            assert result == 0

            # Verify zsh completion was printed
            assert mock_print.called
            output = mock_print.call_args[0][0]
            assert "#compdef iam-validator" in output
            assert "_iam_validator()" in output

    @pytest.mark.asyncio
    async def test_bash_completion_includes_commands(
        self, completion_cmd: CompletionCommand
    ) -> None:
        """Test bash completion includes all commands."""
        args = argparse.Namespace(shell="bash")

        with patch("builtins.print") as mock_print:
            await completion_cmd.execute(args)
            output = mock_print.call_args[0][0]

            # Check for main commands
            assert "validate" in output
            assert "query" in output
            assert "completion" in output

    @pytest.mark.asyncio
    async def test_zsh_completion_includes_commands(
        self, completion_cmd: CompletionCommand
    ) -> None:
        """Test zsh completion includes all commands."""
        args = argparse.Namespace(shell="zsh")

        with patch("builtins.print") as mock_print:
            await completion_cmd.execute(args)
            output = mock_print.call_args[0][0]

            # Check for main commands
            assert "validate" in output
            assert "query" in output
            assert "completion" in output

    @pytest.mark.asyncio
    async def test_bash_completion_includes_query_subcommands(
        self, completion_cmd: CompletionCommand
    ) -> None:
        """Test bash completion includes query subcommands."""
        args = argparse.Namespace(shell="bash")

        with patch("builtins.print") as mock_print:
            await completion_cmd.execute(args)
            output = mock_print.call_args[0][0]

            # Check for query subcommands
            assert "action" in output
            assert "arn" in output
            assert "condition" in output

    @pytest.mark.asyncio
    async def test_bash_completion_includes_access_levels(
        self, completion_cmd: CompletionCommand
    ) -> None:
        """Test bash completion includes access levels."""
        args = argparse.Namespace(shell="bash")

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
    async def test_get_cached_services_with_cache(
        self, completion_cmd: CompletionCommand, tmp_path
    ) -> None:
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
    async def test_bash_completion_includes_cached_services(
        self, completion_cmd: CompletionCommand
    ) -> None:
        """Test bash completion includes cached services."""
        with patch.object(
            completion_cmd, "_get_cached_services", return_value=["s3", "iam", "ec2"]
        ):
            args = argparse.Namespace(shell="bash")

            with patch("builtins.print") as mock_print:
                await completion_cmd.execute(args)
                output = mock_print.call_args[0][0]

                # Check that services are in the completion
                assert "s3 iam ec2" in output

    @pytest.mark.asyncio
    async def test_zsh_completion_includes_cached_services(
        self, completion_cmd: CompletionCommand
    ) -> None:
        """Test zsh completion includes cached services."""
        with patch.object(
            completion_cmd, "_get_cached_services", return_value=["s3", "iam", "ec2"]
        ):
            args = argparse.Namespace(shell="zsh")

            with patch("builtins.print") as mock_print:
                await completion_cmd.execute(args)
                output = mock_print.call_args[0][0]

                # Check that services are in the completion (zsh format with quotes)
                assert "'s3' 'iam' 'ec2'" in output

    @pytest.mark.asyncio
    async def test_execute_handles_exceptions(self, completion_cmd: CompletionCommand) -> None:
        """Test that execute handles exceptions gracefully."""
        args = argparse.Namespace(shell="bash")

        with patch.object(completion_cmd, "_generate_bash_completion", side_effect=Exception("Test error")):
            result = await completion_cmd.execute(args)
            assert result == 1

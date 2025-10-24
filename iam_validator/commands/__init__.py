"""CLI commands for IAM Policy Validator."""

from .analyze import AnalyzeCommand
from .post_to_pr import PostToPRCommand
from .validate import ValidateCommand

# All available commands
ALL_COMMANDS = [
    ValidateCommand(),
    PostToPRCommand(),
    AnalyzeCommand(),
]

__all__ = ["ValidateCommand", "PostToPRCommand", "AnalyzeCommand", "ALL_COMMANDS"]

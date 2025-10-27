"""CLI commands for IAM Policy Validator."""

from .analyze import AnalyzeCommand
from .cache import CacheCommand
from .post_to_pr import PostToPRCommand
from .validate import ValidateCommand

# All available commands
ALL_COMMANDS = [
    ValidateCommand(),
    PostToPRCommand(),
    AnalyzeCommand(),
    CacheCommand(),
]

__all__ = ["ValidateCommand", "PostToPRCommand", "AnalyzeCommand", "CacheCommand", "ALL_COMMANDS"]

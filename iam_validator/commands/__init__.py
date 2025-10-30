"""CLI commands for IAM Policy Validator."""

from .analyze import AnalyzeCommand
from .cache import CacheCommand
from .download_services import DownloadServicesCommand
from .post_to_pr import PostToPRCommand
from .validate import ValidateCommand

# All available commands
ALL_COMMANDS = [
    ValidateCommand(),
    PostToPRCommand(),
    AnalyzeCommand(),
    CacheCommand(),
    DownloadServicesCommand(),
]

__all__ = [
    "ValidateCommand",
    "PostToPRCommand",
    "AnalyzeCommand",
    "CacheCommand",
    "DownloadServicesCommand",
    "ALL_COMMANDS",
]

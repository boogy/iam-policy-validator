"""CLI commands for IAM Policy Validator."""

from .analyze import AnalyzeCommand
from .cache import CacheCommand
from .completion import CompletionCommand
from .download_services import DownloadServicesCommand
from .mcp import MCPCommand
from .post_to_pr import PostToPRCommand
from .query import QueryCommand
from .validate import ValidateCommand

# All available commands
ALL_COMMANDS = [
    ValidateCommand(),
    PostToPRCommand(),
    AnalyzeCommand(),
    CacheCommand(),
    DownloadServicesCommand(),
    QueryCommand(),
    CompletionCommand(),
    MCPCommand(),
]

__all__ = [
    "ValidateCommand",
    "PostToPRCommand",
    "AnalyzeCommand",
    "CacheCommand",
    "DownloadServicesCommand",
    "QueryCommand",
    "CompletionCommand",
    "MCPCommand",
    "ALL_COMMANDS",
]

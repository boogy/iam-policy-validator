"""External service integrations for IAM Policy Validator.

This package contains integrations with external services:
- GitHub for PR comments and review integration
- Microsoft Teams for notifications and alerts
"""

from iam_validator.integrations.github_integration import (
    GitHubIntegration,
    PRState,
    ReviewEvent,
)
from iam_validator.integrations.ms_teams import (
    CardTheme,
    MessageType,
    MSTeamsIntegration,
    TeamsMessage,
)

__all__ = [
    "GitHubIntegration",
    "PRState",
    "ReviewEvent",
    "MSTeamsIntegration",
    "MessageType",
    "CardTheme",
    "TeamsMessage",
]

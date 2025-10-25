"""Microsoft Teams Integration for IAM Policy Validator.

This module provides functionality to send notifications to MS Teams channels
via incoming webhooks, including validation reports and alerts.
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class MessageType(str, Enum):
    """MS Teams message types."""

    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


class CardTheme(str, Enum):
    """MS Teams adaptive card accent colors."""

    DEFAULT = "default"
    DARK = "dark"
    LIGHT = "light"
    ACCENT = "accent"
    ATTENTION = "attention"  # Red for errors
    GOOD = "good"  # Green for success
    WARNING = "warning"  # Yellow for warnings


@dataclass
class TeamsMessage:
    """Represents a message to send to MS Teams."""

    title: str
    message: str
    message_type: MessageType = MessageType.INFO
    facts: list[dict[str, str]] | None = None
    actions: list[dict[str, Any]] | None = None
    sections: list[dict[str, Any]] | None = None


class MSTeamsIntegration:
    """Handles Microsoft Teams notifications via webhooks.

    This class provides methods to:
    - Send simple text notifications
    - Send adaptive cards with rich formatting
    - Send validation reports as formatted messages
    - Send alerts for critical findings
    """

    def __init__(self, webhook_url: str | None = None):
        """Initialize MS Teams integration.

        Args:
            webhook_url: MS Teams incoming webhook URL
        """
        self.webhook_url = self._validate_webhook_url(webhook_url)
        self._client: httpx.AsyncClient | None = None

    def _validate_webhook_url(self, webhook_url: str | None) -> str | None:
        """Validate and sanitize webhook URL.

        Args:
            webhook_url: Webhook URL to validate

        Returns:
            Validated URL or None
        """
        if webhook_url is None:
            return None

        if not isinstance(webhook_url, str) or not webhook_url.strip():
            logger.warning("Invalid webhook URL provided (empty or non-string)")
            return None

        webhook_url = webhook_url.strip()

        # Must be HTTPS for security
        if not webhook_url.startswith("https://"):
            logger.warning(
                f"Webhook URL must use HTTPS: {webhook_url[:50]}... "
                "(MS Teams webhooks require HTTPS)"
            )
            return None

        # Basic URL validation - should contain office.com or webhook.office365.com
        if "webhook.office" not in webhook_url.lower():
            logger.warning(
                f"Webhook URL doesn't appear to be a valid MS Teams webhook: {webhook_url[:50]}..."
            )
            # Still allow it, but warn

        # Length check to prevent extremely long URLs
        if len(webhook_url) > 2048:
            logger.warning(
                f"Webhook URL is unusually long ({len(webhook_url)} chars), may be invalid"
            )
            return None

        # Ensure only ASCII characters
        if not webhook_url.isascii():
            logger.warning("Webhook URL contains non-ASCII characters")
            return None

        return webhook_url

    async def __aenter__(self) -> "MSTeamsIntegration":
        """Async context manager entry."""
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        del exc_type, exc_val, exc_tb  # Unused
        if self._client:
            await self._client.aclose()
            self._client = None

    def is_configured(self) -> bool:
        """Check if MS Teams integration is configured.

        Returns:
            True if webhook URL is set
        """
        return bool(self.webhook_url)

    def _get_card_color(self, message_type: MessageType) -> str:
        """Get the accent color for the card based on message type."""
        color_mapping = {
            MessageType.INFO: "0078D4",  # Blue
            MessageType.SUCCESS: "107C10",  # Green
            MessageType.WARNING: "FFB900",  # Yellow
            MessageType.ERROR: "D83B01",  # Red
        }
        return color_mapping.get(message_type, "0078D4")

    def _create_adaptive_card(self, message: TeamsMessage) -> dict[str, Any]:
        """Create an adaptive card for MS Teams.

        Args:
            message: TeamsMessage object with content

        Returns:
            Adaptive card payload
        """
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "Container",
                                "style": "emphasis",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": message.title,
                                        "weight": "bolder",
                                        "size": "large",
                                        "wrap": True,
                                    }
                                ],
                            },
                            {
                                "type": "Container",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": message.message,
                                        "wrap": True,
                                    }
                                ],
                            },
                        ],
                    },
                }
            ],
        }

        # Add facts if provided
        if message.facts:
            fact_set = {
                "type": "FactSet",
                "facts": [{"title": f["title"], "value": f["value"]} for f in message.facts],
            }
            card["attachments"][0]["content"]["body"].append(fact_set)

        # Add custom sections if provided
        if message.sections:
            for section in message.sections:
                card["attachments"][0]["content"]["body"].append(section)

        # Add actions if provided
        if message.actions:
            card["attachments"][0]["content"]["actions"] = message.actions

        return card

    def _create_simple_card(self, title: str, text: str, theme_color: str) -> dict[str, Any]:
        """Create a simple message card (legacy format).

        Args:
            title: Card title
            text: Card text (markdown supported)
            theme_color: Hex color for the card accent

        Returns:
            Message card payload
        """
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": theme_color,
            "title": title,
            "text": text,
        }

    async def send_message(self, message: TeamsMessage, use_adaptive_card: bool = True) -> bool:
        """Send a message to MS Teams.

        Args:
            message: TeamsMessage object to send
            use_adaptive_card: If True, use adaptive card format; else use legacy format

        Returns:
            True if successful, False otherwise
        """
        if not self.is_configured():
            logger.warning("MS Teams integration not configured (no webhook URL)")
            return False

        # Type safety: webhook_url is guaranteed to be str here due to is_configured() check
        if self.webhook_url is None:
            logger.error("Webhook URL is None despite configuration check")
            return False

        try:
            if use_adaptive_card:
                payload = self._create_adaptive_card(message)
            else:
                color = self._get_card_color(message.message_type)
                payload = self._create_simple_card(message.title, message.message, color)

            if self._client:
                response = await self._client.post(self.webhook_url, json=payload, timeout=30.0)
            else:
                async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
                    response = await client.post(self.webhook_url, json=payload)

            response.raise_for_status()
            logger.info(f"Successfully sent message to MS Teams: {message.title}")
            return True

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error sending to MS Teams: {e.response.status_code}")
            return False
        except Exception as e:
            logger.error(f"Failed to send message to MS Teams: {e}")
            return False

    async def send_validation_report(
        self,
        report_title: str,
        total_issues: int,
        errors: int,
        warnings: int,
        suggestions: int,
        policy_files: list[str],
        report_url: str | None = None,
    ) -> bool:
        """Send a validation report to MS Teams.

        Args:
            report_title: Title of the report
            total_issues: Total number of issues found
            errors: Number of errors
            warnings: Number of warnings
            suggestions: Number of suggestions
            policy_files: List of policy files validated
            report_url: Optional URL to full report

        Returns:
            True if successful, False otherwise
        """
        # Determine message type based on findings
        if errors > 0:
            message_type = MessageType.ERROR
            status = "❌ Validation Failed"
        elif warnings > 0:
            message_type = MessageType.WARNING
            status = "⚠️ Validation Passed with Warnings"
        else:
            message_type = MessageType.SUCCESS
            status = "✅ Validation Passed"

        facts = [
            {"title": "Status", "value": status},
            {"title": "Total Issues", "value": str(total_issues)},
            {"title": "Errors", "value": str(errors)},
            {"title": "Warnings", "value": str(warnings)},
            {"title": "Suggestions", "value": str(suggestions)},
            {"title": "Files Validated", "value": str(len(policy_files))},
        ]

        actions = []
        if report_url:
            actions.append(
                {
                    "type": "Action.OpenUrl",
                    "title": "View Full Report",
                    "url": report_url,
                }
            )

        message = TeamsMessage(
            title=report_title,
            message=f"IAM Policy validation completed for {len(policy_files)} file(s).",
            message_type=message_type,
            facts=facts,
            actions=actions,
        )

        return await self.send_message(message)

    async def send_pr_notification(
        self,
        pr_number: int,
        pr_title: str,
        pr_url: str,
        validation_passed: bool,
        issue_summary: dict[str, int],
    ) -> bool:
        """Send a PR validation notification to MS Teams.

        Args:
            pr_number: Pull request number
            pr_title: Pull request title
            pr_url: URL to the PR
            validation_passed: Whether validation passed
            issue_summary: Dictionary with issue counts by severity

        Returns:
            True if successful, False otherwise
        """
        if validation_passed:
            message_type = MessageType.SUCCESS
            status = "✅ PR validation passed"
        else:
            message_type = MessageType.ERROR
            status = "❌ PR validation failed"

        facts = [
            {"title": "PR Number", "value": f"#{pr_number}"},
            {"title": "Status", "value": status},
        ]

        # Add issue counts
        for severity, count in issue_summary.items():
            if count > 0:
                facts.append({"title": severity.capitalize(), "value": str(count)})

        actions = [
            {
                "type": "Action.OpenUrl",
                "title": "View Pull Request",
                "url": pr_url,
            }
        ]

        message = TeamsMessage(
            title=f"PR #{pr_number}: {pr_title}",
            message="IAM Policy validation completed for pull request.",
            message_type=message_type,
            facts=facts,
            actions=actions,
        )

        return await self.send_message(message)

    async def send_alert(
        self,
        title: str,
        message: str,
        severity: MessageType = MessageType.WARNING,
        details: list[str] | None = None,
    ) -> bool:
        """Send an alert notification to MS Teams.

        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity level
            details: Optional list of detail items

        Returns:
            True if successful, False otherwise
        """
        sections = []
        if details:
            detail_text = "\n".join([f"• {detail}" for detail in details])
            sections.append(
                {
                    "type": "Container",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Details:",
                            "weight": "bolder",
                        },
                        {
                            "type": "TextBlock",
                            "text": detail_text,
                            "wrap": True,
                            "spacing": "small",
                        },
                    ],
                }
            )

        teams_message = TeamsMessage(
            title=title,
            message=message,
            message_type=severity,
            sections=sections,
        )

        return await self.send_message(teams_message)

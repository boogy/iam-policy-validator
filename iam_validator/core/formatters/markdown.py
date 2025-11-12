"""Markdown formatter - placeholder for existing functionality."""

from iam_validator.core import constants
from iam_validator.core.formatters.base import OutputFormatter
from iam_validator.core.models import ValidationReport


class MarkdownFormatter(OutputFormatter):
    """Markdown formatter for GitHub comments and documentation."""

    @property
    def format_id(self) -> str:
        return "markdown"

    @property
    def description(self) -> str:
        return "GitHub-flavored markdown for PR comments"

    @property
    def file_extension(self) -> str:
        return "md"

    @property
    def content_type(self) -> str:
        return "text/markdown"

    def format(self, report: ValidationReport, **kwargs) -> str:
        """Format as Markdown.

        Note: The primary markdown generation is handled by ReportGenerator.generate_github_comment().
        This is a simplified formatter for the registry system.
        """
        # Count issues by severity - support both IAM validity and security severities
        errors = sum(
            1
            for r in report.results
            for i in r.issues
            if i.severity in constants.HIGH_SEVERITY_LEVELS
        )
        warnings = sum(
            1 for r in report.results for i in r.issues if i.severity in ("warning", "medium")
        )
        infos = sum(1 for r in report.results for i in r.issues if i.severity in ("info", "low"))

        output = [
            "# IAM Policy Validation Report\n",
            "## Summary",
            f"**Total Policies:** {report.total_policies}",
            f"**Valid (IAM):** {report.valid_policies} ✅",
            f"**Invalid (IAM):** {report.invalid_policies} ❌",
            f"**Security Findings:** {report.policies_with_security_issues} ⚠️",
            "",
            "## Issue Breakdown",
            f"**Total Issues:** {report.total_issues}",
            f"**Validity Issues:** {report.validity_issues} (error/warning/info)",
            f"**Security Issues:** {report.security_issues} (critical/high/medium/low)",
            "",
            "## Legacy Severity Counts",
            f"**Errors:** {errors}",
            f"**Warnings:** {warnings}",
            f"**Info:** {infos}\n",
        ]

        return "\n".join(output)

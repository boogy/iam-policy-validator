"""Report Generation Module.

This module provides functionality to generate validation reports in various formats
including console output, JSON, and GitHub-flavored markdown for PR comments.
"""

import logging

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from iam_validator.__version__ import __version__
from iam_validator.core.formatters import (
    ConsoleFormatter,
    CSVFormatter,
    EnhancedFormatter,
    HTMLFormatter,
    JSONFormatter,
    MarkdownFormatter,
    SARIFFormatter,
    get_global_registry,
)
from iam_validator.core.models import (
    PolicyValidationResult,
    ValidationIssue,
    ValidationReport,
)

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates validation reports in various formats."""

    def __init__(self) -> None:
        """Initialize the report generator."""
        self.console = Console()
        self.formatter_registry = get_global_registry()
        self._register_default_formatters()

    def _register_default_formatters(self) -> None:
        """Register default formatters if not already registered."""
        # Register all built-in formatters
        if not self.formatter_registry.get_formatter("console"):
            self.formatter_registry.register(ConsoleFormatter())
        if not self.formatter_registry.get_formatter("enhanced"):
            self.formatter_registry.register(EnhancedFormatter())
        if not self.formatter_registry.get_formatter("json"):
            self.formatter_registry.register(JSONFormatter())
        if not self.formatter_registry.get_formatter("markdown"):
            self.formatter_registry.register(MarkdownFormatter())
        if not self.formatter_registry.get_formatter("sarif"):
            self.formatter_registry.register(SARIFFormatter())
        if not self.formatter_registry.get_formatter("csv"):
            self.formatter_registry.register(CSVFormatter())
        if not self.formatter_registry.get_formatter("html"):
            self.formatter_registry.register(HTMLFormatter())

    def format_report(self, report: ValidationReport, format_id: str, **kwargs) -> str:
        """Format a report using the specified formatter.

        Args:
            report: Validation report to format
            format_id: ID of the formatter to use
            **kwargs: Additional formatter-specific options

        Returns:
            Formatted string representation
        """
        return self.formatter_registry.format_report(report, format_id, **kwargs)

    def generate_report(self, results: list[PolicyValidationResult]) -> ValidationReport:
        """Generate a validation report from results.

        Args:
            results: List of policy validation results

        Returns:
            ValidationReport
        """
        valid_count = sum(1 for r in results if r.is_valid)
        invalid_count = len(results) - valid_count
        total_issues = sum(len(r.issues) for r in results)

        # Count policies with security issues (separate from validity issues)
        policies_with_security_issues = sum(
            1 for r in results if any(issue.is_security_severity() for issue in r.issues)
        )

        # Count validity vs security issues
        validity_issues = sum(
            sum(1 for issue in r.issues if issue.is_validity_severity()) for r in results
        )
        security_issues = sum(
            sum(1 for issue in r.issues if issue.is_security_severity()) for r in results
        )

        return ValidationReport(
            total_policies=len(results),
            valid_policies=valid_count,
            invalid_policies=invalid_count,
            policies_with_security_issues=policies_with_security_issues,
            total_issues=total_issues,
            validity_issues=validity_issues,
            security_issues=security_issues,
            results=results,
        )

    def print_console_report(self, report: ValidationReport) -> None:
        """Print a formatted console report using Rich.

        Args:
            report: Validation report to display
        """
        # Summary panel
        summary_text = Text()
        summary_text.append(f"Total Policies: {report.total_policies}\n")
        summary_text.append(f"Valid: {report.valid_policies} ", style="green")

        # Show invalid policies (IAM validity issues)
        if report.invalid_policies > 0:
            summary_text.append(f"Invalid: {report.invalid_policies} ", style="red")

        # Show policies with security findings (separate from validity)
        if report.policies_with_security_issues > 0:
            summary_text.append(
                f"Security Findings: {report.policies_with_security_issues} ", style="yellow"
            )

        summary_text.append("\n")

        # Breakdown of issue types
        summary_text.append(f"Total Issues: {report.total_issues}")
        if report.validity_issues > 0 or report.security_issues > 0:
            summary_text.append(" (")
            if report.validity_issues > 0:
                summary_text.append(f"{report.validity_issues} validity", style="red")
            if report.validity_issues > 0 and report.security_issues > 0:
                summary_text.append(", ")
            if report.security_issues > 0:
                summary_text.append(f"{report.security_issues} security", style="yellow")
            summary_text.append(")")
        summary_text.append("\n")

        self.console.print(
            Panel(
                summary_text,
                title=f"Validation Summary (iam-validator v{__version__})",
                border_style="blue",
            )
        )

        # Detailed results
        for result in report.results:
            self._print_policy_result(result)

        # Final status
        if report.invalid_policies == 0:
            self.console.print(
                f"\n[green]✓ All {report.valid_policies} policies are valid![/green]"
                f"\n[yellow]⚠ Issues found: {report.total_issues}[/yellow]"
                if report.total_issues > 0
                else ""
            )
        else:
            self.console.print(f"\n[red]✗ {report.invalid_policies} policies have issues[/red]")

    def _print_policy_result(self, result: PolicyValidationResult) -> None:
        """Print results for a single policy."""
        status = "[green]✓[/green]" if result.is_valid else "[red]✗[/red]"
        self.console.print(f"\n{status} {result.policy_file}")

        if not result.issues:
            self.console.print("  [dim]No issues found[/dim]")
            return

        # Create issues table with adjusted column widths for better readability
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        table.add_column("Severity", style="cyan", width=12, no_wrap=False)
        table.add_column("Type", style="magenta", width=25, no_wrap=False)
        table.add_column("Message", style="white", no_wrap=False)

        for issue in result.issues:
            severity_style = {
                # IAM validity severities
                "error": "[red]ERROR[/red]",
                "warning": "[yellow]WARNING[/yellow]",
                "info": "[blue]INFO[/blue]",
                # Security severities
                "critical": "[bold red]CRITICAL[/bold red]",
                "high": "[red]HIGH[/red]",
                "medium": "[yellow]MEDIUM[/yellow]",
                "low": "[cyan]LOW[/cyan]",
            }.get(issue.severity, issue.severity.upper())

            location = f"Statement {issue.statement_index}"
            if issue.statement_sid:
                location += f" ({issue.statement_sid})"
            if issue.line_number is not None:
                location += f" @L{issue.line_number}"

            message = f"{location}: {issue.message}"
            if issue.suggestion:
                message += f"\n  → {issue.suggestion}"

            table.add_row(severity_style, issue.issue_type, message)

        self.console.print(table)

    def generate_json_report(self, report: ValidationReport) -> str:
        """Generate a JSON report.

        Args:
            report: Validation report

        Returns:
            JSON string
        """
        return report.model_dump_json(indent=2)

    def generate_github_comment_parts(
        self, report: ValidationReport, max_length_per_part: int = 60000
    ) -> list[str]:
        """Generate GitHub PR comment(s), splitting into multiple parts if needed.

        Args:
            report: Validation report
            max_length_per_part: Maximum character length per comment part (default 60000)

        Returns:
            List of comment parts (each under max_length_per_part)
        """
        # Estimate the size needed - if it's likely to fit, generate single comment
        # Otherwise, go straight to multi-part generation
        estimated_size = self._estimate_report_size(report)

        if estimated_size <= max_length_per_part:
            # Try single comment
            single_comment = self.generate_github_comment(
                report, max_length=max_length_per_part * 2
            )
            if len(single_comment) <= max_length_per_part:
                return [single_comment]

        # Need to split into multiple parts
        return self._generate_split_comments(report, max_length_per_part)

    def _estimate_report_size(self, report: ValidationReport) -> int:
        """Estimate the size of the report in characters.

        Args:
            report: Validation report

        Returns:
            Estimated character count
        """
        # Rough estimate: ~500 chars per issue + overhead
        base_overhead = 2000  # Header + footer
        chars_per_issue = 500
        return base_overhead + (report.total_issues * chars_per_issue)

    def _generate_split_comments(self, report: ValidationReport, max_length: int) -> list[str]:
        """Split a large report into multiple comment parts.

        Args:
            report: Validation report
            max_length: Maximum length per part

        Returns:
            List of comment parts
        """
        parts: list[str] = []

        # Generate header (will be in first part only)
        header_lines = self._generate_header(report)
        header_content = "\n".join(header_lines)

        # Generate footer (will be in all parts)
        footer_content = self._generate_footer()

        # Calculate space available for policy details in each part
        # Reserve space for:
        # - "Continued from previous comment" / "Continued in next comment" messages
        # - Part indicator: "**(Part N/M)**\n\n" (estimated ~20 chars)
        # - HTML comment identifier: "<!-- iam-policy-validator -->\n" (~35 chars)
        # - Safety buffer for formatting
        continuation_overhead = 200

        # Sort results to prioritize errors - support both IAM validity and security severities
        sorted_results = sorted(
            [(idx, r) for idx, r in enumerate(report.results, 1) if r.issues],
            key=lambda x: (
                -sum(1 for i in x[1].issues if i.severity in ("error", "critical", "high")),
                -len(x[1].issues),
            ),
        )

        current_part_lines: list[str] = []
        current_length = 0
        is_first_part = True

        for idx, result in sorted_results:
            if not result.issues:
                continue

            # Generate this policy's content
            policy_content = self._format_policy_for_comment(idx, result)
            policy_length = len(policy_content)

            # Add policy to current part if needed (initialize)
            if is_first_part and not current_part_lines:
                current_part_lines.append(header_content)
                current_part_lines.append("")
                current_part_lines.append("## 📝 Detailed Findings")
                current_part_lines.append("")
                current_length = len("\n".join(current_part_lines))
            elif not current_part_lines:
                # Continuation part
                current_part_lines.append("> ⬆️ **Continued from previous comment**")
                current_part_lines.append("")
                current_part_lines.append("## 📝 Detailed Findings (continued)")
                current_part_lines.append("")
                current_length = len("\n".join(current_part_lines))

            # Check if adding this policy would exceed the limit
            test_length = (
                current_length + policy_length + len(footer_content) + continuation_overhead
            )

            if test_length > max_length and len(current_part_lines) > 4:  # 4 = header lines
                # Finalize current part without this policy
                part_content = self._finalize_part(
                    current_part_lines,
                    None,  # Header already added
                    footer_content,
                    continued_in_next=True,
                )
                parts.append(part_content)

                # Start new part
                current_part_lines = []
                current_length = 0
                is_first_part = False

                # Add continuation header
                current_part_lines.append("> ⬆️ **Continued from previous comment**")
                current_part_lines.append("")
                current_part_lines.append("## 📝 Detailed Findings (continued)")
                current_part_lines.append("")
                current_length = len("\n".join(current_part_lines))

            # Add policy to current part
            current_part_lines.append(policy_content)
            current_length += policy_length

        # Finalize last part
        if current_part_lines:
            part_content = self._finalize_part(
                current_part_lines,
                header_content if is_first_part else None,
                footer_content,
                continued_in_next=False,
            )
            parts.append(part_content)

        return parts

    def _generate_header(self, report: ValidationReport) -> list[str]:
        """Generate the comment header with summary."""
        lines = []

        # Title with emoji and status badge
        if report.invalid_policies == 0:
            lines.append("# 🎉 IAM Policy Validation Passed!")
            status_badge = (
                "![Status](https://img.shields.io/badge/status-passed-success?style=flat-square)"
            )
        else:
            lines.append("# 🚨 IAM Policy Validation Failed")
            status_badge = (
                "![Status](https://img.shields.io/badge/status-failed-critical?style=flat-square)"
            )

        lines.append("")
        lines.append(status_badge)
        lines.append("")

        # Summary section
        lines.append("## 📊 Summary")
        lines.append("")
        lines.append("| Metric | Count | Status |")
        lines.append("|--------|------:|:------:|")
        lines.append(f"| **Total Policies Analyzed** | {report.total_policies} | 📋 |")
        lines.append(f"| **Valid Policies** | {report.valid_policies} | ✅ |")
        lines.append(f"| **Invalid Policies** | {report.invalid_policies} | ❌ |")
        lines.append(
            f"| **Total Issues Found** | {report.total_issues} | {'⚠️' if report.total_issues > 0 else '✨'} |"
        )
        lines.append("")

        # Issue breakdown
        if report.total_issues > 0:
            # Count issues - support both IAM validity and security severities
            errors = sum(
                1
                for r in report.results
                for i in r.issues
                if i.severity in ("error", "critical", "high")
            )
            warnings = sum(
                1 for r in report.results for i in r.issues if i.severity in ("warning", "medium")
            )
            infos = sum(
                1 for r in report.results for i in r.issues if i.severity in ("info", "low")
            )

            lines.append("<details>")
            lines.append("<summary><b>🔍 Issue Breakdown</b></summary>")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|------:|")
            if errors > 0:
                lines.append(f"| 🔴 **Errors** | {errors} |")
            if warnings > 0:
                lines.append(f"| 🟡 **Warnings** | {warnings} |")
            if infos > 0:
                lines.append(f"| 🔵 **Info** | {infos} |")
            lines.append("")
            lines.append("</details>")
            lines.append("")

        return lines

    def _generate_footer(self) -> str:
        """Generate the comment footer."""
        return "\n".join(
            [
                "---",
                "",
                "<div align='center'>",
                "",
                "**🤖 Generated by IAM Policy Validator**",
                "",
                "_Powered by AWS IAM Access Analyzer and custom policy checks_",
                "",
                "</div>",
            ]
        )

    def _format_policy_for_comment(self, idx: int, result: PolicyValidationResult) -> str:
        """Format a single policy's issues for the comment."""
        lines = []

        lines.append("<details open>")
        lines.append(
            f"<summary><b>{idx}. <code>{result.policy_file}</code></b> - {len(result.issues)} issue(s) found</summary>"
        )
        lines.append("")

        # Group issues by severity - support both IAM validity and security severities
        errors = [i for i in result.issues if i.severity in ("error", "critical", "high")]
        warnings = [i for i in result.issues if i.severity in ("warning", "medium")]
        infos = [i for i in result.issues if i.severity in ("info", "low")]

        if errors:
            lines.append("### 🔴 Errors")
            lines.append("")
            for issue in errors:
                lines.append(self._format_issue_markdown(issue))
            lines.append("")

        if warnings:
            lines.append("### 🟡 Warnings")
            lines.append("")
            for issue in warnings:
                lines.append(self._format_issue_markdown(issue))
            lines.append("")

        if infos:
            lines.append("### 🔵 Info")
            lines.append("")
            for issue in infos:
                lines.append(self._format_issue_markdown(issue))
            lines.append("")

        lines.append("</details>")
        lines.append("")

        return "\n".join(lines)

    def _finalize_part(
        self,
        lines: list[str],
        header: str | None,
        footer: str,
        continued_in_next: bool,
    ) -> str:
        """Finalize a comment part with header, footer, and continuation messages."""
        parts = []

        if header:
            parts.append(header)

        parts.extend(lines)

        if continued_in_next:
            parts.append("")
            parts.append("> ⬇️ **Continued in next comment...**")
            parts.append("")

        parts.append(footer)

        return "\n".join(parts)

    def generate_github_comment(self, report: ValidationReport, max_length: int = 65000) -> str:
        """Generate a GitHub-flavored markdown comment for PR reviews.

        Args:
            report: Validation report
            max_length: Maximum character length (GitHub limit is 65536, we use 65000 for safety)

        Returns:
            Markdown formatted string
        """
        lines = []

        # Header with emoji and status badge
        if report.invalid_policies == 0:
            lines.append("# 🎉 IAM Policy Validation Passed!")
            status_badge = (
                "![Status](https://img.shields.io/badge/status-passed-success?style=flat-square)"
            )
        else:
            lines.append("# 🚨 IAM Policy Validation Failed")
            status_badge = (
                "![Status](https://img.shields.io/badge/status-failed-critical?style=flat-square)"
            )

        lines.append("")
        lines.append(status_badge)
        lines.append("")

        # Summary section with enhanced table
        lines.append("## 📊 Summary")
        lines.append("")
        lines.append("| Metric | Count | Status |")
        lines.append("|--------|------:|:------:|")
        lines.append(f"| **Total Policies Analyzed** | {report.total_policies} | 📋 |")
        lines.append(f"| **Valid Policies** | {report.valid_policies} | ✅ |")
        lines.append(f"| **Invalid Policies** | {report.invalid_policies} | ❌ |")
        lines.append(
            f"| **Total Issues Found** | {report.total_issues} | {'⚠️' if report.total_issues > 0 else '✨'} |"
        )
        lines.append("")

        # Issue breakdown
        if report.total_issues > 0:
            # Count issues - support both IAM validity and security severities
            errors = sum(
                1
                for r in report.results
                for i in r.issues
                if i.severity in ("error", "critical", "high")
            )
            warnings = sum(
                1 for r in report.results for i in r.issues if i.severity in ("warning", "medium")
            )
            infos = sum(
                1 for r in report.results for i in r.issues if i.severity in ("info", "low")
            )

            lines.append("<details>")
            lines.append("<summary><b>🔍 Issue Breakdown</b></summary>")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|------:|")
            if errors > 0:
                lines.append(f"| 🔴 **Errors** | {errors} |")
            if warnings > 0:
                lines.append(f"| 🟡 **Warnings** | {warnings} |")
            if infos > 0:
                lines.append(f"| 🔵 **Info** | {infos} |")
            lines.append("")
            lines.append("</details>")
            lines.append("")

        # Store header for later (we always include this)
        header_content = "\n".join(lines)

        # Footer (we always include this)
        footer_lines = [
            "---",
            "",
            "<div align='center'>",
            "",
            "**🤖 Generated by IAM Policy Validator**",
            "",
            "_Powered by AWS IAM Access Analyzer and custom policy checks_",
            "",
            "</div>",
        ]
        footer_content = "\n".join(footer_lines)

        # Calculate remaining space for details
        base_length = len(header_content) + len(footer_content) + 100  # 100 for safety
        available_length = max_length - base_length

        # Detailed findings
        if report.invalid_policies > 0:
            details_lines = []
            details_lines.append("## 📝 Detailed Findings")
            details_lines.append("")

            truncated = False
            policies_shown = 0
            issues_shown = 0

            # Sort results to prioritize errors - support both IAM validity and security severities
            sorted_results = sorted(
                [(idx, r) for idx, r in enumerate(report.results, 1) if r.issues],
                key=lambda x: (
                    -sum(1 for i in x[1].issues if i.severity in ("error", "critical", "high")),
                    -len(x[1].issues),
                ),
            )

            for idx, result in sorted_results:
                if not result.issues:
                    continue

                policy_lines = []

                # Group issues by severity - support both IAM validity and security severities
                errors = [i for i in result.issues if i.severity in ("error", "critical", "high")]
                warnings = [i for i in result.issues if i.severity in ("warning", "medium")]
                infos = [i for i in result.issues if i.severity in ("info", "low")]

                # Build severity summary for header
                severity_parts = []
                if errors:
                    severity_parts.append(f"🔴 {len(errors)}")
                if warnings:
                    severity_parts.append(f"🟡 {len(warnings)}")
                if infos:
                    severity_parts.append(f"🔵 {len(infos)}")
                severity_summary = " · ".join(severity_parts)

                # Only open first 3 policy details by default to avoid wall of text
                is_open = " open" if policies_shown < 3 else ""
                policy_lines.append(f"<details{is_open}>")
                policy_lines.append(
                    f"<summary><b>{idx}. <code>{result.policy_file}</code></b> - {severity_summary}</summary>"
                )
                policy_lines.append("")

                # Add errors (prioritized)
                if errors:
                    policy_lines.append("### 🔴 Errors")
                    policy_lines.append("")
                    for i, issue in enumerate(errors):
                        issue_content = self._format_issue_markdown(issue)
                        test_length = len("\n".join(details_lines + policy_lines)) + len(
                            issue_content
                        )
                        if test_length > available_length:
                            truncated = True
                            break
                        policy_lines.append(issue_content)
                        issues_shown += 1
                        # Add separator between issues within same severity
                        if i < len(errors) - 1:
                            policy_lines.append("---")
                            policy_lines.append("")
                    policy_lines.append("")

                if truncated:
                    break

                # Add warnings
                if warnings:
                    policy_lines.append("### 🟡 Warnings")
                    policy_lines.append("")
                    for i, issue in enumerate(warnings):
                        issue_content = self._format_issue_markdown(issue)
                        test_length = len("\n".join(details_lines + policy_lines)) + len(
                            issue_content
                        )
                        if test_length > available_length:
                            truncated = True
                            break
                        policy_lines.append(issue_content)
                        issues_shown += 1
                        # Add separator between issues within same severity
                        if i < len(warnings) - 1:
                            policy_lines.append("---")
                            policy_lines.append("")
                    policy_lines.append("")

                if truncated:
                    break

                # Add infos
                if infos:
                    policy_lines.append("### 🔵 Info")
                    policy_lines.append("")
                    for i, issue in enumerate(infos):
                        issue_content = self._format_issue_markdown(issue)
                        test_length = len("\n".join(details_lines + policy_lines)) + len(
                            issue_content
                        )
                        if test_length > available_length:
                            truncated = True
                            break
                        policy_lines.append(issue_content)
                        issues_shown += 1
                        # Add separator between issues within same severity
                        if i < len(infos) - 1:
                            policy_lines.append("---")
                            policy_lines.append("")
                    policy_lines.append("")

                if truncated:
                    break

                policy_lines.append("</details>")
                policy_lines.append("")
                policy_lines.append("---")
                policy_lines.append("")

                # Check if adding this policy would exceed limit
                test_length = len("\n".join(details_lines + policy_lines))
                if test_length > available_length:
                    truncated = True
                    break

                details_lines.extend(policy_lines)
                policies_shown += 1

            # Add truncation warning if needed
            if truncated:
                remaining_policies = len([r for r in report.results if r.issues]) - policies_shown
                remaining_issues = report.total_issues - issues_shown

                details_lines.append("")
                details_lines.append("> ⚠️ **Output Truncated**")
                details_lines.append(">")
                details_lines.append(
                    "> The report was truncated to fit within GitHub's comment size limit."
                )
                details_lines.append(
                    f"> **Showing:** {policies_shown} policies with {issues_shown} issues"
                )
                details_lines.append(
                    f"> **Remaining:** {remaining_policies} policies with {remaining_issues} issues"
                )
                details_lines.append(">")
                details_lines.append(
                    "> 💡 **Tip:** Download the full report using `--output report.json` or `--format markdown --output report.md`"
                )
                details_lines.append("")

            lines.extend(details_lines)
        else:
            # Success message when no issues
            lines.append("## ✨ All Policies Valid")
            lines.append("")
            lines.append("> 🎯 Great job! All IAM policies passed validation with no issues found.")
            lines.append("")

        # Add footer
        lines.extend(footer_lines)

        return "\n".join(lines)

    def _format_issue_markdown(self, issue: ValidationIssue) -> str:
        """Format a single issue as markdown."""
        location = f"Statement {issue.statement_index}"
        if issue.statement_sid:
            location = f"`{issue.statement_sid}` (index {issue.statement_index})"

        parts = []

        # Issue header with type badge
        parts.append(f"**📍 {location}** · `{issue.issue_type}`")
        parts.append("")

        # Message in blockquote for emphasis
        parts.append(f"> {issue.message}")
        parts.append("")

        # Details section - inline format
        details = []
        if issue.action:
            details.append(f"**Action:** `{issue.action}`")
        if issue.resource:
            details.append(f"**Resource:** `{issue.resource}`")
        if issue.condition_key:
            details.append(f"**Condition Key:** `{issue.condition_key}`")

        if details:
            parts.append(" · ".join(details))
            parts.append("")

        # Suggestion in highlighted box with code examples
        if issue.suggestion:
            # Check if suggestion contains "Example:" section
            if "\nExample:\n" in issue.suggestion:
                text_part, code_part = issue.suggestion.split("\nExample:\n", 1)
                parts.append(f"> 💡 **Suggestion:** {text_part}")
                parts.append("")
                parts.append("<details>")
                parts.append("<summary>📖 View Example</summary>")
                parts.append("")
                parts.append("```json")
                parts.append(code_part)
                parts.append("```")
                parts.append("</details>")
                parts.append("")
            else:
                parts.append(f"> 💡 **Suggestion:** {issue.suggestion}")
                parts.append("")

        return "\n".join(parts)

    def save_json_report(self, report: ValidationReport, file_path: str) -> None:
        """Save report to a JSON file.

        Args:
            report: Validation report
            file_path: Path to save the JSON file
        """
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.generate_json_report(report))
            logger.info(f"Saved JSON report to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save JSON report: {e}")
            raise

    def save_markdown_report(self, report: ValidationReport, file_path: str) -> None:
        """Save GitHub markdown report to a file.

        Args:
            report: Validation report
            file_path: Path to save the markdown file
        """
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.generate_github_comment(report))
            logger.info(f"Saved markdown report to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save markdown report: {e}")
            raise

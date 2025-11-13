"""Report generation for IAM Access Analyzer validation results."""

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from iam_validator.__version__ import __version__
from iam_validator.core.access_analyzer import (
    AccessAnalyzerFinding,
    AccessAnalyzerReport,
    AccessAnalyzerResult,
    CustomCheckResult,
    FindingType,
)


class AccessAnalyzerReportFormatter:
    """Formats Access Analyzer validation results for various outputs."""

    def __init__(self) -> None:
        """Initialize the report formatter."""
        self.console = Console()

    def print_console_report(self, report: AccessAnalyzerReport) -> None:
        """Print a formatted console report using Rich.

        Args:
            report: Access Analyzer validation report
        """
        # Print summary
        self._print_summary(report)

        # Print detailed results for each policy
        for result in report.results:
            self._print_policy_result(result)

        # Print final statistics
        self._print_statistics(report)

    def _print_summary(self, report: AccessAnalyzerReport) -> None:
        """Print summary panel."""
        summary_text = Text()
        summary_text.append(f"Total Policies: {report.total_policies}\n")
        summary_text.append("Valid Policies: ", style="bold")
        summary_text.append(f"{report.valid_policies}\n", style="bold green")
        summary_text.append("Invalid Policies: ", style="bold")
        summary_text.append(f"{report.invalid_policies}\n", style="bold red")
        summary_text.append(f"\nTotal Findings: {report.total_findings}\n")
        summary_text.append("  Errors: ", style="bold")
        summary_text.append(f"{report.total_errors}\n", style="bold red")
        summary_text.append("  Warnings: ", style="bold")
        summary_text.append(f"{report.total_warnings}\n", style="bold yellow")
        summary_text.append("  Suggestions: ", style="bold")
        summary_text.append(f"{report.total_suggestions}", style="bold blue")

        # Add custom checks summary if present
        total_custom_checks = sum(len(r.custom_checks) for r in report.results if r.custom_checks)
        failed_custom_checks = sum(r.failed_custom_checks for r in report.results)

        if total_custom_checks > 0:
            summary_text.append(f"\n\nCustom Policy Checks: {total_custom_checks}\n")
            summary_text.append("  Failed Checks: ", style="bold")
            if failed_custom_checks > 0:
                summary_text.append(f"{failed_custom_checks}", style="bold red")
            else:
                summary_text.append(f"{failed_custom_checks}", style="bold green")

        panel = Panel(
            summary_text,
            title=f"[bold]Access Analyzer Validation Summary (iam-validator v{__version__})[/bold]",
            border_style="blue",
        )
        self.console.print(panel)
        self.console.print()

    def _print_policy_result(self, result: AccessAnalyzerResult) -> None:
        """Print results for a single policy."""
        # Policy header
        status_emoji = "✅" if result.is_valid else "❌"
        status_text = "VALID" if result.is_valid else "INVALID"
        status_style = "bold green" if result.is_valid else "bold red"

        self.console.print(
            f"\n{status_emoji} [bold]{result.policy_file}[/bold] - "
            f"[{status_style}]{status_text}[/{status_style}]"
        )

        # Handle errors
        if result.error:
            self.console.print(f"  [red]Error: {result.error}[/red]")
            return

        # Print custom check results
        if result.custom_checks:
            self.console.print("\n  [bold cyan]Custom Policy Checks:[/bold cyan]")
            for check in result.custom_checks:
                self._print_custom_check(check)

        # Print findings
        if not result.findings:
            self.console.print("  [green]No findings[/green]")
            return

        # Group findings by type
        for finding in result.findings:
            self._print_finding(finding)

    def _print_finding(self, finding: AccessAnalyzerFinding) -> None:
        """Print a single finding."""
        # Icon and color based on finding type
        icons = {
            FindingType.ERROR: ("❌", "red"),
            FindingType.SECURITY_WARNING: ("⚠️", "yellow"),
            FindingType.WARNING: ("⚠️", "yellow"),
            FindingType.SUGGESTION: ("💡", "blue"),
        }
        icon, color = icons.get(finding.finding_type, ("ℹ️", "white"))

        self.console.print(f"\n  {icon} [{color}]{finding.finding_type.value}[/{color}]")
        self.console.print(f"     Code: [bold]{finding.issue_code}[/bold]")
        self.console.print(f"     {finding.message}")

        # Print locations if available
        if finding.locations:
            self.console.print("     Locations:")
            for loc in finding.locations:
                path = loc.get("path", [])
                span = loc.get("span", {})
                if path:
                    path_str = " → ".join(str(p.get("value", p)) for p in path)
                    self.console.print(f"       • {path_str}")
                if span:
                    start = span.get("start", {})
                    line_info = f"Line {start.get('line', '?')}"
                    if start.get("column"):
                        line_info += f", Column {start.get('column')}"
                    self.console.print(f"         {line_info}")

        self.console.print(f"     [dim]Learn more: {finding.learn_more_link}[/dim]")

    def _print_custom_check(self, check: CustomCheckResult) -> None:
        """Print a custom policy check result."""
        # Icon and color based on result
        if check.passed:
            icon, color = ("✅", "green")
            result_text = "PASS"
        else:
            icon, color = ("❌", "red")
            result_text = "FAIL"

        self.console.print(f"\n  {icon} [{color}]{check.check_type}: {result_text}[/{color}]")
        if check.message:
            self.console.print(f"     {check.message}")

        # Print reasons if failed
        if check.reasons and not check.passed:
            self.console.print("     [yellow]Reasons:[/yellow]")
            for reason in check.reasons:
                self.console.print(f"       • {reason.description}")
                if reason.statement_id:
                    self.console.print(f"         Statement ID: {reason.statement_id}")
                if reason.statement_index is not None:
                    self.console.print(f"         Statement Index: {reason.statement_index}")

    def _print_statistics(self, report: AccessAnalyzerReport) -> None:
        """Print final statistics table."""
        self.console.print("\n")

        table = Table(title="Finding Statistics", show_header=True, header_style="bold magenta")
        table.add_column("Finding Type", style="cyan", no_wrap=True)
        table.add_column("Count", justify="right", style="green")

        table.add_row("Errors", str(report.total_errors), style="red")
        table.add_row("Warnings", str(report.total_warnings), style="yellow")
        table.add_row("Suggestions", str(report.total_suggestions), style="blue")
        table.add_row("Total", str(report.total_findings), style="bold")

        self.console.print(table)

    def generate_json_report(self, report: AccessAnalyzerReport) -> str:
        """Generate JSON report.

        Args:
            report: Access Analyzer validation report

        Returns:
            JSON string
        """
        data: dict[str, Any] = {
            "summary": {
                "total_policies": report.total_policies,
                "valid_policies": report.valid_policies,
                "invalid_policies": report.invalid_policies,
                "total_findings": report.total_findings,
                "total_errors": report.total_errors,
                "total_warnings": report.total_warnings,
                "total_suggestions": report.total_suggestions,
            },
            "results": [],
        }

        for result in report.results:
            result_data: dict[str, Any] = {
                "policy_file": result.policy_file,
                "is_valid": result.is_valid,
                "error_count": result.error_count,
                "warning_count": result.warning_count,
                "suggestion_count": result.suggestion_count,
                "findings": [],
            }

            if result.error:
                result_data["error"] = result.error

            # Add custom checks if present
            if result.custom_checks:
                result_data["custom_checks"] = []
                for check in result.custom_checks:
                    check_data = {
                        "check_type": check.check_type,
                        "result": check.result.value,
                        "passed": check.passed,
                        "message": check.message,
                        "reasons": [
                            {
                                "description": r.description,
                                "statement_id": r.statement_id,
                                "statement_index": r.statement_index,
                            }
                            for r in check.reasons
                        ],
                    }
                    result_data["custom_checks"].append(check_data)

            for finding in result.findings:
                finding_data = {
                    "finding_type": finding.finding_type.value,
                    "severity": finding.severity,
                    "issue_code": finding.issue_code,
                    "message": finding.message,
                    "learn_more_link": finding.learn_more_link,
                    "locations": finding.locations,
                }
                result_data["findings"].append(finding_data)

            data["results"].append(result_data)

        return json.dumps(data, indent=2)

    def save_json_report(self, report: AccessAnalyzerReport, file_path: str) -> None:
        """Save JSON report to file.

        Args:
            report: Access Analyzer validation report
            file_path: Path to save JSON report
        """
        json_content = self.generate_json_report(report)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(json_content)

    def generate_markdown_report(
        self, report: AccessAnalyzerReport, max_length: int = 65000
    ) -> str:
        """Generate Markdown report.

        Args:
            report: Access Analyzer validation report
            max_length: Maximum character length (GitHub limit is 65536, we use 65000 for safety)

        Returns:
            Markdown string
        """
        lines = []

        # Title with emoji and status badge
        if report.invalid_policies == 0:
            lines.append("# 🛡️ IAM Access Analyzer Validation Passed!")
            status_badge = "![Status](https://img.shields.io/badge/AWS%20Access%20Analyzer-passed-success?style=flat-square&logo=amazon-aws)"
        else:
            lines.append("# 🔍 IAM Access Analyzer Validation Results")
            status_badge = "![Status](https://img.shields.io/badge/AWS%20Access%20Analyzer-issues%20found-critical?style=flat-square&logo=amazon-aws)"

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
            f"| **Total Findings** | {report.total_findings} | {'⚠️' if report.total_findings > 0 else '✨'} |"
        )

        # Add custom checks summary if present
        total_custom_checks = sum(len(r.custom_checks) for r in report.results if r.custom_checks)
        failed_custom_checks = sum(r.failed_custom_checks for r in report.results)

        if total_custom_checks > 0:
            lines.append(f"| **Custom Policy Checks** | {total_custom_checks} | 🔍 |")
            if failed_custom_checks > 0:
                lines.append(f"| **Failed Custom Checks** | {failed_custom_checks} | ❌ |")
            else:
                lines.append(f"| **Failed Custom Checks** | {failed_custom_checks} | ✅ |")

        lines.append("")

        # Findings breakdown
        if report.total_findings > 0:
            lines.append("<details>")
            lines.append("<summary><b>🔍 Findings Breakdown</b></summary>")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|------:|")
            if report.total_errors > 0:
                lines.append(f"| 🔴 **Errors** | {report.total_errors} |")
            if report.total_warnings > 0:
                lines.append(f"| 🟡 **Warnings** | {report.total_warnings} |")
            if report.total_suggestions > 0:
                lines.append(f"| 🔵 **Suggestions** | {report.total_suggestions} |")
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
            "🤖 <em>Generated by <strong>IAM Policy Validator</strong></em><br>",
            "<sub>Powered by AWS IAM Access Analyzer</sub>",
            "</div>",
        ]
        footer_content = "\n".join(footer_lines)

        # Calculate remaining space for details
        base_length = len(header_content) + len(footer_content) + 100  # 100 for safety
        available_length = max_length - base_length

        # Detailed results
        details_lines = []
        details_lines.append("## 📝 Detailed Results")
        details_lines.append("")

        truncated = False
        policies_shown = 0
        findings_shown = 0

        # Sort results to prioritize errors
        sorted_results = sorted(
            [(idx, r) for idx, r in enumerate(report.results, 1)],
            key=lambda x: (
                -x[1].error_count if x[1].error_count else 0,
                -(x[1].error_count + x[1].warning_count + x[1].suggestion_count),
            ),
        )

        for idx, result in sorted_results:
            status_emoji = "✅" if result.is_valid else "❌"

            policy_lines = []
            # File header with collapsible section
            policy_lines.append(f"<details {'open' if result.findings else ''}>")
            policy_lines.append(
                f"<summary><b>{idx}. {status_emoji} <code>{result.policy_file}</code></b>"
            )
            if result.findings:
                policy_lines.append(f" - {len(result.findings)} finding(s)")
            policy_lines.append("</summary>")
            policy_lines.append("")

            if result.error:
                policy_lines.append(f"> ❌ **Error**: {result.error}")
                policy_lines.append("")
                policy_lines.append("</details>")
                policy_lines.append("")

                # Check if we can fit this
                test_length = len("\n".join(details_lines + policy_lines))
                if test_length > available_length:
                    truncated = True
                    break

                details_lines.extend(policy_lines)
                policies_shown += 1
                continue

            # Add custom check results if present
            if result.custom_checks:
                policy_lines.append("### 🔍 Custom Policy Checks")
                policy_lines.append("")
                for check in result.custom_checks:
                    check_lines = self._format_custom_check_markdown(check)
                    policy_lines.extend(check_lines)
                policy_lines.append("")

            if not result.findings:
                policy_lines.append("> ✨ **No findings** - Policy is valid!")
                policy_lines.append("")
                policy_lines.append("</details>")
                policy_lines.append("")

                # Check if we can fit this
                test_length = len("\n".join(details_lines + policy_lines))
                if test_length > available_length:
                    truncated = True
                    break

                details_lines.extend(policy_lines)
                policies_shown += 1
                continue

            # Group findings by type
            errors = [f for f in result.findings if f.finding_type == FindingType.ERROR]
            warnings = [
                f
                for f in result.findings
                if f.finding_type in (FindingType.WARNING, FindingType.SECURITY_WARNING)
            ]
            suggestions = [f for f in result.findings if f.finding_type == FindingType.SUGGESTION]

            # Add errors (prioritized)
            if errors:
                policy_lines.append("### 🔴 Errors")
                policy_lines.append("")
                for finding in errors:
                    finding_content = self._format_finding_markdown(finding)
                    test_length = len("\n".join(details_lines + policy_lines)) + len(
                        "\n".join(finding_content)
                    )
                    if test_length > available_length:
                        truncated = True
                        break
                    policy_lines.extend(finding_content)
                    findings_shown += 1
                policy_lines.append("")

            if truncated:
                break

            # Add warnings
            if warnings:
                policy_lines.append("### 🟡 Warnings")
                policy_lines.append("")
                for finding in warnings:
                    finding_content = self._format_finding_markdown(finding)
                    test_length = len("\n".join(details_lines + policy_lines)) + len(
                        "\n".join(finding_content)
                    )
                    if test_length > available_length:
                        truncated = True
                        break
                    policy_lines.extend(finding_content)
                    findings_shown += 1
                policy_lines.append("")

            if truncated:
                break

            # Add suggestions
            if suggestions:
                policy_lines.append("### 🔵 Suggestions")
                policy_lines.append("")
                for finding in suggestions:
                    finding_content = self._format_finding_markdown(finding)
                    test_length = len("\n".join(details_lines + policy_lines)) + len(
                        "\n".join(finding_content)
                    )
                    if test_length > available_length:
                        truncated = True
                        break
                    policy_lines.extend(finding_content)
                    findings_shown += 1
                policy_lines.append("")

            if truncated:
                break

            policy_lines.append("</details>")
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
            remaining_policies = report.total_policies - policies_shown
            remaining_findings = report.total_findings - findings_shown

            details_lines.append("")
            details_lines.append("> ⚠️ **Output Truncated**")
            details_lines.append(">")
            details_lines.append(
                "> The report was truncated to fit within GitHub's comment size limit."
            )
            details_lines.append(
                f"> **Showing:** {policies_shown} policies with {findings_shown} findings"
            )
            details_lines.append(
                f"> **Remaining:** {remaining_policies} policies with {remaining_findings} findings"
            )
            details_lines.append(">")
            details_lines.append(
                "> 💡 **Tip:** Download the full report using `--output report.json` or `--format markdown --output report.md`"
            )
            details_lines.append("")

        lines.extend(details_lines)

        # Add footer
        lines.extend(footer_lines)

        return "\n".join(lines)

    def _format_custom_check_markdown(self, check: CustomCheckResult) -> list[str]:
        """Format a custom check result as markdown lines.

        Args:
            check: The custom check result to format

        Returns:
            List of markdown lines
        """
        lines = []

        # Check header with result
        if check.passed:
            icon = "✅"
            badge_color = "green"
        else:
            icon = "❌"
            badge_color = "red"

        lines.append(
            f"{icon} **{check.check_type}**: "
            f"![{check.result.value}](https://img.shields.io/badge/{check.result.value}-{badge_color})"
        )
        lines.append("")

        # Message if available
        if check.message:
            lines.append(f"> {check.message}")
            lines.append("")

        # Reasons if failed
        if check.reasons and not check.passed:
            lines.append("<table>")
            lines.append("<tr><td>")
            lines.append("")
            lines.append("**Reasons:**")
            lines.append("")
            for reason in check.reasons:
                lines.append(f"- {reason.description}")
                if reason.statement_id:
                    lines.append(f"  - Statement ID: `{reason.statement_id}`")
                if reason.statement_index is not None:
                    lines.append(f"  - Statement Index: `{reason.statement_index}`")
            lines.append("")
            lines.append("</td></tr>")
            lines.append("</table>")
            lines.append("")

        return lines

    def _format_finding_markdown(self, finding: AccessAnalyzerFinding) -> list[str]:
        """Format a single finding as markdown lines.

        Args:
            finding: The finding to format

        Returns:
            List of markdown lines
        """
        lines = []

        # Finding header with code
        lines.append(f"**📍 `{finding.issue_code}`**")
        lines.append("")

        # Message in blockquote
        lines.append(f"> {finding.message}")
        lines.append("")

        # Locations if available
        if finding.locations:
            lines.append("<table>")
            lines.append("<tr><td>")
            lines.append("")
            lines.append("**Locations:**")
            lines.append("")
            for loc in finding.locations:
                path = loc.get("path", [])
                span = loc.get("span", {})
                if path:
                    path_str = " → ".join(str(p.get("value", p)) for p in path)
                    lines.append(f"- 📂 {path_str}")
                if span:
                    start = span.get("start", {})
                    line_info = f"Line {start.get('line', '?')}"
                    if start.get("column"):
                        line_info += f", Column {start.get('column')}"
                    lines.append(f"  - 📍 {line_info}")
            lines.append("")
            lines.append("</td></tr>")
            lines.append("</table>")
            lines.append("")

        # Learn more link as button-style
        lines.append(f"[📚 Learn more]({finding.learn_more_link})")
        lines.append("")

        return lines

    def save_markdown_report(self, report: AccessAnalyzerReport, file_path: str) -> None:
        """Save Markdown report to file.

        Args:
            report: Access Analyzer validation report
            file_path: Path to save Markdown report
        """
        markdown_content = self.generate_markdown_report(report)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)

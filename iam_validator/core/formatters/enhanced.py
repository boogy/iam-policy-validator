"""Enhanced formatter - Rich-based console output with modern design."""

from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from iam_validator.__version__ import __version__
from iam_validator.core import constants
from iam_validator.core.formatters.base import OutputFormatter
from iam_validator.core.models import PolicyValidationResult, ValidationReport


class EnhancedFormatter(OutputFormatter):
    """Enhanced console formatter with modern, visually rich output using Rich library."""

    @property
    def format_id(self) -> str:
        return "enhanced"

    @property
    def description(self) -> str:
        return "Enhanced console output with progress bars, tree structure, and rich visuals"

    def format(self, report: ValidationReport, **kwargs) -> str:
        """Format validation report as modern Rich console output.

        This creates a visually enhanced string representation with:
        - Gradient-styled headers
        - Progress bars for validation metrics
        - Tree structure for issues
        - Bordered panels with icons

        Args:
            report: Validation report to format
            **kwargs: Additional options:
                - color (bool): Enable color output (default: True)
                - show_summary (bool): Show Executive Summary panel (default: True)
                - show_severity_breakdown (bool): Show Issue Severity Breakdown panel (default: True)

        Returns:
            Formatted string with ANSI codes for console display
        """
        # Allow disabling color for plain text output
        color = kwargs.get("color", True)
        show_summary = kwargs.get("show_summary", True)
        show_severity_breakdown = kwargs.get("show_severity_breakdown", True)

        # Use StringIO to capture Rich console output
        from iam_validator.utils import get_terminal_width

        string_buffer = StringIO()
        # Get terminal width for proper text wrapping
        terminal_width = get_terminal_width()
        console = Console(file=string_buffer, force_terminal=color, width=terminal_width, legacy_windows=False)

        # Header with title
        title = Text(
            f"IAM Policy Validation Report (v{__version__})",
            style="bold cyan",
            justify="center",
        )
        console.print(
            Panel(
                title,
                border_style=constants.CONSOLE_HEADER_COLOR,
                padding=(1, 0),
                width=constants.CONSOLE_PANEL_WIDTH,
            )
        )

        # Executive Summary with progress bars (optional)
        if show_summary:
            self._print_summary_panel(console, report)

        # Severity breakdown if there are issues (optional)
        if show_severity_breakdown and report.total_issues > 0:
            self._print_severity_breakdown(console, report)

        console.print(
            Rule(
                title="[bold]Detailed Results",
                style=constants.CONSOLE_HEADER_COLOR,
            ),
            width=constants.CONSOLE_PANEL_WIDTH,
        )

        # Detailed results using tree structure
        for idx, result in enumerate(report.results, 1):
            self._format_policy_result_modern(console, result, idx, len(report.results))

        # Final status with styled box
        console.print()
        self._print_final_status(console, report)

        # Get the formatted output
        output = string_buffer.getvalue().rstrip("\n")
        string_buffer.close()

        return output

    def _print_summary_panel(self, console: Console, report: ValidationReport) -> None:
        """Print summary panel with clean metrics display."""
        # Create a simple table for metrics without progress bars.
        # First column is sized to fit the longest label ("Policies with Errors (AWS-invalid)")
        # without wrapping.
        metrics_table = Table.grid(padding=(0, 2))
        metrics_table.add_column(style="bold", justify="left", width=42, no_wrap=True)
        metrics_table.add_column(style="bold", justify="left", width=20, no_wrap=True)

        # Total policies
        metrics_table.add_row(
            "📋 Total Policies",
            str(report.total_policies),
        )

        # Policies with errors (AWS-invalid) and policies with findings
        if report.total_policies > 0:
            policies_with_errors = report.policies_with_errors
            policies_with_findings = report.policies_with_findings

            errors_pct = policies_with_errors * 100 // report.total_policies
            if policies_with_errors > 0:
                metrics_table.add_row(
                    "❌ Policies with Errors (AWS-invalid)",
                    f"[red]{policies_with_errors} ({errors_pct}%)[/red]",
                )
            else:
                metrics_table.add_row(
                    "✅ Policies with Errors (AWS-invalid)",
                    f"[green]{policies_with_errors} ({errors_pct}%)[/green]",
                )

            findings_pct = policies_with_findings * 100 // report.total_policies
            if policies_with_findings > 0:
                metrics_table.add_row(
                    "⚠️  Policies with Findings",
                    f"[yellow]{policies_with_findings} ({findings_pct}%)[/yellow]",
                )
            else:
                metrics_table.add_row(
                    "✨ Policies with Findings",
                    f"[green]{policies_with_findings} ({findings_pct}%)[/green]",
                )

        # Total issues
        if report.total_issues > 0:
            metrics_table.add_row(
                "⚠️  Total Issues Found",
                f"[red]{report.total_issues}[/red]",
            )
        else:
            metrics_table.add_row(
                "⚠️  Total Issues Found",
                f"[green]{report.total_issues}[/green]",
            )

        console.print(
            Panel(
                metrics_table,
                title="📊 Executive Summary",
                border_style=constants.CONSOLE_HEADER_COLOR,
                padding=(1, 2),
                width=constants.CONSOLE_PANEL_WIDTH,
            )
        )

    def _create_progress_bar(self, value: int, total: int, color: str) -> str:
        """Create a simple text-based progress bar."""
        if total == 0:
            return "[dim]───────────────────────[/dim]"

        percentage = min(value * 100 // total, 100)
        filled = int(percentage / 5)  # 20 bars total (100/5)
        empty = 20 - filled

        bar = f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"
        return bar

    def _print_severity_breakdown(self, console: Console, report: ValidationReport) -> None:
        """Print a clean breakdown of issues by severity."""
        # Count issues by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "error": 0,
            "medium": 0,
            "warning": 0,
            "low": 0,
            "info": 0,
        }

        for result in report.results:
            for issue in result.issues:
                severity = issue.severity.lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

        # Create clean severity table
        severity_table = Table.grid(padding=(0, 2))
        severity_table.add_column(style="bold", justify="left", width=25)
        severity_table.add_column(style="bold", justify="left", width=15)

        # Show individual severity counts
        if severity_counts["critical"] > 0:
            severity_table.add_row(
                "🔴 Critical",
                f"[red]{severity_counts['critical']}[/red]",
            )

        if severity_counts["high"] > 0:
            severity_table.add_row(
                "🔴 High",
                f"[red]{severity_counts['high']}[/red]",
            )

        if severity_counts["error"] > 0:
            severity_table.add_row(
                "🔴 Error",
                f"[red]{severity_counts['error']}[/red]",
            )

        if severity_counts["medium"] > 0:
            severity_table.add_row(
                "🟡 Medium",
                f"[yellow]{severity_counts['medium']}[/yellow]",
            )

        if severity_counts["warning"] > 0:
            severity_table.add_row(
                "🟡 Warning",
                f"[yellow]{severity_counts['warning']}[/yellow]",
            )

        if severity_counts["low"] > 0:
            severity_table.add_row(
                "🔵 Low",
                f"[blue]{severity_counts['low']}[/blue]",
            )

        if severity_counts["info"] > 0:
            severity_table.add_row(
                "🔵 Info",
                f"[blue]{severity_counts['info']}[/blue]",
            )

        console.print(
            Panel(
                severity_table,
                title="🎯 Issue Severity Breakdown",
                border_style=constants.CONSOLE_HEADER_COLOR,
                width=constants.CONSOLE_PANEL_WIDTH,
            )
        )

    def _format_policy_result_modern(
        self, console: Console, result: PolicyValidationResult, idx: int, total: int
    ) -> None:
        """Format policy results with modern tree structure.

        Args:
            console: Rich console instance
            result: Policy validation result
            idx: Index of this policy (1-based)
            total: Total number of policies
        """
        # Status icon and color
        if result.is_valid and not result.issues:
            icon = "✅"
            color = "green"
            status_text = "VALID"
        elif result.is_valid and result.issues:
            # Valid IAM policy but has security findings
            # Check severity to determine the appropriate status
            has_critical = any(i.severity in constants.HIGH_SEVERITY_LEVELS for i in result.issues)
            if has_critical:
                icon = "⚠️"
                color = "red"
                status_text = "VALID (with security issues)"
            else:
                icon = "⚠️"
                color = "yellow"
                status_text = "VALID (with warnings)"
        else:
            # Policy failed validation (is_valid=false)
            # Check if it's due to IAM errors or security issues
            has_iam_errors = any(i.severity == "error" for i in result.issues)
            has_security_critical = any(i.severity in ("critical", "high") for i in result.issues)

            if has_iam_errors and has_security_critical:
                # Both IAM errors and security issues
                status_text = "INVALID (IAM errors + security issues)"
            elif has_iam_errors:
                # Only IAM validation errors
                status_text = "INVALID (IAM errors)"
            else:
                # Only security issues (failed due to fail_on_severity config)
                status_text = "FAILED (critical security issues)"

            icon = "❌"
            color = "red"

        # Policy header
        header = Text()
        header.append(f"{icon} ", style=color)
        header.append(f"[{idx}/{total}] ", style="dim")
        header.append(result.policy_file, style=f"bold {color}")
        header.append(f" • {status_text}", style=f"{color}")

        if not result.issues:
            console.print(header)
            console.print("     [dim italic]No issues detected[/dim italic]")
            return

        console.print(header)
        console.print(f"     [dim]{len(result.issues)} issue(s) found[/dim]")
        # Create tree structure for issues
        tree = Tree(f"[bold]Issues ({len(result.issues)})[/bold]", guide_style="bright_black")

        # Group issues by severity with proper categorization
        critical_issues = [i for i in result.issues if i.severity == "critical"]
        high_issues = [i for i in result.issues if i.severity == "high"]
        error_issues = [i for i in result.issues if i.severity == "error"]
        medium_issues = [i for i in result.issues if i.severity == "medium"]
        warning_issues = [i for i in result.issues if i.severity == "warning"]
        low_issues = [i for i in result.issues if i.severity == "low"]
        info_issues = [i for i in result.issues if i.severity == "info"]

        # Add critical issues (security checks)
        if critical_issues:
            critical_branch = tree.add("🔴 [bold red]Critical[/bold red]")
            for issue in critical_issues:
                self._add_issue_to_tree(critical_branch, issue, "red")

        # Add high severity issues (security checks)
        if high_issues:
            high_branch = tree.add("🔴 [bold red]High[/bold red]")
            for issue in high_issues:
                self._add_issue_to_tree(high_branch, issue, "red")

        # Add errors (IAM validation)
        if error_issues:
            error_branch = tree.add("🔴 [bold red]Error[/bold red]")
            for issue in error_issues:
                self._add_issue_to_tree(error_branch, issue, "red")

        # Add medium severity issues (security checks)
        if medium_issues:
            medium_branch = tree.add("🟡 [bold yellow]Medium[/bold yellow]")
            for issue in medium_issues:
                self._add_issue_to_tree(medium_branch, issue, "yellow")

        # Add warnings (IAM validation)
        if warning_issues:
            warning_branch = tree.add("🟡 [bold yellow]Warning[/bold yellow]")
            for issue in warning_issues:
                self._add_issue_to_tree(warning_branch, issue, "yellow")

        # Add low severity issues (security checks)
        if low_issues:
            low_branch = tree.add("🔵 [bold blue]Low[/bold blue]")
            for issue in low_issues:
                self._add_issue_to_tree(low_branch, issue, "blue")

        # Add info (IAM validation)
        if info_issues:
            info_branch = tree.add("🔵 [bold blue]Info[/bold blue]")
            for issue in info_issues:
                self._add_issue_to_tree(info_branch, issue, "blue")

        console.print("   ", tree)
        console.print()

    def _add_issue_to_tree(self, branch: Tree, issue, color: str) -> None:
        """Add an issue to a tree branch."""
        # Build location string (use 1-indexed statement numbers for user-facing output)
        # Handle policy-level issues (statement_index = -1)
        if issue.statement_index == -1:
            location = "Policy-level"
        else:
            statement_num = issue.statement_index + 1
            location = f"Statement {statement_num}"
            if issue.statement_sid:
                location = f"{issue.statement_sid} (#{statement_num})"
        if issue.line_number is not None:
            location += f" @L{issue.line_number}"

        # Issue summary
        issue_text = Text()
        issue_text.append(f"[{location}] ", style="dim")
        issue_text.append(issue.issue_type, style=f"bold {color}")
        issue_node = branch.add(issue_text)

        # Message
        msg_node = issue_node.add(Text(issue.message, style="white"))

        # Details
        if issue.action or issue.resource or issue.condition_key:
            details = []
            if issue.action:
                details.append(f"Action: {issue.action}")
            if issue.resource:
                details.append(f"Resource: {issue.resource}")
            if issue.condition_key:
                details.append(f"Condition: {issue.condition_key}")
            msg_node.add(Text(" • ".join(details), style="dim cyan"))

        # Suggestion and Example - combine into single node to reduce spacing
        if issue.suggestion or issue.example:
            combined_text = Text()

            # Add suggestion
            if issue.suggestion:
                combined_text.append("💡 ", style="yellow")
                combined_text.append(issue.suggestion, style="italic yellow")

            # Add example on same node (reduces vertical spacing)
            if issue.example:
                if issue.suggestion:
                    combined_text.append("\n", style="yellow")  # Single newline separator
                combined_text.append("Example:", style="bold cyan")
                combined_text.append("\n")
                combined_text.append(issue.example, style="dim")

            msg_node.add(combined_text)

    def _print_final_status(self, console: Console, report: ValidationReport) -> None:
        """Print final status panel."""
        policies_with_errors = report.policies_with_errors
        policies_with_findings = report.policies_with_findings

        if policies_with_errors == 0 and report.total_issues == 0:
            # Perfect success
            status = Text("🎉 ALL POLICIES VALIDATED SUCCESSFULLY! 🎉", style="bold green")
            message = Text(
                f"All {report.total_policies} policies are structurally valid with no findings.",
                style="green",
            )
            border_color = "green"
        elif policies_with_errors == 0:
            # Structurally valid policies but may have security/best-practice findings
            has_critical = any(i.severity in constants.HIGH_SEVERITY_LEVELS for r in report.results for i in r.issues)

            _p = lambda n, word: f"{n} {word}" + ("" if n == 1 else "s")  # noqa: E731
            if has_critical:
                status = Text("⚠️ All Policies Structurally Valid (with findings)", style="bold red")
                message = Text(
                    f"All {report.total_policies} policies are structurally valid (AWS-accepted), but "
                    f"{_p(policies_with_findings, 'policy')} "
                    f"{'has' if policies_with_findings == 1 else 'have'} "
                    f"{_p(report.total_issues, 'finding')} that must be addressed.",
                    style="red",
                )
                border_color = "red"
            else:
                status = Text("✅ All Policies Structurally Valid (with advisories)", style="bold yellow")
                message = Text(
                    f"All {report.total_policies} policies are structurally valid, but "
                    f"{_p(policies_with_findings, 'policy')} "
                    f"{'has' if policies_with_findings == 1 else 'have'} "
                    f"{_p(report.total_issues, 'advisory finding')} that should be reviewed.",
                    style="yellow",
                )
                border_color = "yellow"
        else:
            # Has structurally invalid policies (AWS would reject)
            status = Text("❌ VALIDATION FAILED", style="bold red")
            message = Text(
                f"{policies_with_errors} of {report.total_policies} policies are AWS-invalid "
                f"(structural errors AWS would reject) and must be fixed.",
                style="red",
            )
            border_color = "red"

        # Combine status and message
        final_text = Text()
        final_text.append(status)
        final_text.append("\n")  # Reduced from \n\n to single newline
        final_text.append(message)

        console.print(
            Panel(
                final_text,
                border_style=border_color,
                padding=(1, 2),
                width=constants.CONSOLE_PANEL_WIDTH,
            )
        )

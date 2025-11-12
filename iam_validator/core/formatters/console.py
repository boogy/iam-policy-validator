"""Console formatter - Classic console output using report.py."""

from io import StringIO

from rich.console import Console

from iam_validator.core.formatters.base import OutputFormatter
from iam_validator.core.models import ValidationReport


class ConsoleFormatter(OutputFormatter):
    """Classic console formatter - uses the standard report.py print_console_report output."""

    @property
    def format_id(self) -> str:
        return "console"

    @property
    def description(self) -> str:
        return "Classic console output with colors and tables"

    def format(self, report: ValidationReport, **kwargs) -> str:
        """Format validation report using the classic console output from report.py.

        This delegates to the ReportGenerator.print_console_report method,
        capturing its output to return as a string.

        Args:
            report: Validation report to format
            **kwargs: Additional options (color: bool = True)

        Returns:
            Formatted string with classic console output
        """
        # Import here to avoid circular dependency
        from iam_validator.core.report import ReportGenerator

        # Allow disabling color for plain text output
        color = kwargs.get("color", True)

        # Capture the output from print_console_report
        from iam_validator.utils import get_terminal_width

        string_buffer = StringIO()
        # Get terminal width for proper table column spacing
        terminal_width = get_terminal_width()
        console = Console(
            file=string_buffer,
            force_terminal=color,
            width=terminal_width,
            legacy_windows=False,
        )

        # Create a generator instance with our custom console
        generator = ReportGenerator()

        # Replace the console temporarily to capture output
        original_console = generator.console
        generator.console = console

        # Call the actual print_console_report method
        generator.print_console_report(report)

        # Restore original console
        generator.console = original_console

        # Return captured output
        return string_buffer.getvalue()

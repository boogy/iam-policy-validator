"""Console formatter - placeholder for existing functionality."""

from iam_validator.core.formatters.base import OutputFormatter
from iam_validator.core.models import ValidationReport


class ConsoleFormatter(OutputFormatter):
    """Console formatter using Rich library."""

    @property
    def format_id(self) -> str:
        return "console"

    @property
    def description(self) -> str:
        return "Rich console output with colors and tables"

    def format(self, report: ValidationReport, **kwargs) -> str:
        """Format for console output."""
        # This would integrate with existing Rich console output
        # from iam_validator.core.report module
        return "Console output (uses Rich library for terminal display)"

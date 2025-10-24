"""JSON formatter - placeholder for existing functionality."""

import json

from iam_validator.core.formatters.base import OutputFormatter
from iam_validator.core.models import ValidationReport


class JSONFormatter(OutputFormatter):
    """JSON formatter for programmatic processing."""

    @property
    def format_id(self) -> str:
        return "json"

    @property
    def description(self) -> str:
        return "JSON format for programmatic processing"

    @property
    def file_extension(self) -> str:
        return "json"

    @property
    def content_type(self) -> str:
        return "application/json"

    def format(self, report: ValidationReport, **kwargs) -> str:
        """Format as JSON."""
        # This would integrate with existing JSON output
        # from iam_validator.core.report module
        indent = kwargs.get("indent", 2)
        return json.dumps(report.model_dump(), indent=indent, default=str)

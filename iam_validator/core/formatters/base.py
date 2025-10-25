"""Base formatter and registry for output formatters."""

import logging
from abc import ABC, abstractmethod
from typing import Any

from iam_validator.core.models import ValidationReport

logger = logging.getLogger(__name__)


class OutputFormatter(ABC):
    """Base class for all output formatters."""

    @property
    @abstractmethod
    def format_id(self) -> str:
        """Unique identifier for this formatter (e.g., 'json', 'markdown')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of the formatter."""
        pass

    @property
    def file_extension(self) -> str:
        """Default file extension for this format."""
        return "txt"

    @property
    def content_type(self) -> str:
        """MIME content type for this format."""
        return "text/plain"

    @abstractmethod
    def format(self, report: ValidationReport, **kwargs: Any) -> str:
        """Format the validation report.

        Args:
            report: The validation report to format
            **kwargs: Additional formatter-specific options

        Returns:
            Formatted string representation of the report
        """
        pass

    def format_to_file(self, report: ValidationReport, filepath: str, **kwargs: Any) -> None:
        """Format report and write to file.

        Args:
            report: The validation report to format
            filepath: Path to output file
            **kwargs: Additional formatter-specific options
        """
        output = self.format(report, **kwargs)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(output)
        logger.info(f"Report written to {filepath} using {self.format_id} formatter")


class FormatterRegistry:
    """Registry for managing output formatters."""

    def __init__(self) -> None:
        """Initialize the formatter registry."""
        self._formatters: dict[str, OutputFormatter] = {}

    def register(self, formatter: OutputFormatter) -> None:
        """Register a new formatter.

        Args:
            formatter: OutputFormatter instance to register
        """
        self._formatters[formatter.format_id] = formatter
        logger.debug(f"Registered formatter: {formatter.format_id}")

    def unregister(self, format_id: str) -> None:
        """Unregister a formatter.

        Args:
            format_id: ID of the formatter to unregister
        """
        if format_id in self._formatters:
            del self._formatters[format_id]
            logger.debug(f"Unregistered formatter: {format_id}")

    def get_formatter(self, format_id: str) -> OutputFormatter | None:
        """Get a formatter by ID.

        Args:
            format_id: ID of the formatter to retrieve

        Returns:
            OutputFormatter instance or None if not found
        """
        return self._formatters.get(format_id)

    def list_formatters(self) -> dict[str, str]:
        """List all registered formatters.

        Returns:
            Dictionary of format_id -> description
        """
        return {fmt_id: formatter.description for fmt_id, formatter in self._formatters.items()}

    def format_report(self, report: ValidationReport, format_id: str, **kwargs: Any) -> str:
        """Format a report using the specified formatter.

        Args:
            report: The validation report to format
            format_id: ID of the formatter to use
            **kwargs: Additional formatter-specific options

        Returns:
            Formatted string representation

        Raises:
            ValueError: If formatter not found
        """
        formatter = self.get_formatter(format_id)
        if not formatter:
            available = ", ".join(self._formatters.keys())
            raise ValueError(f"Formatter '{format_id}' not found. Available: {available}")

        return formatter.format(report, **kwargs)


# Global formatter registry
_global_registry = FormatterRegistry()


def get_global_registry() -> FormatterRegistry:
    """Get the global formatter registry."""
    return _global_registry


def register_formatter(formatter: OutputFormatter) -> None:
    """Register a formatter in the global registry."""
    _global_registry.register(formatter)


def get_formatter(format_id: str) -> OutputFormatter | None:
    """Get a formatter from the global registry."""
    return _global_registry.get_formatter(format_id)

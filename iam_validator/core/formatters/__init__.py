"""Output formatters for IAM Policy Validator."""

from iam_validator.core.formatters.base import (
    FormatterRegistry,
    OutputFormatter,
    get_global_registry,
)
from iam_validator.core.formatters.console import ConsoleFormatter
from iam_validator.core.formatters.csv import CSVFormatter
from iam_validator.core.formatters.enhanced import EnhancedFormatter
from iam_validator.core.formatters.html import HTMLFormatter
from iam_validator.core.formatters.json import JSONFormatter
from iam_validator.core.formatters.markdown import MarkdownFormatter
from iam_validator.core.formatters.sarif import SARIFFormatter

__all__ = [
    "OutputFormatter",
    "FormatterRegistry",
    "get_global_registry",
    "ConsoleFormatter",
    "EnhancedFormatter",
    "JSONFormatter",
    "MarkdownFormatter",
    "SARIFFormatter",
    "CSVFormatter",
    "HTMLFormatter",
]

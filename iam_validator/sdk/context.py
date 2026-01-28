"""
Context managers for common validation workflows.

This module provides context managers that handle resource lifecycle
and make the validation API more convenient to use.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.models import PolicyValidationResult
from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.report import ReportGenerator


class ValidationContext:
    """
    Validation context that provides convenience methods with shared resources.

    This class maintains a shared AWSServiceFetcher and configuration
    across multiple validation operations, improving performance.
    """

    def __init__(
        self,
        fetcher: AWSServiceFetcher,
        config_path: str | None = None,
    ):
        """
        Initialize validation context.

        Args:
            fetcher: AWS service fetcher instance
            config_path: Optional path to configuration file
        """
        self.fetcher = fetcher
        self.config_path = config_path
        self.loader = PolicyLoader()

    async def validate_file(self, file_path: str | Path) -> PolicyValidationResult:
        """
        Validate a single IAM policy file.

        Args:
            file_path: Path to the policy file

        Returns:
            PolicyValidationResult for the policy
        """
        policies = self.loader.load_from_path(str(file_path))

        if not policies:
            raise ValueError(f"No IAM policies found in {file_path}")

        results = await validate_policies(
            policies,
            config_path=self.config_path,
        )

        return (
            results[0]
            if results
            else PolicyValidationResult(
                policy_file=str(file_path),
                is_valid=False,
                issues=[],
            )
        )

    async def validate_directory(self, dir_path: str | Path) -> list[PolicyValidationResult]:
        """
        Validate all IAM policies in a directory.

        Args:
            dir_path: Path to directory containing policy files

        Returns:
            List of PolicyValidationResults for all policies found
        """
        policies = self.loader.load_from_path(str(dir_path))

        if not policies:
            raise ValueError(f"No IAM policies found in {dir_path}")

        return await validate_policies(
            policies,
            config_path=self.config_path,
        )

    async def validate_json(
        self, policy_json: dict, policy_name: str = "inline-policy"
    ) -> PolicyValidationResult:
        """
        Validate an IAM policy from a Python dictionary.

        Args:
            policy_json: IAM policy as a Python dict
            policy_name: Name to identify this policy in results

        Returns:
            PolicyValidationResult for the policy
        """
        from iam_validator.core.models import IAMPolicy

        # Parse the dict into an IAMPolicy
        policy = IAMPolicy(**policy_json)

        results = await validate_policies(
            [(policy_name, policy)],
            config_path=self.config_path,
        )

        return (
            results[0]
            if results
            else PolicyValidationResult(
                policy_file=policy_name,
                is_valid=False,
                issues=[],
            )
        )

    def generate_report(
        self, results: list[PolicyValidationResult], format: str = "console"
    ) -> str:
        """
        Generate a report from validation results.

        Args:
            results: List of validation results
            format: Output format (console, json, html, csv, markdown, sarif)

        Returns:
            Formatted report as string
        """
        generator = ReportGenerator()
        report = generator.generate_report(results)

        if format == "console":
            # Return empty string for console (it prints directly)
            generator.print_console_report(report)
            return ""
        elif format == "json":
            from iam_validator.core.formatters.json import JSONFormatter

            return JSONFormatter().format(report)
        elif format == "html":
            from iam_validator.core.formatters.html import HTMLFormatter

            return HTMLFormatter().format(report)
        elif format == "csv":
            from iam_validator.core.formatters.csv import CSVFormatter

            return CSVFormatter().format(report)
        elif format == "markdown":
            from iam_validator.core.formatters.markdown import MarkdownFormatter

            return MarkdownFormatter().format(report)
        elif format == "sarif":
            from iam_validator.core.formatters.sarif import SARIFFormatter

            return SARIFFormatter().format(report)
        else:
            raise ValueError(f"Unknown format: {format}")


@asynccontextmanager
async def validator(
    config_path: str | None = None,
) -> AsyncIterator[ValidationContext]:
    """
    Context manager that handles AWS fetcher lifecycle.

    This context manager creates an AWS service fetcher, provides a validation
    context for performing multiple validations efficiently, and ensures proper
    cleanup when done.

    Args:
        config_path: Optional path to configuration file

    Yields:
        ValidationContext for performing validations

    Example:
        >>> async with validator() as v:
        ...     result = await v.validate_file("policy.json")
        ...     report = v.generate_report([result], format="json")
        ...
        ...     # Can do multiple validations with same context
        ...     result2 = await v.validate_directory("./policies")

    Example with configuration:
        >>> async with validator(config_path="./iam-validator.yaml") as v:
        ...     results = await v.validate_directory("./policies")
        ...     v.generate_report(results, format="console")
    """
    async with AWSServiceFetcher() as fetcher:
        yield ValidationContext(fetcher, config_path)


@asynccontextmanager
async def validator_from_config(config_path: str) -> AsyncIterator[ValidationContext]:
    """
    Context manager that loads configuration and creates a validator.

    Convenience wrapper around validator() that loads config from a file.

    Args:
        config_path: Path to configuration file

    Yields:
        ValidationContext configured from the config file

    Example:
        >>> async with validator_from_config("./iam-validator.yaml") as v:
        ...     results = await v.validate_directory("./policies")
        ...     v.generate_report(results)
    """
    async with AWSServiceFetcher() as fetcher:
        yield ValidationContext(fetcher, config_path=config_path)

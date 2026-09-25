"""
Context managers for common validation workflows.

This module provides context managers that handle resource lifecycle
and make the validation API more convenient to use.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckRegistry
from iam_validator.core.config.config_loader import ConfigLoader, ValidatorConfig
from iam_validator.core.models import PolicyType, PolicyValidationResult
from iam_validator.core.policy_checks import build_registry, fetcher_kwargs, validate_policies
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.report import ReportGenerator
from iam_validator.sdk.shortcuts import _policy_from_json


class ValidationContext:
    """
    Validation context that provides convenience methods with shared resources.

    The configuration is loaded once, the check registry (built-in checks plus any
    custom checks) is built once on first use, and every validation reuses the
    context's AWSServiceFetcher — so repeated calls cost only the validation itself
    and produce exactly what ``iam-validator validate`` would for the same inputs.
    """

    def __init__(
        self,
        fetcher: AWSServiceFetcher,
        config_path: str | None = None,
        *,
        config: ValidatorConfig | None = None,
        custom_checks_dir: str | None = None,
        allow_config_custom_checks: bool = False,
    ):
        """
        Initialize validation context.

        Args:
            fetcher: AWS service fetcher instance, reused for every validation
            config_path: Optional path to configuration file (auto-discovered when
                omitted, as the CLI does)
            config: Already-loaded configuration; ``config_path`` is ignored when given
            custom_checks_dir: Directory of custom checks to load (``--custom-checks-dir``)
            allow_config_custom_checks: Honour a ``custom_checks_dir`` set only in the
                config file (``--allow-config-custom-checks``)
        """
        self.fetcher = fetcher
        self.config_path = config_path
        self._config = config
        self._custom_checks_dir = custom_checks_dir
        self._allow_config_custom_checks = allow_config_custom_checks
        self._registry: CheckRegistry | None = None

    @property
    def config(self) -> ValidatorConfig:
        """The configuration every validation in this context uses (loaded once)."""
        if self._config is None:
            self._config = ConfigLoader.load_config(explicit_path=self.config_path, allow_missing=True)
        return self._config

    @property
    def registry(self) -> CheckRegistry:
        """The configured check registry (built once, on first use)."""
        if self._registry is None:
            self._registry = build_registry(
                self.config,
                custom_checks_dir=self._custom_checks_dir,
                allow_config_custom_checks=self._allow_config_custom_checks,
            )
        return self._registry

    async def _validate(self, policies: list, policy_type: PolicyType | None) -> list[PolicyValidationResult]:
        if not policies:
            return []
        return await validate_policies(
            policies,
            config_path=self.config_path,
            policy_type=policy_type,
            config=self.config,
            registry=self.registry,
            fetcher=self.fetcher,
        )

    async def validate_file(
        self, file_path: str | Path, policy_type: PolicyType | None = None
    ) -> PolicyValidationResult:
        """
        Validate a single IAM policy file.

        Args:
            file_path: Path to the policy file
            policy_type: Explicit policy type; ``None`` resolves it per file

        Returns:
            PolicyValidationResult for the policy. A file that cannot be parsed
            yields ``is_valid=False`` with a ``policy_parse_error`` finding.
        """
        loader = PolicyLoader()
        policies = loader.load_from_path(str(file_path))

        if not policies and not loader.parsing_errors:
            raise ValueError(f"No IAM policies found in {file_path}")

        results = [*await self._validate(policies, policy_type), *loader.parsing_error_results()]

        return (
            results[0]
            if results
            else PolicyValidationResult(
                policy_file=str(file_path),
                is_valid=False,
                issues=[],
            )
        )

    async def validate_directory(
        self,
        dir_path: str | Path,
        recursive: bool = True,
        policy_type: PolicyType | None = None,
    ) -> list[PolicyValidationResult]:
        """
        Validate all IAM policies in a directory.

        Args:
            dir_path: Path to directory containing policy files
            recursive: Whether to search subdirectories (default: True)
            policy_type: Explicit policy type for every policy; ``None`` resolves per file

        Returns:
            List of PolicyValidationResults for all policies found, including one
            failed result (``policy_parse_error``) per file that could not be parsed
        """
        loader = PolicyLoader()
        policies = loader.load_from_path(str(dir_path), recursive=recursive)

        if not policies and not loader.parsing_errors:
            raise ValueError(f"No IAM policies found in {dir_path}")

        return [*await self._validate(policies, policy_type), *loader.parsing_error_results()]

    async def validate_json(
        self,
        policy_json: dict | str,
        policy_name: str = "inline-policy",
        policy_type: PolicyType | None = None,
    ) -> PolicyValidationResult:
        """
        Validate an IAM policy from a Python dictionary or JSON string.

        Args:
            policy_json: IAM policy as a Python dict or JSON string
            policy_name: Name to identify this policy in results
            policy_type: Explicit policy type; ``None`` auto-detects

        Returns:
            PolicyValidationResult for the policy
        """
        policy, raw = _policy_from_json(policy_json)
        results = await self._validate([(policy_name, policy, raw)], policy_type)

        return (
            results[0]
            if results
            else PolicyValidationResult(
                policy_file=policy_name,
                is_valid=False,
                issues=[],
            )
        )

    def generate_report(self, results: list[PolicyValidationResult], format: str = "console") -> str:
        """
        Generate a report from validation results.

        Each format renders exactly as ``iam-validator validate --format <format>``.

        Args:
            results: List of validation results
            format: Output format (console, enhanced, json, html, csv, markdown, sarif)

        Returns:
            Formatted report as string (empty for ``console``, which prints directly)
        """
        generator = ReportGenerator()
        report = generator.generate_report(results)

        if format == "console":
            generator.print_console_report(report)
            return ""
        if format == "json":
            return generator.generate_json_report(report)
        if format == "markdown":
            return generator.generate_github_comment(report)
        if generator.formatter_registry.get_formatter(format) is None:
            raise ValueError(f"Unknown format: {format}")
        return generator.format_report(report, format)


@asynccontextmanager
async def validator(
    config_path: str | None = None,
    *,
    config: ValidatorConfig | None = None,
    aws_services_dir: str | None = None,
    custom_checks_dir: str | None = None,
    allow_config_custom_checks: bool = False,
) -> AsyncIterator[ValidationContext]:
    """
    Context manager that handles AWS fetcher lifecycle.

    This context manager creates an AWS service fetcher (honouring the config's
    cache settings and ``aws_services_dir``, as the CLI does), provides a
    validation context for performing multiple validations efficiently, and
    ensures proper cleanup when done.

    Args:
        config_path: Optional path to configuration file
        config: Already-loaded configuration; ``config_path`` is ignored when given
        aws_services_dir: Pre-downloaded AWS service definitions (offline mode)
        custom_checks_dir: Directory of custom checks to load
        allow_config_custom_checks: Honour a ``custom_checks_dir`` set only in the config file

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
    if config is None:
        config = ConfigLoader.load_config(explicit_path=config_path, allow_missing=True)

    async with AWSServiceFetcher(**fetcher_kwargs(config, aws_services_dir)) as fetcher:
        yield ValidationContext(
            fetcher,
            config_path,
            config=config,
            custom_checks_dir=custom_checks_dir,
            allow_config_custom_checks=allow_config_custom_checks,
        )


@asynccontextmanager
async def validator_from_config(
    config: str | Path | ValidatorConfig,
    *,
    aws_services_dir: str | None = None,
    custom_checks_dir: str | None = None,
    allow_config_custom_checks: bool = False,
) -> AsyncIterator[ValidationContext]:
    """
    Context manager that creates a validator from a configuration.

    Convenience wrapper around validator() that takes either a config file path
    or an already-loaded ``ValidatorConfig``.

    Args:
        config: Path to configuration file, or a loaded ``ValidatorConfig``
        aws_services_dir: Pre-downloaded AWS service definitions (offline mode)
        custom_checks_dir: Directory of custom checks to load
        allow_config_custom_checks: Honour a ``custom_checks_dir`` set only in the config file

    Yields:
        ValidationContext configured from the config

    Example:
        >>> async with validator_from_config("./iam-validator.yaml") as v:
        ...     results = await v.validate_directory("./policies")
        ...     v.generate_report(results)
    """
    loaded = config if isinstance(config, ValidatorConfig) else None
    async with validator(
        config_path=None if loaded is not None else str(config),
        config=loaded,
        aws_services_dir=aws_services_dir,
        custom_checks_dir=custom_checks_dir,
        allow_config_custom_checks=allow_config_custom_checks,
    ) as ctx:
        yield ctx

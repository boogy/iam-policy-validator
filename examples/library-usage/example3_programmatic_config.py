#!/usr/bin/env python3
"""Example 3: Validate with programmatically created configuration."""
import asyncio

from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.policy_checks import validate_policies, _validate_policy_with_registry
from iam_validator.core.config_loader import ValidatorConfig, ConfigLoader
from iam_validator.core.check_registry import create_default_registry
from iam_validator.core.aws_fetcher import AWSServiceFetcher


async def validate_programmatic():
    """Validate with programmatically created configuration."""

    # Create configuration dictionary
    config_dict = {
        "settings": {
            "fail_on_severity": ["error"],
            "cache_enabled": True,
            "cache_ttl_hours": 24,
            "parallel_execution": True,
        },
        "security_best_practices_check": {
            "enabled": True,
            "severity": "high",
        },
        "action_validation_check": {
            "enabled": True,
            "severity": "error",
        },
    }

    # Create config object
    config = ValidatorConfig(config_dict, use_defaults=True)

    # Create registry and apply config
    registry = create_default_registry(
        enable_parallel=True, include_builtin_checks=True
    )
    ConfigLoader.apply_config_to_registry(config, registry)

    # Load policies
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")

    # Get settings from config
    cache_enabled = config.get_setting("cache_enabled", True)
    cache_ttl_hours = config.get_setting("cache_ttl_hours", 168)
    fail_on_severities = config.get_setting("fail_on_severity", ["error"])

    # Validate with AWS Service Fetcher
    async with AWSServiceFetcher(
        enable_cache=cache_enabled,
        cache_ttl=cache_ttl_hours * 3600,
    ) as fetcher:
        results = []
        for file_path, policy in policies:
            result = await _validate_policy_with_registry(
                policy, file_path, registry, fetcher, fail_on_severities
            )
            results.append(result)

    return results


if __name__ == "__main__":
    results = asyncio.run(validate_programmatic())
    print(f"Validated {len(results)} policies")

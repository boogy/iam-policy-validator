#!/usr/bin/env python3
"""Example 2: Validate using an explicit configuration file."""
import asyncio

from iam_validator.core.config_loader import ConfigLoader
from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader


async def validate_with_config():
    """Validate using an explicit configuration file."""

    # Load configuration from file
    ConfigLoader.load_config(
        explicit_path="./iam-validator.yaml",
        allow_missing=False  # Fail if config not found
    )

    # Load policies
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")

    # Validate with config
    results = await validate_policies(
        policies,
        config_path="./iam-validator.yaml",
        use_registry=True  # Use new check registry system
    )

    return results


if __name__ == "__main__":
    results = asyncio.run(validate_with_config())
    print(f"Validated {len(results)} policies")

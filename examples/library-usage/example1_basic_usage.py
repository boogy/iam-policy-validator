#!/usr/bin/env python3
"""Example 1: Basic validation with default configuration."""

import asyncio

from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.report import ReportGenerator


async def validate_basic():
    """Basic validation with default configuration."""

    # Load policies from a directory or file
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/my-policy.json")
    # Or: policies = loader.load_from_path("./policies/")  # for directory

    # Validate policies (uses default config)
    results = await validate_policies(policies)

    # Generate and print report
    generator = ReportGenerator()
    report = generator.generate_report(results)
    generator.print_console_report(report)

    # Check if validation passed
    all_valid = all(r.is_valid for r in results)
    return 0 if all_valid else 1


if __name__ == "__main__":
    # Run it
    exit_code = asyncio.run(validate_basic())
    print(f"Exit code: {exit_code}")

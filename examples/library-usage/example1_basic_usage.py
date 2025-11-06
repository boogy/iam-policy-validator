#!/usr/bin/env python3
"""
Example 1: Basic validation with default configuration.

This is the simplest way to validate IAM policies. It:
- Loads policies from a file or directory
- Uses default built-in checks (all enabled)
- Generates and prints a formatted console report
- Returns appropriate exit code

Use this for: Quick validation, CI/CD pipelines, testing
"""

import asyncio

from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.report import ReportGenerator


async def validate_basic():
    """Basic validation with default configuration."""
    print("=" * 70)
    print("Example 1: Basic Validation")
    print("=" * 70)

    # Load policies from a directory or file
    loader = PolicyLoader()

    # Load from a single file
    policies = loader.load_from_path("./policies/my-policy.json")

    # Or load from a directory (uncomment to use)
    # policies = loader.load_from_path("./policies/")

    print(f"\n✓ Loaded {len(policies)} policy/policies")

    # Validate policies (uses default configuration with all built-in checks)
    print("\n⏳ Validating policies with default checks...")
    results = await validate_policies(policies)

    # Generate and print report
    generator = ReportGenerator()
    report = generator.generate_report(results)
    generator.print_console_report(report)

    # Check if validation passed
    all_valid = all(r.is_valid for r in results)

    # Print summary
    print("\n" + "=" * 70)
    if all_valid:
        print("✅ All policies are valid!")
    else:
        invalid_count = sum(1 for r in results if not r.is_valid)
        print(f"❌ {invalid_count} of {len(results)} policies have issues")
    print("=" * 70)

    return 0 if all_valid else 1


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║                  IAM Policy Validator - Example 1                   ║
║                   Basic Validation with Defaults                    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    # Run validation
    exit_code = asyncio.run(validate_basic())

    print(f"\n📝 Exit code: {exit_code}")
    print("\n💡 Tip: Use config_path parameter to customize validation behavior")
    print("   See example2_config_file.py for details")

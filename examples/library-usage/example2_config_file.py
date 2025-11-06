#!/usr/bin/env python3
"""
Example 2: Validate using an explicit configuration file.

This example shows how to:
- Use a YAML configuration file to control validation
- Enable/disable specific checks
- Configure check severities
- Set fail_on_severity thresholds
- Use the check registry system

Use this for: Production validation, team standards, custom rules
"""

import asyncio

from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.report import ReportGenerator


async def validate_with_config():
    """Validate using an explicit configuration file."""
    print("=" * 70)
    print("Example 2: Validation with Configuration File")
    print("=" * 70)

    # Load policies
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")
    print(f"\n✓ Loaded {len(policies)} policy/policies")

    # Validate with config file
    # The config_path parameter loads configuration from a YAML file
    # use_registry=True enables the modular check registry system
    print("\n⏳ Validating with configuration from 'iam-validator.yaml'...")

    results = await validate_policies(
        policies,
        config_path="./iam-validator.yaml",
        use_registry=True,  # Enable check registry system
    )

    # Generate report
    generator = ReportGenerator()
    report = generator.generate_report(results)
    generator.print_console_report(report)

    # Print detailed statistics
    stats = report.get_statistics()
    print("\n" + "=" * 70)
    print("Validation Statistics:")
    print("=" * 70)
    print(f"  Total Policies: {stats.get('total_policies', 0)}")
    print(f"  Valid: {stats.get('valid_policies', 0)}")
    print(f"  Invalid: {stats.get('invalid_policies', 0)}")
    print(f"  Total Issues: {stats.get('total_issues', 0)}")

    if "issues_by_severity" in stats:
        print("\n  Issues by Severity:")
        for severity, count in stats["issues_by_severity"].items():
            print(f"    {severity}: {count}")

    print("=" * 70)

    return results


async def validate_with_auto_discovery():
    """Example of config auto-discovery."""
    print("\n" + "=" * 70)
    print("Bonus: Configuration Auto-Discovery")
    print("=" * 70)

    # If you don't specify config_path, the validator searches for config files:
    # 1. ./iam-validator.yaml (current directory)
    # 2. ../.iam-validator.yaml (parent directories)
    # 3. ~/.iam-validator.yaml (home directory)

    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")

    print("\n⏳ Auto-discovering configuration file...")
    results = await validate_policies(policies, use_registry=True)

    print(f"✓ Validated {len(results)} policies with auto-discovered config")

    return results


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║                  IAM Policy Validator - Example 2                   ║
║               Validation with Configuration File                    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    # Run validation with explicit config
    results = asyncio.run(validate_with_config())

    # Optionally show auto-discovery
    # asyncio.run(validate_with_auto_discovery())

    print("\n💡 Configuration File Tips:")
    print("   • Use settings.fail_on_severity to control exit codes")
    print("   • Enable/disable checks with <check_name>.enabled")
    print("   • Override severities with <check_name>.severity")
    print("   • See examples/configs/ for sample configurations")

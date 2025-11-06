#!/usr/bin/env python3
"""
Example 3: Validate with programmatically created configuration.

This example shows how to:
- Create configuration programmatically (no YAML file needed)
- Use the public validate_policies API
- Configure settings dynamically at runtime
- Control caching and parallel execution
- Integrate with existing Python applications

Use this for: Dynamic configurations, programmatic control, embedded validation
"""

import asyncio
import tempfile

import yaml

from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.report import ReportGenerator


async def validate_programmatic():
    """Validate with programmatically created configuration."""
    print("=" * 70)
    print("Example 3: Programmatic Configuration")
    print("=" * 70)

    # Create configuration dictionary dynamically
    # This could be built from environment variables, database, etc.
    config_dict = {
        "settings": {
            "fail_on_severity": ["error", "critical"],
            "cache_enabled": True,
            "cache_ttl_hours": 24,  # 1 day cache
            "parallel_execution": True,
        },
        # Enable specific checks with custom settings
        "wildcard_action": {
            "enabled": True,
            "severity": "high",
        },
        "action_validation": {
            "enabled": True,
            "severity": "error",
        },
        "principal_validation": {
            "enabled": True,
            "severity": "critical",
        },
    }

    print("\n✓ Created configuration programmatically")
    print("  • Enabled checks: wildcard_action, action_validation, principal_validation")
    print(f"  • Cache TTL: {config_dict['settings']['cache_ttl_hours']} hours")
    print(f"  • Parallel execution: {config_dict['settings']['parallel_execution']}")

    # Save config to temporary file
    # The public API requires a config file path
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(config_dict, f)
        config_path = f.name

    print(f"\n✓ Config saved to: {config_path}")

    # Load policies
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")
    print(f"✓ Loaded {len(policies)} policy/policies")

    # Validate using public API
    print("\n⏳ Validating policies...")
    results = await validate_policies(policies, config_path=config_path, use_registry=True)

    # Generate report
    generator = ReportGenerator()
    report = generator.generate_report(results)
    generator.print_console_report(report)

    # Print statistics
    all_valid = all(r.is_valid for r in results)
    print("\n" + "=" * 70)
    if all_valid:
        print("✅ All policies passed validation!")
    else:
        invalid_count = sum(1 for r in results if not r.is_valid)
        print(f"❌ {invalid_count} of {len(results)} policies have issues")
    print("=" * 70)

    return results


async def validate_with_minimal_checks():
    """Example: Validate with only specific checks enabled."""
    print("\n" + "=" * 70)
    print("Bonus: Minimal Configuration - Only Specific Checks")
    print("=" * 70)

    # Create minimal config with only specific checks enabled
    minimal_config = {
        "settings": {
            "enable_builtin_checks": True,  # Enable built-in checks
        },
        # Enable only these specific checks
        "wildcard_action": {
            "enabled": True,
            "severity": "critical",
        },
        "principal_validation": {
            "enabled": True,
            "severity": "high",
        },
        # All other checks will use defaults or can be explicitly disabled
    }

    # Save to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(minimal_config, f)
        config_path = f.name

    print("\n✓ Minimal config with selected checks only")
    print("  • wildcard_action (critical)")
    print("  • principal_validation (high)")

    # Load and validate
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")

    results = await validate_policies(policies, config_path=config_path, use_registry=True)

    print(f"\n✓ Validated {len(results)} policies with minimal config")
    return results


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║                  IAM Policy Validator - Example 3                   ║
║                   Programmatic Configuration                        ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    # Run programmatic validation
    results = asyncio.run(validate_programmatic())

    # Optionally show minimal config example
    # asyncio.run(validate_with_minimal_checks())

    print("\n💡 Programmatic Configuration Tips:")
    print("   • Build config from environment variables or secrets")
    print("   • Change configuration based on runtime conditions")
    print("   • Enable only specific checks for targeted validation")
    print("   • Perfect for embedding in existing applications")
    print("   • Always use public validate_policies() API")

#!/usr/bin/env python3
"""
Example 2: Using context managers for efficient validation.

This demonstrates how to use the validator context manager for performing
multiple validations with shared resources (better performance).
"""

import asyncio

from iam_validator.sdk import validator


async def validate_with_context():
    """Validate multiple policies using context manager."""
    print("=" * 70)
    print("Example 2: Context Manager for Efficient Validation")
    print("=" * 70)

    # Use context manager - automatically handles AWS fetcher lifecycle
    async with validator() as v:
        print("\n✓ Validation context created (AWS fetcher initialized)")

        # Validate multiple files efficiently (shared fetcher)
        print("\n📋 Validating multiple policies...")
        print("-" * 70)

        # Validate first policy
        result1 = await v.validate_file("./policies/policy1.json")
        print(f"\n1. {result1.policy_file}")
        print(f"   Status: {'✅ Valid' if result1.is_valid else '❌ Invalid'}")
        if not result1.is_valid:
            print(f"   Issues: {len(result1.issues)}")

        # Validate second policy
        result2 = await v.validate_file("./policies/policy2.json")
        print(f"\n2. {result2.policy_file}")
        print(f"   Status: {'✅ Valid' if result2.is_valid else '❌ Invalid'}")
        if not result2.is_valid:
            print(f"   Issues: {len(result2.issues)}")

        # Validate entire directory
        print("\n📁 Validating directory...")
        results = await v.validate_directory("./policies")
        print(f"   Found {len(results)} policies")

        valid_count = sum(1 for r in results if r.is_valid)
        print(f"   Valid: {valid_count}/{len(results)}")

        # Generate reports in different formats
        print("\n📊 Generating reports...")
        print("-" * 70)

        # Console report
        print("\n📺 Console Report:")
        v.generate_report(results, format="console")

        # JSON report
        json_report = v.generate_report(results, format="json")
        with open("validation-report.json", "w") as f:
            f.write(json_report)
        print("\n✓ JSON report saved to: validation-report.json")

        # HTML report
        html_report = v.generate_report(results, format="html")
        with open("validation-report.html", "w") as f:
            f.write(html_report)
        print("✓ HTML report saved to: validation-report.html")

        # Summary
        print("\n" + "=" * 70)
        print(f"✅ Validated {len(results)} policies")
        print(f"✅ {valid_count} valid, {len(results) - valid_count} with issues")
        print("=" * 70)

    # Context manager automatically closes AWS fetcher here
    print("\n✓ Validation context closed (resources cleaned up)")

    return 0 if all(r.is_valid for r in results) else 1


async def validate_with_config():
    """Validate policies with configuration."""
    print("\n\n" + "=" * 70)
    print("Example 2b: Context Manager with Configuration")
    print("=" * 70)

    # Use configuration file
    async with validator(config_path="./iam-validator.yaml") as v:
        print("\n✓ Loaded configuration from: ./iam-validator.yaml")

        results = await v.validate_directory("./policies")

        print(f"\n✓ Validated {len(results)} policies with custom configuration")
        valid_count = sum(1 for r in results if r.is_valid)
        print(f"✓ {valid_count} valid, {len(results) - valid_count} with issues")

        v.generate_report(results, format="console")

    return 0 if all(r.is_valid for r in results) else 1


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║              IAM Policy Validator - Example 2 (New SDK)              ║
║                Context Managers for Efficient Validation             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    # Run validation examples
    asyncio.run(validate_with_context())

    print("\n\n" + "🔄" * 35)

    # Run validation with config
    asyncio.run(validate_with_config())

    print("\n💡 Benefits of context managers:")
    print("   • Automatic resource cleanup (AWS fetcher)")
    print("   • Efficient reuse of fetcher across multiple validations")
    print("   • Clean, readable code with 'async with' syntax")
    print("   • Better performance for batch operations")

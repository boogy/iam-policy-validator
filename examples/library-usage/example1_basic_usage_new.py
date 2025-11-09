#!/usr/bin/env python3
"""
Example 1: Basic validation with the new SDK.

This demonstrates the simplest way to validate IAM policies using the new
iam_validator.sdk module with high-level convenience functions.
"""

import asyncio

from iam_validator.sdk import quick_validate, validate_file


async def validate_basic():
    """Basic validation using the new SDK shortcuts."""
    print("=" * 70)
    print("Example 1: Basic Validation (New SDK)")
    print("=" * 70)

    # Method 1: Quick validation (just returns True/False)
    print("\n📋 Method 1: Quick Validate")
    print("-" * 70)

    is_valid = await quick_validate("./policies/my-policy.json")

    if is_valid:
        print("✅ Policy is valid!")
    else:
        print("❌ Policy has issues")

    # Method 2: Full validation with detailed results
    print("\n📋 Method 2: Detailed Validation")
    print("-" * 70)

    result = await validate_file("./policies/my-policy.json")

    print(f"\n✓ Loaded policy: {result.policy_file}")
    print(f"✓ Valid: {result.is_valid}")

    if not result.is_valid:
        print(f"\n❌ Found {len(result.issues)} issues:")
        for issue in result.issues:
            print(f"  - [{issue.severity.upper()}] {issue.message}")
            if issue.suggestion:
                print(f"    💡 Suggestion: {issue.suggestion}")

    # Print summary
    print("\n" + "=" * 70)
    if result.is_valid:
        print("✅ Policy validation passed!")
    else:
        print(f"❌ Policy validation failed with {len(result.issues)} issues")
    print("=" * 70)

    return 0 if result.is_valid else 1


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║              IAM Policy Validator - Example 1 (New SDK)              ║
║                   Basic Validation with Shortcuts                    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    # Run validation
    exit_code = asyncio.run(validate_basic())

    print(f"\n📝 Exit code: {exit_code}")
    print("\n💡 Benefits of new SDK:")
    print("   • Simpler imports: from iam_validator.sdk import ...")
    print("   • Convenience functions: quick_validate, validate_file, etc.")
    print("   • Better discoverability with comprehensive __all__ exports")
    print("\n💡 See example2 for context manager usage")

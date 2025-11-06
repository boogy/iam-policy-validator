#!/usr/bin/env python3
"""
Quick Reference: IAM Policy Validator Library

Copy-paste ready code snippets for common operations.
Each function is self-contained and can be used independently.
"""

import asyncio

from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.report import ReportGenerator

# ============================================================================
# BASIC USAGE
# ============================================================================


async def basic_validation():
    """Simplest validation with defaults."""
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")
    results = await validate_policies(policies)

    generator = ReportGenerator()
    report = generator.generate_report(results)
    generator.print_console_report(report)

    return all(r.is_valid for r in results)


# ============================================================================
# WITH CONFIGURATION
# ============================================================================


async def validation_with_config():
    """Validation with YAML configuration."""
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")

    # Load and apply config from file
    results = await validate_policies(
        policies, config_path="./iam-validator.yaml", use_registry=True
    )

    return results


# ============================================================================
# CUSTOM CHECKS
# ============================================================================


async def validation_with_custom_checks():
    """Validation with custom checks from directory."""
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")

    # Custom checks are loaded via configuration
    # Specify custom_checks_dir in your iam-validator.yaml:
    # settings:
    #   custom_checks_dir: "./custom_checks"

    results = await validate_policies(
        policies,
        config_path="./iam-validator.yaml",
        use_registry=True,
    )

    return results


# ============================================================================
# FILTERING RESULTS
# ============================================================================


async def filter_by_severity():
    """Filter validation results by severity."""
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")
    results = await validate_policies(policies)

    # Group by severity
    by_severity = {"critical": [], "error": [], "warning": [], "info": []}

    for result in results:
        for issue in result.issues:
            severity = issue.severity.lower()
            if severity in by_severity:
                by_severity[severity].append(
                    {
                        "file": result.policy_file,
                        "message": issue.message,
                        "line": issue.line_number,
                    }
                )

    # Print critical issues only
    for item in by_severity["critical"]:
        print(f"CRITICAL: {item['file']}:{item['line']} - {item['message']}")

    return by_severity


# ============================================================================
# MULTIPLE OUTPUT FORMATS
# ============================================================================


async def generate_multiple_formats():
    """Generate reports in multiple formats."""
    from iam_validator.core.formatters.csv import CsvFormatter
    from iam_validator.core.formatters.html import HtmlFormatter
    from iam_validator.core.formatters.json import JsonFormatter

    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")
    results = await validate_policies(policies)

    generator = ReportGenerator()
    report = generator.generate_report(results)

    # JSON
    json_out = JsonFormatter().format(report)
    with open("report.json", "w") as f:
        f.write(json_out)

    # HTML
    html_out = HtmlFormatter().format(report)
    with open("report.html", "w") as f:
        f.write(html_out)

    # CSV
    csv_out = CsvFormatter().format(report)
    with open("report.csv", "w") as f:
        f.write(csv_out)

    return report


# ============================================================================
# BATCH PROCESSING
# ============================================================================


async def batch_validate_directories():
    """Validate multiple directories."""
    directories = ["./iam-policies/", "./s3-policies/", "./lambda-policies/"]
    all_results = []

    loader = PolicyLoader()

    for directory in directories:
        policies = loader.load_from_path(directory)
        results = await validate_policies(policies)
        all_results.extend(results)

        # Progress
        valid = sum(1 for r in results if r.is_valid)
        print(f"{directory}: {valid}/{len(results)} valid")

    return all_results


# ============================================================================
# GET STATISTICS
# ============================================================================


async def get_validation_stats():
    """Get detailed statistics from validation."""
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies/")
    results = await validate_policies(policies)

    generator = ReportGenerator()
    report = generator.generate_report(results)

    # Get stats
    stats = report.get_statistics()

    print(f"Total Policies: {stats.get('total_policies', 0)}")
    print(f"Valid: {stats.get('valid_policies', 0)}")
    print(f"Invalid: {stats.get('invalid_policies', 0)}")
    print(f"Total Issues: {stats.get('total_issues', 0)}")

    # Issues by severity
    if "issues_by_severity" in stats:
        print("\nIssues by Severity:")
        for severity, count in stats["issues_by_severity"].items():
            print(f"  {severity}: {count}")

    return stats


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║            IAM Policy Validator - Quick Reference                   ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    print("\n📖 Quick Reference Guide")
    print("=" * 70)
    print("\nAvailable functions (uncomment to run):")
    print("  • basic_validation() - Simple validation with defaults")
    print("  • validation_with_config() - Use YAML configuration")
    print("  • validation_with_custom_checks() - Include custom checks")
    print("  • filter_by_severity() - Filter results by severity")
    print("  • generate_multiple_formats() - Export as JSON/HTML/CSV")
    print("  • batch_validate_directories() - Validate multiple dirs")
    print("  • get_validation_stats() - Get detailed statistics")

    # Run basic validation example
    print("\n" + "=" * 70)
    print("Running: Basic Validation Example")
    print("=" * 70)
    is_valid = asyncio.run(basic_validation())
    print(f"\n📊 Result: {'✅ All policies valid' if is_valid else '❌ Issues found'}")

    print("\n💡 Tip: Edit this file to run different examples")

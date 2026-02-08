"""
Example: Validate IAM policies and generate reports using the SDK.

This script demonstrates the most common SDK workflows:
- Validating a single policy file
- Validating a JSON dict inline
- Validating an entire directory
- Filtering issues by severity or check ID
- Generating reports in different formats

Usage:
    python -m asyncio examples/sdk/validate_and_report.py
"""

import asyncio

from iam_validator.sdk import (
    count_issues_by_severity,
    filter_issues_by_check_id,
    filter_issues_by_severity,
    get_issues,
    validate_directory,
    validate_file,
    validate_json,
    validator,
)


async def validate_single_file() -> None:
    """Validate a single IAM policy file."""
    print("=== Validate Single File ===")

    result = await validate_file("examples/quick-start/s3-policy.json")

    print(f"File: {result.policy_file}")
    print(f"Valid: {result.is_valid}")
    print(f"Issues: {len(result.issues)}")

    for issue in result.issues:
        print(f"  [{issue.severity}] {issue.message}")

    print()


async def validate_inline_policy() -> None:
    """Validate a policy defined as a Python dict."""
    print("=== Validate Inline Policy ===")

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }

    result = await validate_json(policy)

    print(f"Valid: {result.is_valid}")
    print(f"Issues: {len(result.issues)}")

    for issue in result.issues:
        print(f"  [{issue.severity}] {issue.message}")

    print()


async def validate_with_filtering() -> None:
    """Validate and filter results by severity and check ID."""
    print("=== Validate with Filtering ===")

    result = await validate_file("examples/quick-start/s3-policy.json")

    # Filter to high+ severity only
    high_issues = filter_issues_by_severity(result, min_severity="high")
    print(f"High+ severity issues: {len(high_issues)}")

    # Filter by specific check
    wildcard_issues = filter_issues_by_check_id(result, "wildcard_action")
    print(f"Wildcard action issues: {len(wildcard_issues)}")

    # Get issues across files with severity threshold
    issues = await get_issues("examples/quick-start/", min_severity="medium")
    print(f"Medium+ issues across directory: {len(issues)}")

    # Count by severity
    counts = await count_issues_by_severity("examples/quick-start/")
    for severity, count in sorted(counts.items()):
        print(f"  {severity}: {count}")

    print()


async def validate_with_reports() -> None:
    """Use the validator context manager for multi-file validation with reports."""
    print("=== Validate with Reports ===")

    async with validator() as v:
        # Validate multiple files with shared resources
        result1 = await v.validate_file("examples/quick-start/s3-policy.json")
        result2 = await v.validate_file("examples/quick-start/lambda-policy.json")

        results = [result1, result2]

        # Console report (prints directly)
        v.generate_report(results, format="console")

        # JSON report (returns string)
        json_report = v.generate_report(results, format="json")
        print(f"JSON report length: {len(json_report)} chars")

        # Markdown report (useful for CI/CD)
        md_report = v.generate_report(results, format="markdown")
        print(f"Markdown report length: {len(md_report)} chars")

    print()


async def validate_directory_example() -> None:
    """Validate all policies in a directory."""
    print("=== Validate Directory ===")

    results = await validate_directory("examples/quick-start/", recursive=True)

    valid_count = sum(1 for r in results if r.is_valid)
    total_issues = sum(len(r.issues) for r in results)

    print(f"Policies: {len(results)}")
    print(f"Valid: {valid_count}/{len(results)}")
    print(f"Total issues: {total_issues}")

    print()


async def main() -> None:
    await validate_single_file()
    await validate_inline_policy()
    await validate_with_filtering()
    await validate_with_reports()
    await validate_directory_example()


if __name__ == "__main__":
    asyncio.run(main())

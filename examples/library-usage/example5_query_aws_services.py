#!/usr/bin/env python3
"""Example: Query AWS Service Definitions using SDK.

This example demonstrates how to use the SDK's query utilities to explore
AWS service definitions, including actions, ARN formats, and condition keys.

This functionality is inspired by policy_sentry's query capabilities.
"""

import asyncio

from iam_validator.sdk import (
    AWSServiceFetcher,
    get_actions_by_access_level,
    get_actions_supporting_condition,
    get_wildcard_only_actions,
    query_action_details,
    query_actions,
    query_arn_format,
    query_arn_formats,
    query_arn_types,
    query_condition_key,
    query_condition_keys,
)


async def example_query_actions():
    """Example: Query IAM actions for a service."""
    print("=" * 80)
    print("Example 1: Query Actions")
    print("=" * 80)

    async with AWSServiceFetcher(prefetch_common=False) as fetcher:
        # Query all S3 actions
        print("\n1. All S3 actions (first 5):")
        all_actions = await query_actions(fetcher, "s3")
        for action in all_actions[:5]:
            print(f"  - {action['action']} ({action['access_level']})")
        print(f"  ... and {len(all_actions) - 5} more")

        # Query write-level actions
        print("\n2. S3 write-level actions (first 5):")
        write_actions = await query_actions(fetcher, "s3", access_level="write")
        for action in write_actions[:5]:
            print(f"  - {action['action']}")
        print(f"  Total: {len(write_actions)} write actions")

        # Query wildcard-only actions
        print("\n3. IAM wildcard-only actions (no resource constraint):")
        wildcard_actions = await query_actions(fetcher, "iam", resource_type="*")
        for action in wildcard_actions[:5]:
            print(f"  - {action['action']}")
        print(f"  Total: {len(wildcard_actions)} wildcard-only actions")

        # Query actions supporting specific condition
        print("\n4. S3 actions supporting s3:prefix condition:")
        condition_actions = await query_actions(fetcher, "s3", condition="s3:prefix")
        for action in condition_actions[:5]:
            print(f"  - {action['action']}")


async def example_query_action_details():
    """Example: Get detailed information about a specific action."""
    print("\n" + "=" * 80)
    print("Example 2: Query Action Details")
    print("=" * 80)

    async with AWSServiceFetcher(prefetch_common=False) as fetcher:
        # Get details for S3 GetObject action
        print("\nS3 GetObject action details:")
        details = await query_action_details(fetcher, "s3", "GetObject")
        print(f"  Action: {details['action']}")
        print(f"  Access Level: {details['access_level']}")
        print(f"  Resource Types: {', '.join(details['resource_types'])}")
        print(f"  Condition Keys: {len(details['condition_keys'])} keys")


async def example_query_arns():
    """Example: Query ARN formats."""
    print("\n" + "=" * 80)
    print("Example 3: Query ARN Formats")
    print("=" * 80)

    async with AWSServiceFetcher(prefetch_common=False) as fetcher:
        # Get all ARN formats for S3
        print("\n1. All S3 ARN formats:")
        arns = await query_arn_formats(fetcher, "s3")
        for arn in arns[:5]:
            print(f"  - {arn}")

        # Get ARN types with their formats
        print("\n2. S3 ARN types (first 3):")
        arn_types = await query_arn_types(fetcher, "s3")
        for rt in arn_types[:3]:
            print(f"  - {rt['resource_type']}:")
            for arn_format in rt['arn_formats']:
                print(f"    {arn_format}")

        # Get specific ARN format details
        print("\n3. S3 bucket ARN format details:")
        bucket_arn = await query_arn_format(fetcher, "s3", "bucket")
        print(f"  Resource Type: {bucket_arn['resource_type']}")
        print(f"  ARN Format: {bucket_arn['arn_formats'][0]}")
        print(f"  Condition Keys: {len(bucket_arn['condition_keys'])} keys")


async def example_query_conditions():
    """Example: Query condition keys."""
    print("\n" + "=" * 80)
    print("Example 4: Query Condition Keys")
    print("=" * 80)

    async with AWSServiceFetcher(prefetch_common=False) as fetcher:
        # Get all condition keys for S3
        print("\n1. S3 condition keys (first 5):")
        conditions = await query_condition_keys(fetcher, "s3")
        for cond in conditions[:5]:
            print(f"  - {cond['condition_key']}")
            print(f"    Types: {', '.join(cond['types'])}")
        print(f"  Total: {len(conditions)} condition keys")

        # Get specific condition key details
        print("\n2. S3 prefix condition key details:")
        prefix_key = await query_condition_key(fetcher, "s3", "s3:prefix")
        print(f"  Condition Key: {prefix_key['condition_key']}")
        print(f"  Types: {', '.join(prefix_key['types'])}")
        print(f"  Description: {prefix_key['description']}")


async def example_convenience_functions():
    """Example: Use convenience functions for common queries."""
    print("\n" + "=" * 80)
    print("Example 5: Convenience Functions")
    print("=" * 80)

    async with AWSServiceFetcher(prefetch_common=False) as fetcher:
        # Get actions by access level (returns just action names)
        print("\n1. IAM permissions-management actions (first 5):")
        pm_actions = await get_actions_by_access_level(
            fetcher, "iam", "permissions-management"
        )
        for action in pm_actions[:5]:
            print(f"  - {action}")
        print(f"  Total: {len(pm_actions)} permissions-management actions")

        # Get wildcard-only actions
        print("\n2. IAM wildcard-only actions (first 5):")
        wildcard_actions = await get_wildcard_only_actions(fetcher, "iam")
        for action in wildcard_actions[:5]:
            print(f"  - {action}")
        print(f"  Total: {len(wildcard_actions)} wildcard-only actions")

        # Get actions supporting MFA condition
        print("\n3. IAM actions supporting aws:MultiFactorAuthPresent:")
        mfa_actions = await get_actions_supporting_condition(
            fetcher, "iam", "aws:MultiFactorAuthPresent"
        )
        for action in mfa_actions[:5]:
            print(f"  - {action}")
        print(f"  Total: {len(mfa_actions)} actions")


async def example_policy_development_workflow():
    """Example: Use query utilities in policy development workflow."""
    print("\n" + "=" * 80)
    print("Example 6: Policy Development Workflow")
    print("=" * 80)

    async with AWSServiceFetcher(prefetch_common=False) as fetcher:
        print("\nScenario: Develop least-privilege S3 policy for read operations")

        # Step 1: Find all read-level S3 actions
        print("\n1. Finding S3 read-level actions...")
        read_actions = await get_actions_by_access_level(fetcher, "s3", "read")
        print(f"   Found {len(read_actions)} read actions")

        # Step 2: Get details about GetObject action
        print("\n2. Getting details for s3:GetObject...")
        details = await query_action_details(fetcher, "s3", "GetObject")
        print(f"   Resource types: {', '.join(details['resource_types'])}")
        print(f"   Supports {len(details['condition_keys'])} condition keys")

        # Step 3: Get the ARN format for the object resource type
        print("\n3. Getting ARN format for S3 object...")
        object_arn = await query_arn_format(fetcher, "s3", "object")
        print(f"   ARN format: {object_arn['arn_formats'][0]}")

        # Step 4: Check what condition keys are available
        print("\n4. Checking available condition keys for restricting access...")
        prefix_key = await query_condition_key(fetcher, "s3", "s3:prefix")
        print(f"   s3:prefix: {prefix_key['description']}")
        print(f"   Types: {', '.join(prefix_key['types'])}")

        print("\n✓ Policy development complete!")
        print("  Recommended policy:")
        print("  {")
        print('    "Effect": "Allow",')
        print('    "Action": "s3:GetObject",')
        print('    "Resource": "arn:aws:s3:::my-bucket/data/*",')
        print('    "Condition": {')
        print('      "StringLike": {')
        print('        "s3:prefix": ["data/*"]')
        print("      }")
        print("    }")
        print("  }")


async def main():
    """Run all examples."""
    print("\n" + "=" * 80)
    print("IAM Policy Validator SDK - Query AWS Service Definitions")
    print("=" * 80)
    print("\nThis example demonstrates the SDK's query capabilities for exploring")
    print("AWS service definitions. These utilities are inspired by policy_sentry.")
    print("\n")

    await example_query_actions()
    await example_query_action_details()
    await example_query_arns()
    await example_query_conditions()
    await example_convenience_functions()
    await example_policy_development_workflow()

    print("\n" + "=" * 80)
    print("All examples completed successfully!")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())

"""
Example: Analyze and inspect IAM policies using the SDK.

This script demonstrates the policy analysis and introspection features:
- Parsing and inspecting policy structure
- Extracting actions, resources, and condition keys
- Searching statements by action or resource
- Checking for public access and resource policies
- Querying AWS service definitions

Usage:
    python -m asyncio examples/sdk/policy_analysis.py
"""

import asyncio

from iam_validator.sdk import (
    AWSServiceFetcher,
    extract_actions,
    extract_condition_keys,
    extract_resources,
    find_statements_with_action,
    get_policy_summary,
    has_public_access,
    is_resource_policy,
    parse_policy,
    policy_to_json,
    query_actions,
)


async def analyze_policy_structure() -> None:
    """Parse a policy and inspect its structure."""
    print("=== Policy Structure Analysis ===")

    policy_dict = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Read",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::my-bucket",
                    "arn:aws:s3:::my-bucket/*",
                ],
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            },
            {
                "Sid": "AllowDynamoDB",
                "Effect": "Allow",
                "Action": "dynamodb:GetItem",
                "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/my-table",
            },
        ],
    }

    policy = parse_policy(policy_dict)

    # Get a full summary
    summary = get_policy_summary(policy)
    print(f"Statements: {summary['statement_count']}")
    print(f"  Allow: {summary['allow_statements']}")
    print(f"  Deny: {summary['deny_statements']}")
    print(f"Actions: {summary['action_count']} — {summary['actions']}")
    print(f"Resources: {summary['resource_count']}")
    print(f"Condition keys: {summary['condition_keys']}")
    print(f"Has wildcard actions: {summary['has_wildcard_actions']}")
    print(f"Has wildcard resources: {summary['has_wildcard_resources']}")

    print()


async def search_policy_statements() -> None:
    """Find statements by action or resource."""
    print("=== Search Statements ===")

    policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S3Access",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                },
                {
                    "Sid": "LambdaInvoke",
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": "arn:aws:lambda:us-east-1:123456789012:function:*",
                },
            ],
        }
    )

    # Find statements containing s3:GetObject
    s3_stmts = find_statements_with_action(policy, "s3:GetObject")
    print(f"Statements with s3:GetObject: {len(s3_stmts)}")
    for stmt in s3_stmts:
        print(f"  SID: {stmt.sid}")

    # Extract all unique actions and resources
    actions = extract_actions(policy)
    resources = extract_resources(policy)
    condition_keys = extract_condition_keys(policy)

    print(f"All actions: {actions}")
    print(f"All resources: {resources}")
    print(f"All condition keys: {condition_keys}")

    print()


async def detect_policy_type() -> None:
    """Detect whether a policy is a resource policy with public access."""
    print("=== Policy Type Detection ===")

    # Identity policy (no Principal)
    identity_policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ],
        }
    )

    # S3 bucket policy (resource policy with Principal)
    bucket_policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::public-bucket/*",
                }
            ],
        }
    )

    print(f"Identity policy — is_resource_policy: {is_resource_policy(identity_policy)}")
    print(f"Identity policy — has_public_access: {has_public_access(identity_policy)}")

    print(f"Bucket policy — is_resource_policy: {is_resource_policy(bucket_policy)}")
    print(f"Bucket policy — has_public_access: {has_public_access(bucket_policy)}")

    print()


async def convert_policy_format() -> None:
    """Convert between policy representations."""
    print("=== Policy Format Conversion ===")

    policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Example",
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }
    )

    # Convert back to formatted JSON (useful for writing to files)
    json_str = policy_to_json(policy, indent=2)
    print(json_str)

    print()


async def query_aws_service() -> None:
    """Query AWS service definitions for action discovery."""
    print("=== Query AWS Service Definitions ===")

    async with AWSServiceFetcher() as fetcher:
        # List all S3 actions
        s3_actions = await query_actions(fetcher, "s3")
        print(f"S3 has {len(s3_actions)} actions")

        # Show first 5 actions
        for action in s3_actions[:5]:
            print(f"  {action['action']}")

        if len(s3_actions) > 5:
            print(f"  ... and {len(s3_actions) - 5} more")

    print()


async def main() -> None:
    await analyze_policy_structure()
    await search_policy_statements()
    await detect_policy_type()
    await convert_policy_format()
    await query_aws_service()


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""
Example 3: Policy manipulation and inspection using SDK utilities.

This demonstrates how to use the SDK to parse, analyze, and manipulate
IAM policies programmatically.
"""

import asyncio
import json

from iam_validator.sdk import (
    extract_actions,
    extract_resources,
    find_statements_with_action,
    get_policy_summary,
    has_public_access,
    is_resource_policy,
    parse_policy,
    policy_to_json,
)


async def analyze_policy():
    """Analyze an IAM policy using SDK utilities."""
    print("=" * 70)
    print("Example 3: Policy Manipulation and Analysis")
    print("=" * 70)

    # Sample policy as a string
    policy_json = """
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Read",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:ListBucket"
                ],
                "Resource": [
                    "arn:aws:s3:::my-bucket",
                    "arn:aws:s3:::my-bucket/*"
                ]
            },
            {
                "Sid": "AllowEC2Describe",
                "Effect": "Allow",
                "Action": "ec2:Describe*",
                "Resource": "*"
            },
            {
                "Sid": "DenyDangerousActions",
                "Effect": "Deny",
                "Action": [
                    "iam:DeleteUser",
                    "iam:DeleteRole"
                ],
                "Resource": "*"
            }
        ]
    }
    """

    # Parse the policy
    print("\n📋 Step 1: Parse Policy")
    print("-" * 70)
    policy = parse_policy(policy_json)
    print(f"✓ Parsed policy version: {policy.version}")
    print(f"✓ Number of statements: {len(policy.statement)}")

    # Get policy summary
    print("\n📊 Step 2: Get Policy Summary")
    print("-" * 70)
    summary = get_policy_summary(policy)

    print(f"Statement Count: {summary['statement_count']}")
    print(f"Allow Statements: {summary['allow_statements']}")
    print(f"Deny Statements: {summary['deny_statements']}")
    print(f"Unique Actions: {summary['action_count']}")
    print(f"Unique Resources: {summary['resource_count']}")
    print(f"Has Wildcard Actions: {summary['has_wildcard_actions']}")
    print(f"Has Wildcard Resources: {summary['has_wildcard_resources']}")

    # Extract actions
    print("\n🔍 Step 3: Extract Actions")
    print("-" * 70)
    actions = extract_actions(policy)
    print("Actions in this policy:")
    for action in actions:
        print(f"  • {action}")

    # Extract resources
    print("\n🔍 Step 4: Extract Resources")
    print("-" * 70)
    resources = extract_resources(policy)
    print("Resources in this policy:")
    for resource in resources:
        print(f"  • {resource}")

    # Find specific statements
    print("\n🔎 Step 5: Find Statements with Specific Actions")
    print("-" * 70)
    s3_statements = find_statements_with_action(policy, "s3:GetObject")
    print(f"Found {len(s3_statements)} statement(s) with 's3:GetObject':")
    for stmt in s3_statements:
        print(f"  • Sid: {stmt.sid}, Effect: {stmt.effect}")

    # Check policy type
    print("\n🏷️  Step 6: Identify Policy Type")
    print("-" * 70)
    if is_resource_policy(policy):
        print("This is a RESOURCE policy (has Principal)")
    else:
        print("This is an IDENTITY policy (no Principal)")

    # Check for public access
    print("\n🔓 Step 7: Check for Public Access")
    print("-" * 70)
    if has_public_access(policy):
        print("⚠️  WARNING: This policy allows public access!")
    else:
        print("✅ This policy does not allow public access")

    # Convert back to JSON
    print("\n📝 Step 8: Convert Back to JSON")
    print("-" * 70)
    json_output = policy_to_json(policy, indent=2)
    print("Policy as formatted JSON:")
    print(json_output[:200] + "..." if len(json_output) > 200 else json_output)

    print("\n" + "=" * 70)
    print("✅ Policy analysis complete!")
    print("=" * 70)


async def check_bucket_policy():
    """Check if a bucket policy allows public access."""
    print("\n\n" + "=" * 70)
    print("Example 3b: Analyzing an S3 Bucket Policy")
    print("=" * 70)

    # S3 bucket policy (resource policy with Principal)
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-public-bucket/*",
            }
        ],
    }

    policy = parse_policy(bucket_policy)

    print("\n📋 Policy Analysis:")
    print("-" * 70)
    print(f"Policy Type: {'Resource Policy' if is_resource_policy(policy) else 'Identity Policy'}")
    print(f"Public Access: {'⚠️  YES' if has_public_access(policy) else '✅ NO'}")

    if has_public_access(policy):
        print("\n⚠️  WARNING: This bucket policy allows PUBLIC access!")
        print("   Anyone on the internet can read objects from this bucket.")

    summary = get_policy_summary(policy)
    print(f"\nActions allowed: {', '.join(summary['actions'])}")
    print(f"Resources affected: {', '.join(summary['resources'])}")


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║              IAM Policy Validator - Example 3 (New SDK)             ║
║                  Policy Manipulation & Analysis                     ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    # Run examples
    asyncio.run(analyze_policy())
    asyncio.run(check_bucket_policy())

    print("\n💡 SDK Policy Utilities:")
    print("   • parse_policy() - Parse JSON/dict into IAMPolicy object")
    print("   • get_policy_summary() - Get statistics about a policy")
    print("   • extract_actions/resources() - Extract specific components")
    print("   • find_statements_with_*() - Search for statements")
    print("   • is_resource_policy() - Identify policy type")
    print("   • has_public_access() - Check for public access")
    print("   • policy_to_json/dict() - Convert back to JSON/dict")

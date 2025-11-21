#!/bin/bash
# Query Command Examples
# This script demonstrates the query command functionality inspired by policy_sentry
# See: https://github.com/salesforce/policy_sentry

set -e

echo "=== IAM Policy Validator - Query Examples ==="
echo

# ============================================================================
# Action Table Queries
# ============================================================================

echo "1. List all S3 actions:"
iam-validator query action --service s3 | head -20
echo

echo "2. Get details for specific action:"
iam-validator query action --service s3 --name GetObject
echo

echo "3. Filter S3 actions by access level (write):"
iam-validator query action --service s3 --access-level write --fmt yaml | head -30
echo

echo "4. Find IAM actions with wildcard-only resources:"
iam-validator query action --service iam --resource-type "*" | head -20
echo

echo "5. Find actions that support a specific condition key:"
iam-validator query action --service s3 --condition s3:prefix | head -10
echo

echo "6. List all permissions-management actions for IAM:"
iam-validator query action --service iam --access-level permissions-management --fmt yaml | head -20
echo

# ============================================================================
# ARN Table Queries
# ============================================================================

echo "7. List all S3 ARN formats:"
iam-validator query arn --service s3
echo

echo "8. Get details for specific ARN type:"
iam-validator query arn --service s3 --name bucket
echo

echo "9. List all ARN types with their formats:"
iam-validator query arn --service ec2 --list-arn-types --fmt yaml | head -40
echo

# ============================================================================
# Condition Keys Table Queries
# ============================================================================

echo "10. List all condition keys for S3:"
iam-validator query condition --service s3 | head -20
echo

echo "11. Get details for specific condition key:"
iam-validator query condition --service s3 --name s3:prefix
echo

echo "12. List all IAM condition keys (YAML format):"
iam-validator query condition --service iam --fmt yaml | head -30
echo

echo "=== All examples completed successfully! ==="

# Query Command

The `query` command allows you to explore AWS service definitions including IAM actions, ARN formats, and condition keys. This feature is inspired by [policy_sentry](https://github.com/salesforce/policy_sentry)'s query functionality.

## Features

- **Query IAM Actions** - List all actions for a service, filter by access level, resource type, or condition key
- **Query ARN Formats** - View ARN formats and resource types for any AWS service
- **Query Condition Keys** - Explore available condition keys and their types
- **Multiple Output Formats** - JSON (default), YAML, or text output

## Usage

### Action Queries

```bash
# List all actions for a service
iam-validator query action --service s3

# Get details for specific action
iam-validator query action --service s3 --name GetObject

# Filter by access level
iam-validator query action --service s3 --access-level write
iam-validator query action --service iam --access-level permissions-management

# Find wildcard-only actions (no required resources)
iam-validator query action --service iam --resource-type "*"

# Filter by specific resource type
iam-validator query action --service s3 --resource-type bucket

# Find actions that support a specific condition key
iam-validator query action --service s3 --condition s3:prefix
```

### ARN Queries

```bash
# List all ARN formats for a service
iam-validator query arn --service s3

# Get details for specific ARN type
iam-validator query arn --service s3 --name bucket

# List all ARN types with their formats
iam-validator query arn --service s3 --list-arn-types
```

### Condition Key Queries

```bash
# List all condition keys for a service
iam-validator query condition --service s3

# Get details for specific condition key
iam-validator query condition --service s3 --name s3:prefix
```

### Output Formats

The query command supports three output formats:
- **json** (default) - Structured JSON output with all details
- **yaml** - Human-readable YAML format
- **text** - Simple text output, one item per line (perfect for piping to other commands)

```bash
# JSON output (default) - structured data with all details
iam-validator query action --service s3 --fmt json

# YAML output - human-readable format
iam-validator query action --service s3 --fmt yaml

# Text output - simple, one item per line (perfect for piping)
iam-validator query action --service s3 --fmt text

# Combine text format with shell tools
iam-validator query action --service s3 --fmt text | grep Delete
iam-validator query action --service iam --access-level permissions-management --fmt text | wc -l
```

## Examples

### Example 1: Find High-Privilege Actions

Find all IAM actions with permissions management access level:

```bash
iam-validator query action --service iam --access-level permissions-management
```

Output:
```json
[
  {
    "action": "iam:AttachGroupPolicy",
    "access_level": "permissions-management",
    "description": "N/A"
  },
  {
    "action": "iam:AttachRolePolicy",
    "access_level": "permissions-management",
    "description": "N/A"
  }
]
```

### Example 2: Find Actions Without Resource Constraints

Find all `s3` actions that work with wildcard resources:

```bash
iam-validator query action --service s3 --resource-type "*"
```

This helps identify actions that don't require specific resource ARNs.

### Example 3: Get ARN Format for S3 Bucket

```bash
iam-validator query arn --service s3 --name bucket
```

Output:
```json
{
  "service": "s3",
  "resource_type": "bucket",
  "arn_formats": [
    "arn:${Partition}:s3:::${BucketName}"
  ],
  "condition_keys": [
    "aws:ResourceTag/${TagKey}",
    "s3:BucketTag/${TagKey}"
  ]
}
```

### Example 4: Explore Condition Keys

Find all condition keys available for S3:

```bash
iam-validator query condition --service s3 --fmt yaml
```

### Example 5: Find Tagging Actions

Find all tagging-related actions for a service:

```bash
iam-validator query action --service s3 --access-level tagging
```

Output:

```json
[
  {
    "action": "s3:DeleteObjectTagging",
    "access_level": "tagging",
    "description": "N/A"
  },
  {
    "action": "s3:PutObjectTagging",
    "access_level": "tagging",
    "description": "N/A"
  }
]
```

This helps identify actions that are purely for managing resource tags.

### Example 6: Using Text Format for Scripting

The text format is perfect for shell scripting and automation:

```bash
# Count all Delete actions in S3
iam-validator query action --service s3 --fmt text | grep -c Delete

# Get all write actions for multiple services
for service in s3 iam ec2; do
  echo "$service write actions:"
  iam-validator query action --service $service --access-level write --fmt text | head -5
done

# Find actions matching a pattern
iam-validator query action --service iam --fmt text | grep -i policy | sort

# Export action list to file
iam-validator query action --service s3 --fmt text > s3-actions.txt

# Get just the ARN formats
iam-validator query arn --service s3 --fmt text | grep bucket
```

**Text format output:**
```
s3:AbortMultipartUpload
s3:CreateBucket
s3:DeleteBucket
s3:DeleteObject
...
```

## Access Levels

The query command categorizes actions into five access levels based on AWS IAM properties:

- **read** - Actions that read data but don't modify anything
- **write** - Actions that create, modify, or delete resources
- **list** - Actions that list resources
- **tagging** - Actions related to tagging resources
- **permissions-management** - Actions that grant or modify permissions

## Use Cases

### Policy Development

Use queries to:
- Discover available actions for a service
- Find the correct ARN format for resources
- Identify which condition keys can be used with specific actions
- Ensure you're using the appropriate access level for your needs

### Security Auditing

Use queries to:
- Find high-privilege actions (permissions-management level)
- Identify actions that don't require resource constraints
- Understand which condition keys should be enforced

### Documentation

Use queries to:
- Generate documentation about available IAM actions
- Create reference tables for your organization
- Understand service capabilities

## Implementation Notes

This feature reuses the existing `AWSServiceFetcher` infrastructure, ensuring:
- **Consistent caching** - Queries use the same cache as validation
- **Offline support** - Works with pre-downloaded service definitions
- **No extra dependencies** - Pure Python implementation
- **Fast execution** - Leverages existing HTTP/2 connection pooling

## Credits

This feature is inspired by [policy_sentry](https://github.com/salesforce/policy_sentry)'s query functionality. We acknowledge and thank the Salesforce team for their excellent work on IAM tooling.

## Related Commands

- `iam-validator download-services` - Pre-download AWS service definitions for offline use
- `iam-validator cache` - Manage the service definition cache
- `iam-validator validate` - Validate IAM policies using service definitions

# Action-Resource Mismatch Examples

This directory contains example IAM policies with **intentionally wrong** action-resource combinations to demonstrate the `action_resource_matching` check.

## Purpose

These policies show common mistakes where:
- The action requires a specific resource type
- But the policy specifies a different resource type
- The policy is syntactically valid but won't work as intended

## Examples by Service

### S3 - [s3-wrong-resources.json](s3-wrong-resources.json)
Common S3 action-resource mismatches:
- ❌ `s3:GetObject` with bucket ARN (needs object ARN with `/*`)
- ❌ `s3:ListBucket` with object ARN (needs bucket ARN without `/*`)
- ❌ `s3:PutObject` with bucket ARN
- ❌ `s3:DeleteBucket` with object ARN

### IAM - [iam-wrong-resources.json](iam-wrong-resources.json)
Common IAM action-resource mismatches:
- ❌ `iam:GetUser` with role ARN (needs user ARN)
- ❌ `iam:GetRole` with user ARN (needs role ARN)
- ❌ `iam:GetPolicy` with user ARN (needs policy ARN)
- ❌ `iam:DeleteRole` with group ARN

### EC2 - [ec2-wrong-resources.json](ec2-wrong-resources.json)
Common EC2 action-resource mismatches:
- ❌ `ec2:TerminateInstances` with volume ARN (needs instance ARN)
- ❌ `ec2:DeleteVolume` with instance ARN (needs volume ARN)
- ❌ `ec2:CreateSnapshot` with instance ARN (needs volume ARN)

### Lambda - [lambda-wrong-resources.json](lambda-wrong-resources.json)
Common Lambda action-resource mismatches:
- ❌ `lambda:InvokeFunction` with layer ARN (needs function ARN)
- ❌ `lambda:GetLayerVersion` with function ARN (needs layer ARN)
- ❌ `lambda:DeleteFunction` with event source ARN

### DynamoDB - [dynamodb-wrong-resources.json](dynamodb-wrong-resources.json)
Common DynamoDB action-resource mismatches:
- ❌ `dynamodb:GetItem` with index ARN (needs table ARN)
- ❌ `dynamodb:Query` with stream ARN (needs table ARN)
- ❌ `dynamodb:DeleteTable` with backup ARN

### SQS/SNS - [sqs-sns-wrong-resources.json](sqs-sns-wrong-resources.json)
Common SQS/SNS action-resource mismatches:
- ❌ `sqs:SendMessage` with SNS topic ARN (needs SQS queue ARN)
- ❌ `sns:Publish` with SQS queue ARN (needs SNS topic ARN)

## Testing

Validate these policies to see the action_resource_matching check in action:

```bash
# Test all examples
iam-validator validate --path examples/iam-test-policies/wrong_actions_mismatch/

# Test specific service
iam-validator validate --path examples/iam-test-policies/wrong_actions_mismatch/s3-wrong-resources.json

# See detailed output
iam-validator validate --path examples/iam-test-policies/wrong_actions_mismatch/ --format enhanced
```

## Expected Output

Each policy should generate validation errors like:

```
❌ MEDIUM: No resources match for action 's3:GetObject'
   This action requires resource type: object
   Expected format: arn:${Partition}:s3:::${BucketName}/${ObjectName}
   Example: arn:aws:s3:::bucket/* or arn:aws:s3:::bucket/prefix/*
   Current resources: arn:aws:s3:::my-bucket
```

## Learning from These Examples

These examples help you:
1. **Understand resource requirements** for different AWS actions
2. **Avoid common mistakes** when writing IAM policies
3. **Test the validator** to ensure it catches real-world errors
4. **Learn ARN formats** for different AWS resource types

## Correct Versions

To see the correct versions of these policies, check the main examples directory or refer to AWS documentation for proper ARN formats for each action.

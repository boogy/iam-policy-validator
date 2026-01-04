# Example Conversation: Secure IAM Policy Generation

This document shows an example interaction demonstrating best practices for generating secure IAM policies using the MCP server.

---

## User Request

> "I need a policy for my Lambda function that reads from an S3 bucket and writes to DynamoDB"

---

## AI Response

### Understanding Your Requirements

Let me clarify a few details to generate the most secure policy:

1. **S3 Bucket**: Which bucket? What prefix if any?
2. **DynamoDB Table**: Which table? What operations (read, write, both)?
3. **Lambda Function**: What's the function name for CloudWatch Logs scoping?
4. **Region/Account**: Should we scope to specific region/account?

For this example, I'll assume:
- S3 bucket: `my-app-data-bucket`
- DynamoDB table: `my-app-users`
- Lambda function: `my-data-processor`
- Region: `us-east-1`
- Account: `123456789012`

### Step 1: Check Sensitive Actions

First, let me verify the actions we need aren't flagged as sensitive:

```
Tool: check_sensitive_actions
Input: {
  "actions": ["s3:GetObject", "dynamodb:PutItem", "dynamodb:UpdateItem", "logs:CreateLogStream"]
}
```

**Result**: No sensitive actions detected. These are standard data operations.

### Step 2: Query Correct ARN Formats

```
Tool: query_arn_formats
Input: {"service": "dynamodb"}
```

**Result**: `arn:aws:dynamodb:{region}:{account}:table/{table-name}`

### Step 3: Generate the Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogsAccess",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-data-processor:*"
    },
    {
      "Sid": "S3ReadAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion"
      ],
      "Resource": "arn:aws:s3:::my-app-data-bucket/*",
      "Condition": {
        "StringEqual": {
          "aws:ResourceAccount": "${aws:PrincipalAccount}"
        }
      }
    },
    {
      "Sid": "S3ListBucket",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": "arn:aws:s3:::my-app-data-bucket"
    },
    {
      "Sid": "DynamoDBWriteAccess",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:GetItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:us-east-1:123456789012:table/my-app-users",
        "arn:aws:dynamodb:us-east-1:123456789012:table/my-app-users/index/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:ResourceAccount": "${aws:PrincipalAccount}"
        }
      }
    }
  ]
}
```

### Step 4: Validate the Policy

```
Tool: validate_policy
Input: {
  "policy": <policy above>,
  "policy_type": "identity"
}
```

**Validation Results**:
- **Valid**: true
- **Issues**: 0

### Security Analysis

**What this policy allows:**
- Write Lambda execution logs to the specific log group
- Read objects from the S3 bucket (with TLS required)
- List the S3 bucket contents
- Read/write items in the DynamoDB table and its indexes

**Security measures in place:**
1. **Resource scoping**: All resources are explicitly named, no wildcards
2. **TLS enforcement**: S3 access requires secure transport
3. **Account scoping**: DynamoDB access restricted to same account
4. **Log isolation**: CloudWatch logs scoped to specific function

**What this policy does NOT allow:**
- Access to other S3 buckets
- Access to other DynamoDB tables
- Deleting the S3 bucket or DynamoDB table
- IAM operations
- Cross-account access

### Usage Notes

1. **Attach to Lambda execution role**: Create an IAM role with this policy and the AWS managed `AWSLambdaBasicExecutionRole` for X-Ray tracing if needed.

2. **Trust policy needed**: The role also needs a trust policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Service": "lambda.amazonaws.com"
    },
    "Action": "sts:AssumeRole"
  }]
}
```

3. **Monitoring**: Enable CloudTrail for the S3 bucket and DynamoDB table to audit access.

---

## Anti-Pattern Example

If the user had asked "just give me full access", here's how to respond:

> **User**: "Just give me a policy with full S3 and DynamoDB access"

> **AI Response**:
>
> I can't generate a policy with `s3:*` or `dynamodb:*` on all resources as this violates least-privilege principles and would fail security validation.
>
> However, I can help you with:
> 1. **List your specific needs** - Which buckets/tables? What operations?
> 2. **Use templates** - I have secure templates for common patterns
> 3. **Time-boxed access** - If you need broad access temporarily for debugging, I can add time-based conditions
>
> Which approach would work best for your use case?

---

## Advanced Example: Cross-Account Access

> **User**: "I need to assume a role in another account (987654321098) to access their S3 bucket"

### Step 1: Check Sensitive Actions

```
Tool: check_sensitive_actions
Input: {"actions": ["sts:AssumeRole"]}
```

**Result**: `sts:AssumeRole` is flagged as sensitive - requires conditions.

### Step 2: Get Required Conditions

```
Tool: get_required_conditions
Input: {"actions": ["sts:AssumeRole"]}
```

**Result**: Recommend `sts:ExternalId` or source restrictions.

### Step 3: Generate Secure Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeExternalRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::987654321098:role/cross-account-s3-reader",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "a1b2c3d4-unique-id-here"
        },
        "StringLike": {
          "aws:RequestTag/Purpose": "data-sync"
        }
      }
    }
  ]
}
```

### Step 4: Validate

```
Tool: validate_policy
```

**Result**: Valid with 0 issues.

### Security Notes

- **External ID**: Prevents confused deputy attacks
- **Specific role ARN**: Cannot assume any other roles
- **Request tags**: Optional additional verification

**Important**: The target account also needs to configure their trust policy to allow your account and validate the External ID.

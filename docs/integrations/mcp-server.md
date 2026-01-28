---
title: MCP Server
description: Use IAM Policy Validator with AI assistants via Model Context Protocol
---

# MCP Server Integration

IAM Policy Validator provides a Model Context Protocol (MCP) server for AI assistants like Claude Desktop, Cursor, Windsurf, etc... This enables AI-powered policy generation, validation, and AWS service queries.

## What is MCP?

[Model Context Protocol](https://modelcontextprotocol.io/) is an open protocol that enables AI assistants to interact with external tools and data sources. The IAM Policy Validator MCP server exposes 35 tools for:

- **Policy Validation** - Validate IAM policies against AWS rules and security best practices
- **Policy Generation** - Generate secure policies from templates or natural language
- **AWS Queries** - Query AWS service definitions, actions, ARN formats, and conditions
- **Organization Config** - Enforce organization-wide policy restrictions

## Installation

```bash
pip install iam-policy-validator[mcp]
```

Or with uv:

```bash
uv sync --extra mcp
```

### Run Without Installation (uvx)

You can run the MCP server directly from PyPI without installing it using [uvx](https://docs.astral.sh/uv/guides/tools/):

```bash
uvx --from 'iam-policy-validator[mcp]' iam-validator-mcp
```

This is particularly useful for Claude Desktop configuration (see below).

## Claude Desktop Setup

### 1. Configure Claude Desktop

Add the server to your Claude Desktop configuration:

=== "macOS"

    Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "iam-validator-mcp",
          "args": []
        }
      }
    }
    ```

=== "Windows"

    Edit `%APPDATA%\Claude\claude_desktop_config.json`:

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "iam-validator-mcp",
          "args": []
        }
      }
    }
    ```

=== "Linux"

    Edit `~/.config/Claude/claude_desktop_config.json`:

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "iam-validator-mcp",
          "args": []
        }
      }
    }
    ```

=== "Using uvx (No Installation)"

    If you prefer not to install the package globally, use [uvx](https://docs.astral.sh/uv/guides/tools/) to run directly from PyPI:

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "uvx",
          "args": ["--from", "iam-policy-validator[mcp]", "iam-validator-mcp"]
        }
      }
    }
    ```

    This downloads and runs the latest version automatically. To pin a specific version:

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "uvx",
          "args": ["--from", "iam-policy-validator[mcp]==1.15.2", "iam-validator-mcp"]
        }
      }
    }
    ```

### 2. Restart Claude Desktop

After saving the configuration, restart Claude Desktop completely for changes to take effect.

### 3. Verify Installation

In Claude Desktop, ask:

> "What IAM policy validation tools do you have available?"

Claude should list the available MCP tools for policy validation and generation.

## Pre-loading Organization Configuration

You can pre-load a configuration file when starting the MCP server. This applies organization-wide validation settings for all operations without requiring the AI to set them up.

### 1. Create an Organization Config File

Create a YAML file (e.g., `config.yaml`) with your check settings. The format is the same as the CLI validator configuration:

```yaml
# Organization IAM Policy Configuration for MCP Server
# Uses the same format as the CLI validator configuration

# Global settings
settings:
  # Fail validation on these severity levels
  fail_on_severity:
    - error
    - critical
    - high

# Configure individual checks by their check_id
# Make wildcard resources a critical issue (default: medium)
wildcard_resource:
  severity: critical

# Make service wildcards (e.g., s3:*) critical
service_wildcard:
  severity: critical
  # Optionally allow certain services to use wildcards
  # allowed_services:
  #   - logs
  #   - cloudwatch

# Require conditions for sensitive actions
sensitive_action:
  enabled: true
  severity: high

# Require specific conditions for certain actions
action_condition_enforcement:
  enabled: true
  severity: high
  # Custom requirements can be defined here
  # See full-reference-config.yaml for examples
```

### 2. Configure Claude Desktop with the Config File

Update your Claude Desktop configuration to include the `--config` argument:

=== "macOS"

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "iam-validator-mcp",
          "args": ["--config", "/Users/you/config.yaml"]
        }
      }
    }
    ```

=== "Windows"

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "iam-validator-mcp",
          "args": ["--config", "C:\\Users\\you\\config.yaml"]
        }
      }
    }
    ```

=== "Linux"

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "iam-validator-mcp",
          "args": ["--config", "/home/you/config.yaml"]
        }
      }
    }
    ```

=== "Using uvx"

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "uvx",
          "args": [
            "--from", "iam-policy-validator[mcp]",
            "iam-validator-mcp",
            "--config", "/path/to/config.yaml"
          ]
        }
      }
    }
    ```

### 3. Alternative: Use iam-validator CLI

You can also use the full CLI command which provides more options:

```json
{
  "mcpServers": {
    "iam-policy-validator": {
      "command": "iam-validator",
      "args": ["mcp", "--config", "/path/to/config.yaml"]
    }
  }
}
```

### Configuration Options

The MCP server uses the same configuration format as the CLI validator. Configuration is organized as:

| Section             | Type | Description                                        |
| ------------------- | ---- | -------------------------------------------------- |
| `settings`          | dict | Global settings (fail_on_severity, parallel, etc.) |
| `<check_id>`        | dict | Per-check configuration (enabled, severity, etc.)  |
| `custom_checks`     | list | Custom check modules to load                       |
| `custom_checks_dir` | str  | Directory for auto-discovered custom checks        |

#### Common Settings

| Setting            | Type | Description                                   |
| ------------------ | ---- | --------------------------------------------- |
| `fail_on_severity` | list | Severity levels that cause validation to fail |
| `fail_fast`        | bool | Stop on first error                           |
| `parallel`         | bool | Enable parallel check execution               |

#### Per-Check Options

Each check can be configured with:

| Option            | Type | Description                                        |
| ----------------- | ---- | -------------------------------------------------- |
| `enabled`         | bool | Enable or disable the check                        |
| `severity`        | str  | Override the default severity level                |
| `ignore_patterns` | list | Patterns to ignore for this check                  |
| (check-specific)  | any  | Check-specific options (see full-reference-config) |

### Example Configurations

#### Enterprise Security (Strict)

```yaml
settings:
  fail_on_severity:
    - error
    - critical
    - high

# Critical severity for any wildcard usage
wildcard_action:
  severity: critical

wildcard_resource:
  severity: critical

service_wildcard:
  severity: critical
  # Only allow wildcards for logging services
  allowed_services:
    - logs
    - cloudwatch

# Require conditions for all sensitive actions
sensitive_action:
  enabled: true
  severity: high

# Detect dangerous NotAction/NotResource patterns
not_action_not_resource:
  enabled: true
  severity: critical
```

#### Development Environment (Permissive)

```yaml
settings:
  fail_on_severity:
    - error
    - critical

# Disable some checks for dev environment
service_wildcard:
  enabled: false

# Lower severity for wildcards in dev
wildcard_resource:
  severity: medium
```

#### Security-Focused (Condition Enforcement)

```yaml
settings:
  fail_on_severity:
    - error
    - critical
    - high

# Enforce conditions on sensitive actions
action_condition_enforcement:
  enabled: true
  severity: high

# Require conditions for sensitive actions
sensitive_action:
  enabled: true
  severity: high

# Validate principal elements strictly
principal_validation:
  enabled: true
  severity: high
  blocked_principals:
    - "*"
```

## Available Tools

### Validation Tools

| Tool                      | Description                                                                                                                                              |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `validate_policy`         | Validate an IAM policy against AWS rules and security best practices. Auto-detects policy type (identity, trust, or resource) based on policy structure. |
| `quick_validate`          | Quick pass/fail validation check                                                                                                                         |
| `validate_policies_batch` | Validate multiple policies in a single call                                                                                                              |

### Generation Tools

| Tool                            | Description                                                                                                                                                                  |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `generate_policy_from_template` | Generate a policy from a built-in secure template                                                                                                                            |
| `build_minimal_policy`          | Build a least-privilege policy from actions and resources. Automatically applies required conditions for sensitive actions (e.g., `iam:PassedToService` for `iam:PassRole`). |
| `build_arn`                     | Build a valid ARN from components (service, resource type, resource name, region, account) with format validation                                                            |
| `list_templates`                | List all available policy templates                                                                                                                                          |
| `suggest_actions`               | Suggest AWS actions based on natural language description                                                                                                                    |
| `get_required_conditions`       | Get recommended conditions for sensitive actions                                                                                                                             |
| `check_sensitive_actions`       | Check if actions are in the sensitive actions catalog                                                                                                                        |

### Analysis Tools

| Tool               | Description                                                                                                            |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `explain_policy`   | Generate a human-readable explanation of what a policy allows or denies, including security concerns and services used |
| `compare_policies` | Compare two IAM policies and highlight differences in permissions, actions added/removed, and resource scope changes   |

### Query Tools

| Tool                                    | Description                                                                             |
| --------------------------------------- | --------------------------------------------------------------------------------------- |
| `query_service_actions`                 | Get all actions for an AWS service                                                      |
| `query_action_details`                  | Get detailed information about a specific action                                        |
| `query_actions_batch`                   | Get details for multiple actions in a single call (more efficient than individual calls)|
| `expand_wildcard_action`                | Expand patterns like `s3:Get*` to specific actions                                      |
| `query_condition_keys`                  | Get condition keys for a service                                                        |
| `query_arn_formats`                     | Get ARN format patterns for a service                                                   |
| `list_checks`                           | List all available validation checks                                                    |
| `get_check_details`                     | Get full documentation for a specific check including examples and configuration options|
| `get_policy_summary`                    | Analyze a policy's structure                                                            |
| `list_sensitive_actions`                | List sensitive actions by category                                                      |
| `check_actions_batch`                   | Validate and check sensitivity for multiple actions in one call                         |
| `get_condition_requirements_for_action` | Get required conditions for a specific action based on sensitivity and best practices   |

### Fix and Help Tools

| Tool                 | Description                                                                                                          |
| -------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `fix_policy_issues`  | Auto-fix common structural policy issues including action case normalization (e.g., `S3:GetObject` → `s3:GetObject`) |
| `get_issue_guidance` | Get detailed guidance on fixing specific issues                                                                      |

### Organization Config Tools

| Tool                                 | Description                                |
| ------------------------------------ | ------------------------------------------ |
| `set_organization_config`            | Set organization-wide policy restrictions  |
| `get_organization_config`            | Get current organization configuration     |
| `clear_organization_config`          | Clear organization configuration           |
| `load_organization_config_from_yaml` | Load config from YAML                      |
| `check_org_compliance`               | Check if a policy complies with org config |
| `validate_with_config`               | Validate with inline configuration         |

### Custom Instructions Tools

| Tool                        | Description                                                         |
| --------------------------- | ------------------------------------------------------------------- |
| `set_custom_instructions`   | Set custom organization-specific instructions for policy generation |
| `get_custom_instructions`   | Get the current custom instructions                                 |
| `clear_custom_instructions` | Clear custom instructions, reverting to defaults                    |

## Usage Examples

This section provides comprehensive prompt examples for all MCP tools, organized by category.

---

### Policy Validation

#### Basic Validation

> "Validate this IAM policy and explain any issues:
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Action": "s3:*",
>       "Resource": "*"
>     }
>   ]
> }
> ```

#### Quick Pass/Fail Check

> "Do a quick security check on this policy - I just need to know if it's safe or not:
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Action": ["s3:GetObject", "s3:ListBucket"],
>       "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
>     }
>   ]
> }
> ```

#### Validate Multiple Policies at Once

> "I have 3 policies I need to validate. Check all of them and tell me which ones have issues:
>
> Policy 1 (S3 access):
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Action": ["s3:GetObject"],
>       "Resource": "arn:aws:s3:::bucket1/*"
>     }
>   ]
> }
> ```
>
> Policy 2 (Lambda execution):
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [{ "Effect": "Allow", "Action": ["logs:*"], "Resource": "*" }]
> }
> ```
>
> Policy 3 (Admin access):
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [{ "Effect": "Allow", "Action": "*", "Resource": "*" }]
> }
> ```

#### Validate a Trust Policy

> "Validate this trust policy for my Lambda execution role:
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Principal": { "Service": "lambda.amazonaws.com" },
>       "Action": "sts:AssumeRole"
>     }
>   ]
> }
> ```

#### Validate a Resource-Based Policy

> "Check this S3 bucket policy for security issues:
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Principal": "*",
>       "Action": "s3:GetObject",
>       "Resource": "arn:aws:s3:::my-public-bucket/*"
>     }
>   ]
> }
> ```

---

### Policy Generation

#### Generate from Natural Language

> "Create an IAM policy for a Lambda function that needs to:
>
> - Read objects from S3 bucket 'data-lake-prod'
> - Query DynamoDB table 'user-sessions'
> - Publish messages to SNS topic 'notifications'
> - Write logs to CloudWatch"

#### Generate Using Templates

> "What policy templates do you have available?"

Then:

> "Generate a policy using the s3-read-write template for bucket 'customer-uploads' with the prefix 'incoming/'"

Or:

> "Use the lambda-basic-execution template to create a policy for my function called 'process-orders'"

#### Generate from New Templates

**SQS Consumer:**

> "Generate a policy using the sqs-consumer template for queue URL https://sqs.us-east-1.amazonaws.com/123456789012/my-queue"

**SNS Publisher:**

> "Use the sns-publisher template to create a policy for SNS topic arn:aws:sns:us-east-1:123456789012:notifications"

**Step Functions Execution:**

> "Generate a policy using the step-functions-execution template for state machine arn:aws:states:us-east-1:123456789012:stateMachine:MyWorkflow"

**API Gateway Invoke:**

> "Create a policy using the api-gateway-invoke template for API ID abc123def in us-east-1"

**Cross-Account Access:**

> "Use the cross-account-assume-role template to allow account 987654321098 to assume roles in my account with MFA required"

#### Build Minimal Policy from Specific Actions

> "Build me a minimal policy with these specific actions and resources:
>
> - Actions: s3:GetObject, s3:PutObject, s3:DeleteObject
> - Resources: arn:aws:s3:::my-bucket/uploads/\*
> - Add a condition requiring secure transport (HTTPS)"

#### Generate Policy with Conditions

> "Create a policy that allows iam:PassRole but only when passing the role to Lambda service. The role ARN is arn:aws:iam::123456789012:role/LambdaExecutionRole"

#### Suggest Actions for a Use Case

> "What AWS actions do I need to allow a service to read from DynamoDB?"

> "Suggest the minimum S3 actions needed to upload files and list bucket contents"

> "What Lambda actions are needed to invoke functions and read their configuration?"

---

### AWS Service Queries

#### List All Actions for a Service

> "Show me all S3 actions"

> "What actions are available for the Lambda service?"

> "List all IAM actions - I want to understand what permissions exist"

#### Filter Actions by Access Level

> "Show me only the S3 write actions"

> "What are all the read-only DynamoDB actions?"

> "List all IAM permissions-management actions - the ones that can modify policies"

#### Get Details About a Specific Action

> "Tell me about the s3:PutObject action - what resource types does it work with and what condition keys can I use?"

> "What are the details of iam:PassRole? I want to understand how to use it correctly"

#### Expand Wildcard Actions

> "What actions does s3:Get\* expand to?"

> "If I use iam:_User_ in my policy, what actions would that actually allow?"

> "Expand lambda:Invoke\* to show me all the invoke-related actions"

#### Get ARN Formats

> "What's the correct ARN format for S3 buckets and objects?"

> "Show me the ARN format for DynamoDB tables and indexes"

> "How do I write ARNs for Lambda functions? Include region and account placeholders"

#### Get Condition Keys

> "What condition keys can I use with S3 actions?"

> "List all IAM condition keys - I want to add fine-grained access control"

> "What conditions are available for restricting Lambda invocations?"

---

### Sensitive Actions & Security

#### Check if Actions are Sensitive

> "Are any of these actions considered high-risk: iam:CreateAccessKey, s3:GetObject, lambda:InvokeFunction?"

> "Check these actions for security concerns: sts:AssumeRole, iam:AttachRolePolicy, kms:Decrypt"

#### List Sensitive Actions by Category

> "Show me all actions that could lead to privilege escalation"

> "What actions are in the credential_exposure category?"

> "List the data_access sensitive actions - I want to know what needs extra protection"

#### Get Required Conditions for Sensitive Actions

> "What conditions should I add when using iam:PassRole?"

> "Tell me the recommended security conditions for sts:AssumeRole"

> "What conditions are required for iam:CreateAccessKey to be secure?"

#### Analyze Policy Security

> "Analyze this policy and give me a summary of what it allows:
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     { "Effect": "Allow", "Action": ["s3:*"], "Resource": "arn:aws:s3:::*" },
>     { "Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": "*" }
>   ]
> }
> ```

---

### Fixing Policy Issues

#### Auto-Fix Structural Issues

> "This policy is missing the Version field. Can you fix it automatically?
>
> ```json
> {
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Action": "s3:GetObject",
>       "Resource": "arn:aws:s3:::my-bucket/*"
>     }
>   ]
> }
> ```

#### Fix Duplicate SIDs

> "Fix the duplicate SIDs in this policy:
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Sid": "ReadAccess",
>       "Effect": "Allow",
>       "Action": "s3:GetObject",
>       "Resource": "*"
>     },
>     {
>       "Sid": "ReadAccess",
>       "Effect": "Allow",
>       "Action": "s3:ListBucket",
>       "Resource": "*"
>     }
>   ]
> }
> ```

#### Get Guidance on Fixing Issues

> "My policy validation failed with check_id 'wildcard_action'. How do I fix this?"

> "Help me understand how to fix the 'sensitive_action' validation error"

> "What are the steps to fix an 'action_condition_enforcement' issue?"

---

### Organization Configuration

#### Set Organization Restrictions

> "Set up strict validation for my security team:
>
> - Make wildcard patterns critical severity
> - Enable sensitive action checking
> - Fail on high severity and above"

> "Configure the validator to be strict about wildcards and fail on high severity issues"

#### Load Configuration from YAML

> "Load this organization configuration:
>
> ````yaml
> settings:
>   fail_on_severity:
>     - error
>     - critical
>     - high
>
> wildcard_resource:
>   severity: critical
>
> service_wildcard:
>   severity: critical
>
> sensitive_action:
>   enabled: true
>   severity: high
> ```"
> ````

#### Check Compliance Against Org Rules

> "Check if this policy complies with our organization's security rules:
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Action": "iam:CreateUser",
>       "Resource": "*"
>     }
>   ]
> }
> ```

#### Validate with Custom Rules

> "Validate this policy with these specific check settings - don't change my global settings:
>
> - Make wildcard_resource severity critical
> - Enable sensitive_action check
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Action": ["lambda:InvokeFunction"],
>       "Resource": "*"
>     }
>   ]
> }
> ```

#### View Current Organization Config

> "Show me the current organization configuration"

> "What security restrictions are currently active?"

#### Clear Organization Config

> "Clear all organization restrictions - I want to validate without any custom rules"

---

### Complex Workflows

#### Create a Complete Lambda Execution Role

> "I'm setting up a new Lambda function called 'data-processor' that needs to:
>
> 1. Be triggered by S3 events from bucket 'incoming-data'
> 2. Read/write to DynamoDB table 'processed-records'
> 3. Send notifications to SNS topic 'alerts'
> 4. Store secrets in Secrets Manager prefix 'data-processor/'
>
> Create both the trust policy and the permissions policy with least-privilege access."

#### Audit an Existing Policy

> "Review this policy and tell me:
>
> 1. What services it grants access to
> 2. If there are any security issues
> 3. Specific recommendations to improve it
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Action": [
>         "s3:*",
>         "dynamodb:*",
>         "lambda:InvokeFunction",
>         "iam:PassRole"
>       ],
>       "Resource": "*"
>     }
>   ]
> }
> ```

#### Tighten Overly Permissive Policy

> "This policy is too permissive. Help me tighten it while keeping the same functionality - my Lambda needs to read from S3 and write to DynamoDB:
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Action": ["s3:*", "dynamodb:*"],
>       "Resource": "*"
>     }
>   ]
> }
> ```
>
> The S3 bucket is 'my-data-bucket' and the DynamoDB table is 'my-table' in us-east-1, account 123456789012."

#### Create Cross-Account Access Policy

> "Create a policy that allows account 987654321098 to assume a role in my account (123456789012), but only from specific IP ranges (10.0.0.0/8) and require MFA"

#### Set Up Read-Only Audit Access

> "Create a read-only policy for security auditors that allows:
>
> - Viewing all S3 buckets and their configurations
> - Reading CloudTrail logs
> - Viewing IAM policies and roles (but not modifying)
> - Reading CloudWatch metrics and logs
>
> Make sure it's truly read-only with no write permissions."

#### Migrate from Wildcards to Specific Permissions

> "I have this legacy policy with wildcards. Help me identify what specific actions are being used and create a tighter policy:
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Action": ["ec2:Describe*", "rds:Describe*", "elasticache:Describe*"],
>       "Resource": "*"
>     }
>   ]
> }
> ```
>
> Our application only needs to list EC2 instances, RDS databases, and ElastiCache clusters."

---

### Troubleshooting Common Issues

#### Invalid Action Name

> "My policy validation says 's3:Getobject' is invalid. What's the correct action name?"

> "Is 'S3:GetObject' a valid action? The validator is complaining about it."

#### Unknown ARN Format

> "How do I write the ARN for a Secrets Manager secret named 'prod/database/credentials'?"

> "What's the correct ARN format for an API Gateway REST API?"

#### Missing Conditions

> "The validator says I need conditions for iam:PassRole. What conditions should I add and why?"

> "How do I add MFA requirement to sensitive actions in my policy?"

#### Understanding Validation Errors

> "Explain this validation error: 'Action s3:\* grants 150+ permissions including sensitive data access actions'"

> "What does the 'resource_exposure' warning mean and how do I fix it?"

---

### Best Prompts for Generating Secure IAM Policies

These prompts demonstrate how to get the best results when generating IAM policies with the MCP server.

#### Be Specific About Resources

**Good** (includes specific ARNs):

> "Create a policy for a Lambda function to read from S3 bucket `data-lake-prod` prefix `raw/`, write to DynamoDB table `processed-items` in us-east-1 account 123456789012, and log to CloudWatch"

**Less Effective** (vague):

> "Create a policy for Lambda to access S3 and DynamoDB"

#### Specify Access Patterns

**Good** (clear access level):

> "Create a read-only policy for S3 bucket `reports`. The service only needs to list and download objects, never upload or delete."

**Less Effective**:

> "Create an S3 policy"

#### Include Security Requirements

**Good** (explicit security):

> "Create a policy for cross-account access from account 987654321098 to assume role `DataAnalyst`. Requirements:
>
> - Require MFA
> - Limit to our organization (o-abc123)
> - Only allow from specific IP range 10.0.0.0/8"

#### Request Validation

**Good** (asks for validation):

> "Create and validate a policy for ECS tasks to:
>
> - Pull images from ECR repository `my-app`
> - Access Secrets Manager secrets with prefix `my-app/`
> - Write to CloudWatch Logs"

#### Use Templates for Common Patterns

**Good** (leverages templates):

> "List available policy templates and use the `lambda-s3-trigger` template for function `process-uploads` with bucket `incoming-data`"

#### Iterative Refinement

**Good** (asks for improvements):

> "Here's my current policy. Can you:
>
> 1. Validate it for security issues
> 2. Suggest more restrictive resource scopes
> 3. Add any missing security conditions
>
> ```json
> {\"Version\": \"2012-10-17\", \"Statement\": [...]}
> ```

#### Multi-Service Workflows

**Good** (complete context):

> "I'm building a data pipeline that:
>
> 1. Triggers on S3 uploads to `raw-data` bucket
> 2. Processes with Lambda
> 3. Stores results in DynamoDB table `processed`
> 4. Sends notifications to SNS topic `alerts`
> 5. Logs everything to CloudWatch
>
> Create both the trust policy and permissions policy for the Lambda execution role."

---

## Built-in Templates

The MCP server includes 15 secure policy templates:

| Template                    | Description                                             |
| --------------------------- | ------------------------------------------------------- |
| `s3-read-only`              | S3 bucket read-only access                              |
| `s3-read-write`             | S3 bucket read-write access                             |
| `lambda-basic-execution`    | Basic Lambda execution role                             |
| `lambda-s3-trigger`         | Lambda with S3 event trigger                            |
| `dynamodb-crud`             | DynamoDB table CRUD operations                          |
| `cloudwatch-logs`           | CloudWatch Logs write permissions                       |
| `secrets-manager-read`      | Secrets Manager read access                             |
| `kms-encrypt-decrypt`       | KMS key encryption/decryption                           |
| `ec2-describe`              | EC2 describe-only permissions                           |
| `ecs-task-execution`        | ECS task execution role                                 |
| `sqs-consumer`              | SQS queue consumer with receive, delete, and attributes |
| `sns-publisher`             | SNS topic publish permissions                           |
| `step-functions-execution`  | Step Functions state machine execution                  |
| `api-gateway-invoke`        | API Gateway REST API invoke permissions                 |
| `cross-account-assume-role` | Cross-account role assumption with MFA requirement      |

All templates follow security best practices:

- Least-privilege actions
- Scoped resource ARNs
- Required conditions (e.g., `aws:SecureTransport`, MFA requirements)

## MCP Resources

The server also provides static resources that Claude can reference:

| Resource                     | Content                         |
| ---------------------------- | ------------------------------- |
| `iam://templates`            | List of all policy templates    |
| `iam://checks`               | All 19 validation checks        |
| `iam://sensitive-categories` | Sensitive action categories     |
| `iam://org-config-schema`    | Organization config JSON schema |
| `iam://org-config-examples`  | Example organization configs    |
| `iam://workflow-examples`    | Detailed workflow examples      |

## Organization Configuration

Set organization-wide check settings that apply to all policy operations. The configuration uses the same format as the CLI validator:

```yaml
# Example organization config
settings:
  fail_on_severity:
    - error
    - critical
    - high

# Raise severity for wildcard patterns
wildcard_resource:
  severity: critical

service_wildcard:
  severity: critical

# Require conditions for sensitive actions
sensitive_action:
  enabled: true
  severity: high

# Detect dangerous patterns
not_action_not_resource:
  enabled: true
  severity: critical
```

Ask Claude to set this configuration:

> "Set organization config that makes wildcard usage critical severity and enables strict sensitive action checking"

## Custom Instructions

Custom instructions allow organizations to add their own policy generation guidelines that the AI follows when creating or reviewing IAM policies. This is useful for enforcing organization-specific rules, compliance requirements, or naming conventions.

### How Custom Instructions Work

Custom instructions are appended to the default MCP server instructions. When the AI generates or reviews policies, it considers both the built-in security rules and your custom guidelines.

### Setting Custom Instructions

There are five ways to provide custom instructions:

#### 1. CLI Argument (Inline Text)

```bash
iam-validator-mcp --instructions "Always require aws:PrincipalOrgID condition for cross-account access"
```

#### 2. CLI Argument (File)

```bash
iam-validator-mcp --instructions-file /path/to/instructions.md
```

#### 3. Environment Variable

```bash
export IAM_VALIDATOR_MCP_INSTRUCTIONS="All policies must include encryption requirements for S3"
iam-validator-mcp
```

#### 4. YAML Configuration File

Add the `custom_instructions` key to your configuration:

```yaml
# config.yaml
settings:
  fail_on_severity:
    - error
    - critical

custom_instructions: |
  ## Organization-Specific Policy Rules

  - All S3 policies must require aws:SecureTransport
  - Cross-account access must include aws:PrincipalOrgID condition
  - Lambda execution roles must be scoped to specific functions
  - Use resource tags for access control where possible
  - All KMS operations require aws:ViaService condition

wildcard_resource:
  severity: critical
```

Then start the server with:

```bash
iam-validator-mcp --config /path/to/config.yaml
```

#### 5. MCP Tool (Runtime)

Set instructions dynamically during a session:

> "Set custom instructions: All policies for the data-lake project must include the tag condition aws:ResourceTag/Project = data-lake"

### Claude Desktop Configuration with Custom Instructions

=== "macOS"

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "iam-validator-mcp",
          "args": [
            "--config", "/Users/you/config.yaml",
            "--instructions", "Use our org ID o-abc123 in all PrincipalOrgID conditions"
          ]
        }
      }
    }
    ```

=== "Using Instructions File"

    ```json
    {
      "mcpServers": {
        "iam-policy-validator": {
          "command": "iam-validator-mcp",
          "args": [
            "--instructions-file", "/Users/you/.iam-policy-instructions.md"
          ]
        }
      }
    }
    ```

### Example Custom Instructions

#### Enterprise Security Requirements

```markdown
## Enterprise IAM Policy Requirements

### Required Conditions

- All S3 bucket policies must include `aws:SecureTransport: true`
- Cross-account access requires `aws:PrincipalOrgID: o-xxxxxxxxxx`
- iam:PassRole must include `iam:PassedToService` condition
- KMS operations must include `aws:ViaService` condition

### Naming Conventions

- Policy SIDs should follow: `<Action><Resource><Purpose>`
- Example: `S3BucketReadDataLake`, `LambdaInvokeProcessor`

### Restrictions

- Never allow `*` as Principal in resource policies
- Wildcard actions are only allowed for CloudWatch Logs
- Data exfiltration actions (s3:GetObject, dynamodb:Scan) require MFA
```

#### Development Environment

```markdown
## Dev Environment Policy Rules

- Allow broader wildcards for rapid iteration
- S3 buckets can use `dev-*` prefix without strict conditions
- Enable all read actions without MFA requirement
- Tag requirement: aws:ResourceTag/Environment = dev
```

#### Compliance-Focused

```markdown
## SOC 2 Compliance Requirements

- All data access must be logged (enable CloudTrail integration)
- PII data access requires MFA: aws:MultiFactorAuthPresent = true
- S3 buckets with customer data must require encryption
- Cross-region access must be explicitly justified with comments
- Policies must not exceed 90-day access without review
```

### Managing Custom Instructions via MCP

#### Set Instructions During Session

> "Set custom instructions to require that all S3 policies include secure transport conditions"

#### View Current Instructions

> "Show me the current custom instructions"

#### Clear Instructions

> "Clear all custom instructions and use the defaults"

### Priority Order

When multiple instruction sources are provided, they are applied in this priority order (highest to lowest):

1. CLI argument (`--instructions` or `--instructions-file`)
2. YAML configuration file (`custom_instructions` key)
3. Environment variable (`IAM_VALIDATOR_MCP_INSTRUCTIONS`)
4. MCP tool (`set_custom_instructions`) - can override during session

## AI Formatting Instructions

The MCP server provides comprehensive instructions to AI assistants for proper IAM formatting. This ensures Claude and other AI tools generate correctly formatted policies.

### What the AI Learns

**Action Formatting**:

- Service prefix must be lowercase: `s3:GetObject` ✓, `S3:GetObject` ✗
- Action name uses PascalCase: `s3:GetObject` ✓, `s3:getobject` ✗
- Full format: `<service>:<ActionName>` (e.g., `lambda:InvokeFunction`)

**Policy Structure**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "UniqueStatementId",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::my-bucket/*"]
    }
  ]
}
```

**ARN Formatting**:

- S3 buckets: `arn:aws:s3:::<bucket-name>` (no region/account)
- S3 objects: `arn:aws:s3:::<bucket-name>/<key-path>`
- DynamoDB tables: `arn:aws:dynamodb:<region>:<account>:table/<table-name>`
- Lambda functions: `arn:aws:lambda:<region>:<account>:function:<function-name>`

**Condition Operators**:

- String: `StringEquals`, `StringLike`, `StringNotEquals`
- ARN: `ArnEquals`, `ArnLike`
- Boolean: `Bool` (e.g., `aws:SecureTransport`)
- IP: `IpAddress`, `NotIpAddress`
- Set operators: `ForAllValues:StringEquals`, `ForAnyValue:StringEquals`

**Common Mistakes the AI Avoids**:

1. Mixed case service prefix (`S3:` instead of `s3:`)
2. Missing Version field
3. Effect typos (`"allow"` instead of `"Allow"`)
4. Invalid ARN formats
5. Using ARNs in Action field (actions are `service:ActionName`, not ARNs)

## Security Features

The MCP server enforces security best practices:

1. **Blocks dangerous patterns**

   - `Action: "*"` is always blocked
   - `Resource: "*"` with write actions is blocked

2. **Auto-adds conditions**

   - `iam:PassedToService` for `iam:PassRole`
   - `aws:SecureTransport` for S3 operations

3. **Sensitive action tracking**

   - 490+ sensitive actions across 4 categories
   - Automatic warnings and condition recommendations

4. **Validation before output**
   - All generated policies are automatically validated
   - Security notes explain any concerns

## Advanced Features

### Auto-Condition Application

The `build_minimal_policy` tool automatically applies required security conditions for sensitive actions. This ensures generated policies follow AWS best practices without manual intervention.

#### How It Works

When you request a policy with sensitive actions, the tool:

1. Detects sensitive actions that require conditions (e.g., `iam:PassRole`)
2. Automatically adds appropriate condition keys
3. Documents what was added in security notes

#### Example: iam:PassRole with Auto-Conditions

**Request:**

```
Build a policy allowing iam:PassRole for role arn:aws:iam::123456789012:role/LambdaExecutionRole
```

**Generated Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPassRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/LambdaExecutionRole",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "lambda.amazonaws.com"
        }
      }
    }
  ]
}
```

**Security Note:**

```
Auto-applied condition 'iam:PassedToService' for iam:PassRole to restrict
role passing to Lambda service only. This prevents the role from being
passed to unintended services.
```

#### Supported Auto-Conditions

| Action         | Auto-Applied Condition | Purpose                                       |
| -------------- | ---------------------- | --------------------------------------------- |
| `iam:PassRole` | `iam:PassedToService`  | Restricts which AWS services can use the role |

More auto-conditions will be added in future updates based on AWS security best practices.

### Policy Type Auto-Detection

The `validate_policy` tool can automatically detect the policy type based on the policy structure, eliminating the need to manually specify whether it's an identity policy, trust policy, or resource policy.

#### Detection Logic

The tool uses these rules to determine policy type:

1. **Trust Policy**: Contains `sts:AssumeRole` action

   ```json
   {
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": { "Service": "lambda.amazonaws.com" },
         "Action": "sts:AssumeRole"
       }
     ]
   }
   ```

2. **Resource Policy**: Contains `Principal` field (but not `sts:AssumeRole`)

   ```json
   {
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
         "Action": "s3:GetObject",
         "Resource": "*"
       }
     ]
   }
   ```

3. **Identity Policy**: Default for policies without `Principal` field
   ```json
   {
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::my-bucket/*"
       }
     ]
   }
   ```

#### Usage

You can now validate policies without specifying the type:

**Before (manual type specification):**

```
Validate this trust policy: <policy JSON>
```

**Now (auto-detection):**

```
Validate this policy: <policy JSON>
```

The tool will automatically detect it's a trust policy and apply the appropriate validation rules.

#### Manual Override

If you want to force a specific policy type, you can still specify it explicitly:

```
Validate this policy as a resource policy: <policy JSON>
```

### Action Case Normalization

The `fix_policy_issues` tool now automatically normalizes action case formatting to match AWS standards.

#### The Problem

AWS action names must have lowercase service prefixes, but uppercase service prefixes are a common mistake:

```json
{
  "Action": "S3:GetObject" // ❌ Invalid - uppercase prefix
}
```

This causes validation failures because AWS expects:

```json
{
  "Action": "s3:GetObject" // ✓ Valid - lowercase prefix
}
```

#### The Solution

The `fix_policy_issues` tool automatically detects and fixes action case issues:

**Before:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "S3:GetObject",
        "S3:PutObject",
        "Lambda:InvokeFunction",
        "DynamoDB:GetItem"
      ],
      "Resource": "*"
    }
  ]
}
```

**After:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "lambda:InvokeFunction",
        "dynamodb:GetItem"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Usage

Ask Claude to fix action case issues:

```
Fix the action names in this policy:
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "S3:GetObject",
    "Resource": "*"
  }]
}
```

The tool will:

1. Detect invalid action case
2. Normalize to correct format
3. Return the fixed policy
4. Explain what was changed

## Running the Server Manually

For debugging or custom setups:

```bash
# Run with stdio transport (default)
iam-validator-mcp

# Run with config pre-loaded
iam-validator-mcp --config ./config.yaml

# Run with custom instructions inline
iam-validator-mcp --instructions "Require MFA for all sensitive actions"

# Run with custom instructions from file
iam-validator-mcp --instructions-file ./org-instructions.md

# Run with both config and instructions
iam-validator-mcp --config ./config.yaml --instructions-file ./org-instructions.md

# Run via CLI with more options
iam-validator mcp --config ./config.yaml --verbose

# Run with SSE transport (for HTTP clients)
iam-validator mcp --transport sse --host 127.0.0.1 --port 8000
```

### Using uvx (No Installation Required)

Run the MCP server directly from PyPI without installing:

```bash
# Run latest version
uvx --from 'iam-policy-validator[mcp]' iam-validator-mcp

# Run with configuration
uvx --from 'iam-policy-validator[mcp]' iam-validator-mcp --config ./config.yaml

# Pin to a specific version
uvx --from 'iam-policy-validator[mcp]==1.15.2' iam-validator-mcp

# Run with custom instructions
uvx --from 'iam-policy-validator[mcp]' iam-validator-mcp --instructions "Require MFA for all sensitive actions"
```

### CLI Options

| Option                     | Description                                                 |
| -------------------------- | ----------------------------------------------------------- |
| `--config FILE`            | Path to YAML configuration file                             |
| `--instructions TEXT`      | Custom instructions (inline text)                           |
| `--instructions-file FILE` | Path to file containing custom instructions (markdown, txt) |
| `--transport TYPE`         | Transport protocol: `stdio` (default) or `sse`              |
| `--host HOST`              | Host for SSE transport (default: 127.0.0.1)                 |
| `--port PORT`              | Port for SSE transport (default: 8000)                      |
| `--verbose, -v`            | Enable verbose logging                                      |

## Programmatic Usage

While designed for AI assistants, you can also use the MCP tools programmatically:

```python
from iam_validator.mcp.tools.validation import validate_policy
from iam_validator.mcp.tools.generation import build_minimal_policy

# Validate a policy
result = await validate_policy(
    policy={"Version": "2012-10-17", "Statement": [...]},
    policy_type="identity"
)

# Generate a policy
gen_result = await build_minimal_policy(
    actions=["s3:GetObject", "s3:PutObject"],
    resources=["arn:aws:s3:::my-bucket/*"]
)
```

## Troubleshooting

This section covers common issues and their solutions when using the IAM Policy Validator MCP server.

---

### Installation Issues

#### Server Won't Start

**Issue**: `ImportError: fastmcp is required`

**Solution**: Install with MCP extras:

```bash
pip install iam-policy-validator[mcp]
```

Or with uv:

```bash
uv sync --extra mcp
```

#### Command Not Found

**Issue**: `iam-validator-mcp: command not found`

**Solutions**:

1. **Verify installation**:

   ```bash
   pip list | grep iam-policy-validator
   ```

2. **Check if it's in your PATH**:

   ```bash
   which iam-validator-mcp
   ```

3. **Use full path in Claude Desktop config**:

   ```json
   {
     "mcpServers": {
       "iam-policy-validator": {
         "command": "/full/path/to/iam-validator-mcp",
         "args": []
       }
     }
   }
   ```

4. **Alternative: Use iam-validator CLI**:
   ```json
   {
     "mcpServers": {
       "iam-policy-validator": {
         "command": "iam-validator",
         "args": ["mcp"]
       }
     }
   }
   ```

---

### Claude Desktop Configuration Issues

#### MCP Server Not Appearing

**Issue**: MCP server not appearing in Claude Desktop

**Solutions**:

1. **Verify config file location**:

   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. **Check JSON syntax**:

   - Use a JSON validator to ensure the config file is valid
   - Common mistakes: missing commas, trailing commas, unescaped backslashes in Windows paths

3. **Restart Claude Desktop completely**:

   - Quit the application (not just close the window)
   - Wait a few seconds
   - Reopen Claude Desktop

4. **Check Claude Desktop logs** (macOS):

   ```bash
   tail -f ~/Library/Logs/Claude/mcp*.log
   ```

#### Config File Not Loading

**Issue**: Pre-loaded config not being applied

**Solutions**:

1. **Verify file path in config**:

   ```json
   {
     "args": ["--config", "/absolute/path/to/config.yaml"]
   }
   ```

2. **Use absolute paths** (not relative):

   - ❌ `"./config.yaml"`
   - ✓ `"/Users/you/config.yaml"`

3. **Check YAML syntax**:

   ```bash
   python -c "import yaml; yaml.safe_load(open('config.yaml'))"
   ```

4. **Verify file permissions**:

   ```bash
   ls -l config.yaml
   ```

---

### Policy Validation Issues

#### Action Case Sensitivity Errors

**Issue**: `Action 'S3:GetObject' is not valid` or similar validation errors

**Cause**: AWS action names require lowercase service prefixes. Common mistakes:

- `S3:GetObject` → should be `s3:GetObject`
- `Lambda:InvokeFunction` → should be `lambda:InvokeFunction`
- `DynamoDB:GetItem` → should be `dynamodb:GetItem`

**Solutions**:

1. **Use fix_policy_issues tool**:

   ```text
   Fix this policy:
   {
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "S3:GetObject",
         "Resource": "*",
       },
     ],
   }
   ```

2. **Query correct action names**:

   ```text
   What's the correct capitalization for the S3 GetObject action?
   ```

3. **List all actions for a service**:

   ```text
   Show me all S3 actions with correct formatting
   ```

#### Invalid Action Names

**Issue**: `Action 's3:Getobject' is not valid`

**Cause**: Action name part uses incorrect case. AWS uses PascalCase for action names.

**Common Mistakes**:

- `s3:getobject` → should be `s3:GetObject`
- `s3:putobject` → should be `s3:PutObject`
- `lambda:invokefunction` → should be `lambda:InvokeFunction`

**Solutions**:

1. **Query action details**:

   ```text
   What's the correct format for the S3 get object action?
   ```

2. **Expand wildcards to see correct names**:

   ```text
   Expand s3:Get* to show me all the get actions
   ```

3. **Search by keyword**:
   ```text
   Expand s3:Get* to show me all the get actions
   Show me S3 actions related to uploading objects
   ```

#### ARN Format Errors

**Issue**: `Invalid ARN format in Resource field`

**Common ARN Mistakes**:

1. **S3 bucket ARN with region/account**:

   - ❌ `arn:aws:s3:us-east-1:123456789012:my-bucket`
   - ✓ `arn:aws:s3:::my-bucket`

2. **S3 object ARN without bucket**:

   - ❌ `arn:aws:s3:::file.txt`
   - ✓ `arn:aws:s3:::my-bucket/file.txt`

3. **Missing account ID**:

   - ❌ `arn:aws:dynamodb:us-east-1::table/MyTable`
   - ✓ `arn:aws:dynamodb:us-east-1:123456789012:table/MyTable`

4. **Missing region**:
   - ❌ `arn:aws:lambda::123456789012:function:MyFunction`
   - ✓ `arn:aws:lambda:us-east-1:123456789012:function:MyFunction`

**Solutions**:

1. **Query ARN formats**:

   ```text
   What's the correct ARN format for S3 buckets and objects?
   ```

2. **Get service-specific formats**:

   ```text
   Show me the ARN format for DynamoDB tables
   ```

3. **Example request**:

   ```text
   Show me ARN examples for Lambda functions in us-east-1, account 123456789012
   ```

#### Missing Required Conditions

**Issue**: Validation warns about missing conditions for sensitive actions

**Common Examples**:

1. **iam:PassRole without iam:PassedToService**:

   ```json
   {
     "Action": "iam:PassRole",
     "Resource": "arn:aws:iam::123456789012:role/MyRole"
     // Missing Condition
   }
   ```

2. **S3 operations without aws:SecureTransport**:

   ```json
   {
     "Action": "s3:PutObject",
     "Resource": "arn:aws:s3:::my-bucket/*"
     // Missing secure transport requirement
   }
   ```

**Solutions**:

1. **Use build_minimal_policy** (auto-adds conditions):

   ```text
   Build a policy with action iam:PassRole for role arn:aws:iam::123456789012:role/MyRole
   ```

2. **Query required conditions**:

   ```text
   What conditions should I add for iam:PassRole?
   ```

3. **Check sensitive actions**:

   ```text
   Are these actions sensitive: iam:PassRole, s3:PutObject?
   What conditions do they need?
   ```

---

### Policy Type Detection Issues

#### Wrong Policy Type Detected

**Issue**: Auto-detection identifies policy as wrong type

**Cause**: Policy structure is ambiguous or contains mixed elements

**Solutions**:

1. **Specify policy type explicitly**:

   ```text
   Validate this policy as a trust policy:
   <policy JSON>
   ```

2. **Review policy structure**:

   - Trust policies must have `sts:AssumeRole` action
   - Resource policies must have `Principal` field
   - Identity policies have neither

3. **Separate mixed policies**:
   - Don't mix identity and resource policy statements
   - Create separate policies for different policy types

#### Trust Policy Not Detected

**Issue**: Trust policy validated as identity policy

**Cause**: Missing `sts:AssumeRole` action

**Example**:

```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Action": "sts:AssumeRoleWithWebIdentity" // Wrong action
    }
  ]
}
```

**Solution**: Use `sts:AssumeRole` for trust policies:

```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Action": "sts:AssumeRole" // Correct
    }
  ]
}
```

---

### Organization Configuration Issues

#### Validation Fails with Organization Config

**Issue**: Policies fail validation when organization config is active

**Cause**: Organization config has strict check settings

**Solutions**:

1. **View current configuration**:

   ```text
   Show me the current organization configuration
   ```

2. **Check which checks are enabled**:

   ```text
   What validation checks are currently active?
   ```

3. **Temporarily clear configuration** (if appropriate):

   ```text
   Clear all organization restrictions
   ```

4. **Adjust check settings**:

   ```text
   Lower the severity for wildcard_resource check
   ```

#### Check Settings Not Applied

**Issue**: Custom check settings aren't being used during validation

**Cause**: Configuration format may be incorrect

**Solutions**:

1. **Verify YAML format**:

   ```yaml
   # Correct format - check_id at top level
   wildcard_resource:
     severity: critical
   # NOT nested under a "checks" key
   ```

2. **Validate with organization config**:

   ```text
   Check if this policy complies with organization rules:
   <policy JSON>
   ```

3. **Review your configuration structure**:

   ```yaml
   settings:
     fail_on_severity:
       - error
       - critical

   # Check configurations at top level
   wildcard_action:
     enabled: true
     severity: high
   ```

---

### Template Issues

#### Template Not Found

**Issue**: `Template 'xyz' not found`

**Solution**: List available templates:

```text
What policy templates are available?
```

Current templates:

- s3-read-only, s3-read-write
- lambda-basic-execution, lambda-s3-trigger
- dynamodb-crud
- cloudwatch-logs
- secrets-manager-read
- kms-encrypt-decrypt
- ec2-describe
- ecs-task-execution
- sqs-consumer
- sns-publisher
- step-functions-execution
- api-gateway-invoke
- cross-account-assume-role

#### Template Parameters Missing

**Issue**: Template generation fails with "Missing required parameter"

**Solution**: Check template requirements:

```text
Show me the parameters needed for the s3-read-write template
```

Common parameters:

- `bucket_name` - S3 bucket name
- `prefix` - S3 key prefix (optional)
- `table_name` - DynamoDB table name
- `function_name` - Lambda function name
- `topic_arn` - SNS topic ARN
- `queue_url` - SQS queue URL

---

### Performance Issues

#### Slow Validation

**Issue**: Policy validation takes a long time

**Causes and Solutions**:

1. **Large policy (many statements)**:

   - Normal for policies with 50+ statements
   - Consider using `quick_validate` for fast pass/fail checks

2. **Wildcard expansion**:

   - Actions like `s3:*` expand to 150+ specific actions
   - Use more specific wildcards (e.g., `s3:Get*`, `s3:Put*`)

3. **First-time AWS service fetch**:

   - First validation may be slower while fetching AWS service definitions
   - Subsequent validations use cached data (7-day TTL)

4. **Clear cache if stale**:
   ```bash
   iam-validator cache clear
   ```

#### Slow Policy Generation

**Issue**: `build_minimal_policy` takes a long time

**Cause**: Sensitive action checks and condition lookups

**Solutions**:

1. **Use templates for common patterns** (faster):

   ```text
   Generate policy from lambda-basic-execution template
   ```

2. **Reduce action count**:

   - Be specific instead of requesting many actions
   - Use templates and modify as needed

3. **Pre-load config**:
   - Avoids repeated config operations
   - Start server with `--config` flag

---

### Common Prompt Issues

#### AI Doesn't Use Tools

**Issue**: Claude doesn't call MCP tools, just describes them

**Cause**: Ambiguous or conversational request

**Solutions**:

1. **Be explicit about validation**:

   - ❌ "What do you think of this policy?"
   - ✓ "Validate this policy: <JSON>"

2. **Request specific tools**:

   - ❌ "Tell me about S3 actions"
   - ✓ "Show me all S3 actions" (calls `query_service_actions`)

3. **Include policy JSON**:
   - ❌ "Check my S3 policy"
   - ✓ "Validate this S3 policy: {JSON}"

#### Incomplete Generated Policies

**Issue**: Generated policy is missing expected elements

**Causes and Solutions**:

1. **Vague requirements**:

   - ❌ "Create an S3 policy"
   - ✓ "Create a policy allowing read-write access to S3 bucket my-bucket"

2. **Missing resource details**:

   - ❌ "Allow Lambda to read from S3"
   - ✓ "Allow Lambda to read from S3 bucket data-bucket, prefix incoming/"

3. **No account/region specified**:
   - ❌ "Allow DynamoDB access"
   - ✓ "Allow DynamoDB access to table my-table in us-east-1, account 123456789012"

---

### Getting Help

If you encounter issues not covered here:

1. **Check validation output** - Error messages often include fix suggestions

2. **Query AWS service definitions**:

   ```text
   Tell me about the s3:PutObject action
   What ARN formats does S3 use?
   ```

3. **Use fix tools**:

   ```text
   Fix this policy automatically: <JSON>
   ```

4. **Get issue guidance**:

   ```text
   Help me fix the 'wildcard_action' validation error
   ```

5. **File an issue**:
   - GitHub: [iam-policy-auditor/issues](https://github.com/bogdanbrudiu/iam-policy-auditor/issues)
   - Include: Policy JSON, error message, expected behavior

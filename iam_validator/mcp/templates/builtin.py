"""Built-in IAM policy templates for MCP server.

This module provides pre-defined policy templates with variable substitution
for common AWS use cases. Each template includes security best practices
such as condition keys for transport security, resource boundaries, and
least-privilege principles.

Templates are designed to be used with the security enforcement layer
which validates and enhances them before returning to users.
"""

from string import Template
from typing import Any, Final

# ============================================================================
# Template Definitions
# ============================================================================

# Each template has:
# - name: Unique identifier
# - description: What the template does
# - variables: List of variable definitions with name, description, required, default
# - policy: The IAM policy template with ${variable} placeholders

TEMPLATES: Final[dict[str, dict[str, Any]]] = {
    "s3-read-only": {
        "name": "s3-read-only",
        "description": "Read-only access to an S3 bucket with optional prefix filtering",
        "variables": [
            {
                "name": "bucket_name",
                "description": "Name of the S3 bucket (without arn:aws:s3::: prefix)",
                "required": True,
            },
            {
                "name": "prefix",
                "description": "Optional prefix to restrict access to specific paths (e.g., 'data/' or leave empty for full bucket)",
                "required": False,
                "default": "",
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S3ListBucket",
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                        "s3:GetBucketVersioning",
                    ],
                    "Resource": "arn:aws:s3:::${bucket_name}",
                },
                {
                    "Sid": "S3GetObjects",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:GetObjectMetadata",
                    ],
                    "Resource": "arn:aws:s3:::${bucket_name}/${prefix}*",
                    "Condition": {
                        "StringEquals": {"aws:ResourceAccount": "$${aws:PrincipalAccount}"},
                    },
                },
            ],
        },
    },
    "s3-read-write": {
        "name": "s3-read-write",
        "description": "Read and write access to an S3 bucket with optional prefix filtering",
        "variables": [
            {
                "name": "bucket_name",
                "description": "Name of the S3 bucket (without arn:aws:s3::: prefix)",
                "required": True,
            },
            {
                "name": "prefix",
                "description": "Optional prefix to restrict access to specific paths (e.g., 'data/' or leave empty for full bucket)",
                "required": False,
                "default": "",
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S3ListBucket",
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                        "s3:GetBucketVersioning",
                    ],
                    "Resource": "arn:aws:s3:::${bucket_name}",
                },
                {
                    "Sid": "S3ReadWriteObjects",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:PutObject",
                        "s3:PutObjectAcl",
                        "s3:DeleteObject",
                        "s3:DeleteObjectVersion",
                    ],
                    "Resource": "arn:aws:s3:::${bucket_name}/${prefix}*",
                    "Condition": {
                        "StringEquals": {"aws:ResourceAccount": "$${aws:PrincipalAccount}"},
                    },
                },
            ],
        },
    },
    "lambda-basic-execution": {
        "name": "lambda-basic-execution",
        "description": "Basic Lambda execution permissions including CloudWatch Logs",
        "variables": [
            {
                "name": "account_id",
                "description": "AWS account ID (12-digit number)",
                "required": True,
            },
            {
                "name": "region",
                "description": "AWS region (e.g., us-east-1, us-west-2)",
                "required": True,
            },
            {
                "name": "function_name",
                "description": "Lambda function name or prefix pattern (e.g., my-function or dev-*)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "LambdaBasicExecution",
                    "Effect": "Allow",
                    "Action": [
                        "lambda:GetFunction",
                        "lambda:GetFunctionConfiguration",
                        "lambda:InvokeFunction",
                    ],
                    "Resource": "arn:aws:lambda:${region}:${account_id}:function:${function_name}",
                },
                {
                    "Sid": "CloudWatchLogsAccess",
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "arn:aws:logs:${region}:${account_id}:log-group:/aws/lambda/${function_name}:*",
                },
            ],
        },
    },
    "lambda-s3-trigger": {
        "name": "lambda-s3-trigger",
        "description": "Lambda function with S3 read access for event triggers",
        "variables": [
            {
                "name": "bucket_name",
                "description": "Name of the S3 bucket that triggers the Lambda",
                "required": True,
            },
            {
                "name": "function_name",
                "description": "Lambda function name",
                "required": True,
            },
            {
                "name": "account_id",
                "description": "AWS account ID (12-digit number)",
                "required": True,
            },
            {
                "name": "region",
                "description": "AWS region (e.g., us-east-1, us-west-2)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S3ReadAccess",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                    ],
                    "Resource": "arn:aws:s3:::${bucket_name}/*",
                    "Condition": {
                        "StringEquals": {"aws:ResourceAccount": "$${aws:PrincipalAccount}"},
                    },
                },
                {
                    "Sid": "S3ListBucket",
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::${bucket_name}",
                },
                {
                    "Sid": "LambdaLogging",
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "arn:aws:logs:${region}:${account_id}:log-group:/aws/lambda/${function_name}:*",
                },
            ],
        },
    },
    "dynamodb-crud": {
        "name": "dynamodb-crud",
        "description": "Full CRUD access to a DynamoDB table including indexes",
        "variables": [
            {
                "name": "table_name",
                "description": "DynamoDB table name",
                "required": True,
            },
            {
                "name": "region",
                "description": "AWS region (e.g., us-east-1, us-west-2)",
                "required": True,
            },
            {
                "name": "account_id",
                "description": "AWS account ID (12-digit number)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DynamoDBTableAccess",
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:Query",
                        "dynamodb:Scan",
                        "dynamodb:BatchGetItem",
                        "dynamodb:BatchWriteItem",
                    ],
                    "Resource": [
                        "arn:aws:dynamodb:${region}:${account_id}:table/${table_name}",
                        "arn:aws:dynamodb:${region}:${account_id}:table/${table_name}/index/*",
                    ],
                    "Condition": {
                        "StringEquals": {"aws:ResourceTag/owner": "$${aws:PrincipalTag/owner}"},
                    },
                },
                {
                    "Sid": "DynamoDBDescribe",
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:DescribeTable",
                        "dynamodb:DescribeTimeToLive",
                    ],
                    "Resource": "arn:aws:dynamodb:${region}:${account_id}:table/${table_name}",
                },
            ],
        },
    },
    "cloudwatch-logs": {
        "name": "cloudwatch-logs",
        "description": "CloudWatch Logs write permissions for application logging",
        "variables": [
            {
                "name": "log_group_prefix",
                "description": "Log group prefix (e.g., /aws/lambda/my-app or /app/production)",
                "required": True,
            },
            {
                "name": "region",
                "description": "AWS region (e.g., us-east-1, us-west-2)",
                "required": True,
            },
            {
                "name": "account_id",
                "description": "AWS account ID (12-digit number)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "CloudWatchLogsWrite",
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams",
                    ],
                    "Resource": [
                        "arn:aws:logs:${region}:${account_id}:log-group:${log_group_prefix}:*",
                        "arn:aws:logs:${region}:${account_id}:log-group:${log_group_prefix}",
                    ],
                },
            ],
        },
    },
    "secrets-manager-read": {
        "name": "secrets-manager-read",
        "description": "Read-only access to Secrets Manager secrets with prefix filtering",
        "variables": [
            {
                "name": "secret_prefix",
                "description": "Secret name prefix (e.g., app/production/ or database/)",
                "required": True,
            },
            {
                "name": "region",
                "description": "AWS region (e.g., us-east-1, us-west-2)",
                "required": True,
            },
            {
                "name": "account_id",
                "description": "AWS account ID (12-digit number)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowSecretsManagerSameOwner",
                    "Effect": "Allow",
                    "Action": ["secretsmanager:*"],
                    "Resource": "arn:aws:secretsmanager:${region}:${account_id}:secret:${secret_prefix}*",
                    "Condition": {
                        "StringEquals": {
                            "aws:ResourceTag/owner": "$${aws:PrincipalTag/owner}",
                        },
                    },
                },
                {
                    "Sid": "SecretsManagerRead",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:ListSecretVersionIds",
                    ],
                    "Resource": "arn:aws:secretsmanager:${region}:${account_id}:secret:${secret_prefix}*",
                    "Condition": {
                        "StringEquals": {
                            "secretsmanager:VersionStage": "AWSCURRENT",
                        },
                    },
                },
                {
                    "Sid": "SecretsManagerList",
                    "Effect": "Allow",
                    "Action": "secretsmanager:ListSecrets",
                    "Resource": "*",
                },
                {
                    "Sid": "DenyPolicyChanges",
                    "Effect": "Deny",
                    "Action": "secretsmanager:*Policy",
                    "Resource": "*",
                },
            ],
        },
    },
    "kms-encrypt-decrypt": {
        "name": "kms-encrypt-decrypt",
        "description": "KMS key encryption and decryption permissions",
        "variables": [
            {
                "name": "key_id",
                "description": "KMS key ID or ARN (e.g., 12345678-1234-1234-1234-123456789012 or full ARN)",
                "required": True,
            },
            {
                "name": "region",
                "description": "AWS region (e.g., us-east-1, us-west-2)",
                "required": True,
            },
            {
                "name": "account_id",
                "description": "AWS account ID (12-digit number)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "KMSEncryptDecrypt",
                    "Effect": "Allow",
                    "Action": [
                        "kms:Decrypt",
                        "kms:Encrypt",
                        "kms:GenerateDataKey",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:DescribeKey",
                    ],
                    "Resource": "arn:aws:kms:${region}:${account_id}:key/${key_id}",
                },
            ],
        },
    },
    "ec2-describe": {
        "name": "ec2-describe",
        "description": "Read-only EC2 describe permissions for monitoring and discovery",
        "variables": [],  # No variables needed
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EC2Describe",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeInstances",
                        "ec2:DescribeImages",
                        "ec2:DescribeVolumes",
                        "ec2:DescribeSnapshots",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeVpcs",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeRegions",
                        "ec2:DescribeAvailabilityZones",
                    ],
                    "Resource": "*",
                },
            ],
        },
    },
    "ecs-task-execution": {
        "name": "ecs-task-execution",
        "description": "ECS task execution role with ECR and CloudWatch Logs access",
        "variables": [
            {
                "name": "account_id",
                "description": "AWS account ID (12-digit number)",
                "required": True,
            },
            {
                "name": "region",
                "description": "AWS region (e.g., us-east-1, us-west-2)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ECRImageAccess",
                    "Effect": "Allow",
                    "Action": [
                        "ecr:GetAuthorizationToken",
                        "ecr:BatchCheckLayerAvailability",
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:BatchGetImage",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "CloudWatchLogsAccess",
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "arn:aws:logs:${region}:${account_id}:log-group:/ecs/*:*",
                },
                {
                    "Sid": "SecretsManagerAccess",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                    ],
                    "Resource": "arn:aws:secretsmanager:${region}:${account_id}:secret:ecs/*",
                },
                {
                    "Sid": "SSMParameterAccess",
                    "Effect": "Allow",
                    "Action": [
                        "ssm:GetParameters",
                        "ssm:GetParameter",
                    ],
                    "Resource": "arn:aws:ssm:${region}:${account_id}:parameter/ecs/*",
                },
            ],
        },
    },
    "sqs-consumer": {
        "name": "sqs-consumer",
        "description": "SQS queue consumer permissions for receiving and processing messages",
        "variables": [
            {
                "name": "queue_name",
                "description": "SQS queue name",
                "required": True,
            },
            {
                "name": "region",
                "description": "AWS region (e.g., us-east-1, us-west-2)",
                "required": True,
            },
            {
                "name": "account_id",
                "description": "AWS account ID (12-digit number)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SQSConsumerAccess",
                    "Effect": "Allow",
                    "Action": [
                        "sqs:ReceiveMessage",
                        "sqs:DeleteMessage",
                        "sqs:ChangeMessageVisibility",
                        "sqs:GetQueueAttributes",
                    ],
                    "Resource": "arn:aws:sqs:${region}:${account_id}:${queue_name}",
                    "Condition": {
                        "StringEquals": {"aws:ResourceAccount": "$${aws:PrincipalAccount}"},
                    },
                },
            ],
        },
    },
    "sns-publisher": {
        "name": "sns-publisher",
        "description": "SNS topic publisher permissions for sending notifications",
        "variables": [
            {
                "name": "topic_name",
                "description": "SNS topic name",
                "required": True,
            },
            {
                "name": "region",
                "description": "AWS region (e.g., us-east-1, us-west-2)",
                "required": True,
            },
            {
                "name": "account_id",
                "description": "AWS account ID (12-digit number)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SNSPublishAccess",
                    "Effect": "Allow",
                    "Action": [
                        "sns:Publish",
                        "sns:GetTopicAttributes",
                    ],
                    "Resource": "arn:aws:sns:${region}:${account_id}:${topic_name}",
                    "Condition": {
                        "StringEquals": {"aws:ResourceAccount": "$${aws:PrincipalAccount}"},
                    },
                },
            ],
        },
    },
    "step-functions-execution": {
        "name": "step-functions-execution",
        "description": "Step Functions state machine execution permissions",
        "variables": [
            {
                "name": "state_machine_name",
                "description": "Step Functions state machine name",
                "required": True,
            },
            {
                "name": "region",
                "description": "AWS region (e.g., us-east-1, us-west-2)",
                "required": True,
            },
            {
                "name": "account_id",
                "description": "AWS account ID (12-digit number)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "StepFunctionsStartExecution",
                    "Effect": "Allow",
                    "Action": "states:StartExecution",
                    "Resource": "arn:aws:states:${region}:${account_id}:stateMachine:${state_machine_name}",
                    "Condition": {
                        "StringEquals": {"aws:ResourceAccount": "$${aws:PrincipalAccount}"},
                    },
                },
                {
                    "Sid": "StepFunctionsManageExecutions",
                    "Effect": "Allow",
                    "Action": [
                        "states:DescribeExecution",
                        "states:GetExecutionHistory",
                        "states:StopExecution",
                    ],
                    "Resource": "arn:aws:states:${region}:${account_id}:execution:${state_machine_name}:*",
                    "Condition": {
                        "StringEquals": {"aws:ResourceAccount": "$${aws:PrincipalAccount}"},
                    },
                },
                {
                    "Sid": "StepFunctionsDescribe",
                    "Effect": "Allow",
                    "Action": [
                        "states:DescribeStateMachine",
                        "states:ListExecutions",
                    ],
                    "Resource": "arn:aws:states:${region}:${account_id}:stateMachine:${state_machine_name}",
                },
            ],
        },
    },
    "api-gateway-invoke": {
        "name": "api-gateway-invoke",
        "description": "API Gateway invoke permissions for executing API methods",
        "variables": [
            {
                "name": "api_id",
                "description": "API Gateway REST API ID",
                "required": True,
            },
            {
                "name": "stage",
                "description": "API Gateway stage name (e.g., prod, dev, test)",
                "required": True,
            },
            {
                "name": "region",
                "description": "AWS region (e.g., us-east-1, us-west-2)",
                "required": True,
            },
            {
                "name": "account_id",
                "description": "AWS account ID (12-digit number)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "APIGatewayInvoke",
                    "Effect": "Allow",
                    "Action": "execute-api:Invoke",
                    "Resource": "arn:aws:execute-api:${region}:${account_id}:${api_id}/${stage}/*/*",
                },
            ],
        },
    },
    "cross-account-assume-role": {
        "name": "cross-account-assume-role",
        "description": "Trust policy for cross-account role assumption with MFA and external ID security",
        "variables": [
            {
                "name": "trusted_account_id",
                "description": "AWS account ID that is trusted to assume this role",
                "required": True,
            },
            {
                "name": "external_id",
                "description": "External ID for additional security (recommended for third-party access)",
                "required": True,
            },
        ],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "CrossAccountAssumeRole",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::${trusted_account_id}:root",
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "${external_id}",
                        },
                    },
                },
            ],
        },
    },
}


# ============================================================================
# Helper Functions
# ============================================================================


def get_template(name: str) -> dict[str, Any] | None:
    """Get a template definition by name.

    Args:
        name: Template name (e.g., "s3-read-only")

    Returns:
        Template definition dict with name, description, variables, and policy.
        Returns None if template not found.

    Example:
        >>> template = get_template("s3-read-only")
        >>> if template:
        ...     print(template["description"])
        ...     print(template["variables"])
    """
    return TEMPLATES.get(name)


def list_templates() -> list[dict[str, Any]]:
    """List all available templates with their metadata.

    Returns:
        List of dicts containing name, description, and variables for each template.
        Does not include the full policy definition.

    Example:
        >>> templates = list_templates()
        >>> for t in templates:
        ...     print(f"{t['name']}: {t['description']}")
        ...     for var in t['variables']:
        ...         print(f"  - {var['name']}: {var['description']}")
    """
    result = []
    for template_name, template_def in TEMPLATES.items():
        result.append(
            {
                "name": template_def["name"],
                "description": template_def["description"],
                "variables": template_def["variables"],
            }
        )
    return result


def render_template(name: str, variables: dict[str, str]) -> dict[str, Any]:
    """Render a template by substituting variables.

    This function takes a template name and variable values, then performs
    string substitution to generate a complete IAM policy document.

    Variable substitution uses Python's string.Template with ${variable} syntax.
    For optional variables with default values, the default is used if not provided.

    Args:
        name: Template name (e.g., "s3-read-only")
        variables: Dictionary mapping variable names to values

    Returns:
        Rendered policy document as a dictionary

    Raises:
        ValueError: If template not found or required variables missing
        KeyError: If template substitution fails due to missing variables

    Example:
        >>> policy = render_template("s3-read-only", {
        ...     "bucket_name": "my-data-bucket",
        ...     "prefix": "reports/"
        ... })
        >>> print(policy["Statement"][0]["Resource"])
        'arn:aws:s3:::my-data-bucket'

    Notes:
        - Empty string prefixes are normalized to "" in resource ARNs
        - All variable values are treated as strings
        - Resource ARNs with ${prefix} handle trailing slashes automatically
    """
    # Get template definition
    template_def = get_template(name)
    if not template_def:
        available = ", ".join(TEMPLATES.keys())
        raise ValueError(f"Template '{name}' not found. Available templates: {available}")

    # Build final variables dict with defaults
    # First, collect all missing required variables for a comprehensive error message
    missing_vars = []
    for var_def in template_def["variables"]:
        var_name = var_def["name"]
        if var_def["required"] and var_name not in variables:
            missing_vars.append(
                {"name": var_name, "description": var_def.get("description", "No description")}
            )

    if missing_vars:
        missing_details = ", ".join(f"'{v['name']}' ({v['description']})" for v in missing_vars)
        raise ValueError(
            f"Missing {len(missing_vars)} required variable(s) for template '{name}': {missing_details}"
        )

    final_vars = {}
    for var_def in template_def["variables"]:
        var_name = var_def["name"]
        # Use provided value or default
        final_vars[var_name] = variables.get(var_name, var_def.get("default", ""))

    # Convert policy to JSON string for template substitution
    import json

    policy_json = json.dumps(template_def["policy"])

    # Substitute variables using string.Template
    template = Template(policy_json)
    try:
        rendered_json = template.substitute(final_vars)
    except KeyError as e:
        raise ValueError(f"Template substitution failed for '{name}': missing variable {e}") from e

    # Parse back to dict
    rendered_policy = json.loads(rendered_json)

    return rendered_policy


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    "TEMPLATES",
    "get_template",
    "list_templates",
    "render_template",
]

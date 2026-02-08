---
description: Generate an IAM policy from a template or description
---

You are generating an IAM policy using the IAM Policy Validator's generation tools.

Given the argument: $ARGUMENTS

## Steps

1. **Determine generation method**:

   - If argument matches a template name → use template
   - If argument is a description → build minimal policy
   - If no argument → list available templates

2. **List available templates** (if needed):

   ```bash
   uv run --extra mcp python -c "
   import asyncio
   from iam_validator.mcp.tools.generation import list_templates

   async def main():
       result = await list_templates()
       for t in result.get('templates', []):
           print(f\"  {t['name']}: {t['description']}\")

   asyncio.run(main())
   "
   ```

3. **Generate from template**:

   ```bash
   uv run --extra mcp python -c "
   import asyncio
   import json
   from iam_validator.mcp.tools.generation import generate_policy_from_template

   async def main():
       result = await generate_policy_from_template(
           template_name='TEMPLATE_NAME',
           variables={'bucket_name': 'my-bucket', 'account_id': '123456789012', 'region': 'us-east-1'}
       )
       if hasattr(result, 'policy'):
           print(json.dumps(result.policy, indent=2))
       else:
           print(json.dumps(result.get('policy', result), indent=2))

   asyncio.run(main())
   "
   ```

4. **Build minimal policy from actions**:

   ```bash
   uv run --extra mcp python -c "
   import asyncio
   import json
   from iam_validator.mcp.tools.generation import build_minimal_policy

   async def main():
       result = await build_minimal_policy(
           actions=['s3:GetObject', 's3:PutObject'],
           resources=['arn:aws:s3:::my-bucket/*']
       )
       if hasattr(result, 'policy'):
           print(json.dumps(result.policy, indent=2))
       else:
           print(json.dumps(result.get('policy', result), indent=2))

   asyncio.run(main())
   "
   ```

5. **Validate the generated policy**:

   ```bash
   uv run --extra mcp python -c "
   import asyncio
   from iam_validator.mcp.tools.validation import validate_policy

   policy = { ... }  # Generated policy

   async def main():
       result = await validate_policy(policy=policy)
       print(f'Valid: {result.is_valid}')
       for issue in result.issues:
           print(f'  [{issue.severity}] {issue.message}')

   asyncio.run(main())
   "
   ```

6. **Output the final policy**:
   - Show the generated policy
   - Show validation results
   - Suggest improvements if any issues found

## Available Templates

- s3-read-only, s3-read-write
- lambda-basic-execution, lambda-s3-trigger
- dynamodb-crud
- cloudwatch-logs
- secrets-manager-read
- kms-encrypt-decrypt
- ec2-describe
- ecs-task-execution
- sqs-consumer, sns-publisher
- step-functions-execution
- api-gateway-invoke
- cross-account-assume-role

## Example Usage

- `/generate-policy s3-read-only bucket_name=my-bucket`
- `/generate-policy lambda-basic-execution account_id=123456789012 region=us-east-1 function_name=my-func`
- `/generate-policy "read S3 bucket and write to DynamoDB"`

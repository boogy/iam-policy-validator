---
description: Debug a specific check with verbose output
---

You are debugging an IAM policy validation check.

Given the check name argument: $ARGUMENTS

## Steps

1. **Find the check**:

   ```bash
   rg -n "check_id.*=.*\"$ARGUMENTS\"" iam_validator/checks/
   ```

2. **Read the check implementation**:

   - Open the check file
   - Understand the validation logic
   - Identify what conditions trigger issues

3. **Find related tests**:

   ```bash
   rg -l "$ARGUMENTS" tests/checks/
   ```

4. **Create a debug test policy**:

   - Create a minimal policy that should trigger the check
   - Save to `/tmp/debug-policy.json`

5. **Run the validator with verbose output**:

   ```bash
   uv run iam-validator validate --path /tmp/debug-policy.json --format json 2>&1 | head -100
   ```

6. **Run specific test with verbose output**:

   ```bash
   uv run pytest tests/checks/test_${ARGUMENTS}_check.py -v --tb=long -s 2>&1 | head -150
   ```

7. **If MCP is involved, test via MCP**:

   ```bash
   uv run --extra mcp python -c "
   import asyncio
   import json
   from iam_validator.mcp.tools.validation import validate_policy

   policy = {
       'Version': '2012-10-17',
       'Statement': [{
           'Effect': 'Allow',
           'Action': '*',
           'Resource': '*'
       }]
   }

   async def main():
       result = await validate_policy(policy=policy)
       print(f'Valid: {result.is_valid}')
       for issue in result.issues:
           if '${ARGUMENTS}' in issue.check_id:
               print(f'  [{issue.severity}] {issue.check_id}: {issue.message}')

   asyncio.run(main())
   "
   ```

8. **Provide analysis**:
   - What the check validates
   - Why it triggers (or doesn't trigger)
   - Suggested fixes if there's a bug

## Example Usage

- `/debug-check wildcard_action`
- `/debug-check sensitive_action`
- `/debug-check action_condition_enforcement`

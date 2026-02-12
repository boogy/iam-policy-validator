---
description: Validate a policy file with the IAM validator
---

You are running the IAM Policy Validator on a policy file.

Given the file path argument: $ARGUMENTS

Steps:

1. **Validate the path exists**:

   - Check if the file/directory exists
   - If no argument provided, ask for the policy file path

2. **Run the validator**:

   ```bash
   uv run iam-validator validate --path "$ARGUMENTS"
   ```

3. **If validation fails with issues**:

   - Summarize the issues found
   - Group by severity (critical, high, medium, low)
   - Offer to help fix specific issues

4. **Common options to suggest**:
   - `--config config.yaml` - Use custom configuration
   - `--format json` - JSON output for parsing
   - `--policy-type RESOURCE_POLICY` - For resource policies
   - `--fail-on-warnings` - Treat warnings as errors

Example usage:

- `/run-check examples/iam-test-policies/identity-policies/insecure_policy.json`
- `/run-check ./policies/`

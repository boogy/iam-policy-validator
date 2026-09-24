"""Declarative MCP prompt specs, gated the same way tools are."""

from iam_validator.mcp.component_spec import PromptSpec


def generate_secure_policy(
    service: str,
    operations: str,
    resources: str,
    principal_type: str = "Lambda function",
) -> str:
    """Generate a secure IAM policy with proper validation.

    This prompt guides you through creating a least-privilege IAM policy
    that passes all critical validation checks.

    Args:
        service: AWS service (e.g., "s3", "dynamodb", "lambda")
        operations: What operations are needed (e.g., "read objects", "write items")
        resources: Specific resources (e.g., "bucket my-app-data", "table users")
        principal_type: Who needs access (e.g., "Lambda function", "EC2 instance")
    """
    return f"""Generate a secure IAM policy for the following requirement:

**Service**: {service}
**Operations needed**: {operations}
**Resources**: {resources}
**Principal**: {principal_type}

## WORKFLOW (Follow these steps in order):

### Step 1: Ground the Policy in Live AWS Data
1. Call `query(kind="service_actions", service="{service}")` to find exact action names.
2. Call `query(kind="arn_formats", service="{service}")` to get correct ARN patterns.
3. Draft the least-privilege policy JSON using only actions and ARN shapes confirmed
   by Step 1.

### Step 2: Validate
Call `validate_policies` on the drafted policy.

### Step 3: Fix Only BLOCKING Issues
BLOCKING issues (MUST fix): severity = "error" or "critical"
- Use the `example` field from the issue - it shows the exact fix
- Apply the fix directly

NON-BLOCKING issues (present with warnings): severity = "high", "medium", "low", "warning"
- Do NOT try to fix these automatically
- Present them to the user as security recommendations

### Step 4: Re-validate (only if you changed the policy in Step 3)
Call `validate_policies` again to confirm the blocking issues are resolved.

### Step 5: Present the Policy
Show the final policy with:
1. The complete JSON policy
2. Any non-blocking warnings as "Security Considerations"
3. Explanation of what permissions are granted

⚠️ IMPORTANT: Do NOT call `validate_policies` more than twice. Do NOT loop trying to
fix warnings.
"""


def fix_policy_issues_workflow(policy_json: str, issues_description: str) -> str:
    """Systematic workflow to fix IAM policy validation issues.

    Use this prompt when you have a policy with validation issues and need
    to fix them systematically without getting into a loop.

    Args:
        policy_json: The IAM policy JSON that has issues
        issues_description: Description of the issues found (from validate_policies)
    """
    return f"""Fix the following IAM policy issues systematically:

**Current Policy**:
```json
{policy_json}
```

**Issues Found**:
{issues_description}

## FIX WORKFLOW (Maximum 2 iterations):

### Iteration 1: Fix All BLOCKING Issues
For each issue with severity "error" or "critical":
1. Read the `example` field - it shows exactly how to fix it
2. Apply the fix directly to the policy JSON (e.g. correct `Version`, `Effect`
   casing, narrow a wildcard action/resource, add a missing condition)

### After Fixing:
Call `validate_policies` ONE more time to verify blocking issues are resolved.

### Iteration 2 (only if needed):
If new "error" or "critical" issues appeared, fix those.
If only "high/medium/low/warning" issues remain, STOP fixing.

## STOP CONDITIONS (Present policy when ANY is true):
✅ No "error" or "critical" issues remain
✅ You've done 2 fix iterations
✅ Remaining issues are "high", "medium", "low", or "warning" severity
✅ Issues require user input (e.g., "specify resource ARN")

## Final Output:
Present the policy with:
1. The fixed JSON
2. List of remaining warnings (if any) as "Security Recommendations"
3. Note: "These recommendations are informational. The policy is valid for AWS."

⚠️ DO NOT keep iterating to eliminate warnings - they are advisory only.
"""


def review_policy_security(policy_json: str) -> str:
    """Review an existing IAM policy for security issues.

    Use this prompt to analyze a policy the user provides and give
    security recommendations without modifying it.

    Args:
        policy_json: The IAM policy JSON to review
    """
    return f"""Review this IAM policy for security issues:

```json
{policy_json}
```

## REVIEW WORKFLOW:

### Step 1: Validate
Call `validate_policies` (`detail="full"` for complete issue context) with the
policy above.

### Step 2: Check Action Sensitivity
Call `query(kind="action_details", actions=[...])` with the policy's actions.
Each result's `sensitive` field, where present, names the risk category and
severity for that action.

### Step 3: Analyze Results
Categorize issues by severity:
- 🔴 CRITICAL/ERROR: Must be fixed before deployment
- 🟠 HIGH: Strong recommendation to address
- 🟡 MEDIUM/WARNING: Best practice suggestions
- 🟢 LOW: Minor improvements

### Step 4: Present Findings
Format your response as:

**Policy Status**: [VALID / HAS BLOCKING ISSUES]

**Critical Issues** (must fix):
- [List any error/critical issues with the fix from the `example` field]

**Security Recommendations** (should consider):
- [List high/medium issues with explanations]

**Sensitive Actions Detected**:
- [List any actions with a `sensitive` classification and their risk category]

**Overall Assessment**:
[Brief summary of the policy's security posture]

⚠️ Do NOT attempt to fix the policy unless the user asks. Just report findings.
"""


PROMPTS: list[PromptSpec] = [
    PromptSpec(
        tag="validate",
        name="generate_secure_policy",
        fn=generate_secure_policy,
    ),
    PromptSpec(
        tag="fix",
        name="fix_policy_issues_workflow",
        fn=fix_policy_issues_workflow,
    ),
    PromptSpec(
        tag="validate",
        name="review_policy_security",
        fn=review_policy_security,
    ),
]

__all__ = ["PROMPTS"]

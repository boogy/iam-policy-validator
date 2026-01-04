"""FastMCP server implementation for IAM Policy Validator.

This module creates and configures the MCP server with all validation,
generation, and query tools registered. It serves as the main entry point
for the MCP server functionality.

Optimizations:
- Shared AWSServiceFetcher instance via lifespan context
- Cached check registry for repeated list_checks calls
- Pagination support for large result sets
- Batch operation tools for reduced round-trips
- MCP Resources for static data (templates, checks)
"""

import functools
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastmcp import Context, FastMCP

from iam_validator.core.aws_service import AWSServiceFetcher

logger = logging.getLogger(__name__)

# =============================================================================
# Lifespan Management - Shared Resources
# =============================================================================


@asynccontextmanager
async def server_lifespan(_server: FastMCP):
    """Manage server lifecycle with shared resources.

    This context manager initializes expensive resources once at startup
    and shares them across all tool invocations via the Context object.
    """
    # Initialize shared AWSServiceFetcher
    fetcher = AWSServiceFetcher(
        prefetch_common=True,  # Pre-fetch common services at startup
        memory_cache_size=512,  # Larger cache for server use
    )
    await fetcher.__aenter__()

    try:
        # Store fetcher in server context for tools to access
        yield {"fetcher": fetcher}
    finally:
        # Cleanup on shutdown
        await fetcher.__aexit__(None, None, None)


def get_shared_fetcher(ctx: Any) -> AWSServiceFetcher | None:
    """Get the shared AWSServiceFetcher from context.

    Args:
        ctx: FastMCP Context object from tool invocation

    Returns:
        Shared AWSServiceFetcher instance, or None if not available

    Note:
        When None is returned, callers typically create a new fetcher instance.
        This is logged as a warning since it may lead to:
        - Redundant HTTP connections
        - Cache misses (new fetcher has empty cache)
        - Potential performance degradation
    """
    if ctx and hasattr(ctx, "request_context") and ctx.request_context:
        lifespan_ctx = ctx.request_context.lifespan_context
        if lifespan_ctx and "fetcher" in lifespan_ctx:
            return lifespan_ctx["fetcher"]

    logger.warning(
        "Shared fetcher unavailable from context. "
        "A new fetcher instance will be created, which may impact performance."
    )
    return None


# =============================================================================
# Cached Registry for list_checks
# =============================================================================


@functools.lru_cache(maxsize=1)
def _get_cached_checks() -> tuple[dict[str, Any], ...]:
    """Get cached check registry (initialized once, thread-safe via lru_cache)."""
    from iam_validator.core.check_registry import create_default_registry

    registry = create_default_registry()
    return tuple(
        sorted(
            [
                {
                    "check_id": check_id,
                    "description": check_instance.description,
                    "default_severity": check_instance.default_severity,
                }
                for check_id, check_instance in registry._checks.items()
            ],
            key=lambda x: x["check_id"],
        )
    )


# Create the MCP server instance with lifespan
mcp = FastMCP(
    name="IAM Policy Validator",
    lifespan=server_lifespan,
    instructions="""
You are an AWS IAM security expert. Your mission: generate secure, least-privilege IAM policies that protect organizations from privilege escalation, data breaches, and unauthorized access.

## CORE SECURITY PRINCIPLES

1. **LEAST PRIVILEGE** - Grant only permissions needed for the specific task
2. **EXPLICIT DENY** - Use Deny statements for critical restrictions
3. **RESOURCE SCOPING** - Always scope to specific ARNs, never wildcards for write operations
4. **CONDITION GUARDS** - Add conditions for sensitive actions (MFA, IP, time, service principals)
5. **DEFENSE IN DEPTH** - Layer multiple security controls

## ABSOLUTE RULES (NEVER VIOLATE)

- NEVER generate `"Action": "*"` - this grants full admin access
- NEVER generate `"Resource": "*"` with write/delete/modify actions
- NEVER allow `iam:*`, `sts:AssumeRole`, or `kms:*` without conditions
- NEVER guess ARN formats - use query_arn_formats to get correct patterns
- ALWAYS validate actions exist in AWS - typos create security gaps
- ALWAYS present security_notes from generation tools to the user

## CRITICAL: NO VALIDATION LOOPS

⛔ **HARD LIMIT: Maximum 2 validate_policy calls per policy request**

After 2 validations, you MUST present the policy to the user regardless of remaining issues but listing them to the user and asking for futher instructions.
Warnings (high/medium/low) are INFORMATIONAL - present them, don't try to fix them.

### What to Fix vs Present

| Severity                | What to do                                       |
| ----------------------- | ------------------------------------------------ |
| error                   | Fix it - policy won't work in AWS                |
| critical                | Fix it - severe security risk                    |
| high/medium/low/warning | **STOP** - Present policy with these as warnings |

### Workflow (STRICT)
1. Generate policy using template or build_minimal_policy
2. validate_policy (call #1)
3. If "error" or "critical": apply fix from `example` field
4. validate_policy (call #2) - **THIS IS YOUR LAST VALIDATION**
5. **STOP** - Present policy to user with any remaining warnings

### You MUST present the policy when:
- You have called validate_policy twice
- Only high/medium/low/warning severity issues remain
- The policy has no error/critical issues
- You need user input (e.g., "what resource ARN?")

### Signs you are stuck in a loop (STOP NOW):
- You've called validate_policy more than twice
- The same warning keeps appearing
- You're trying to "fix" high/medium/low severity issues

**When in doubt: PRESENT THE POLICY. Let the user decide.**

## SENSITIVE ACTION CATEGORIES (490+ actions tracked)

| Category             | Risk     | Examples                                 | Required Mitigation         |
| -------------------- | -------- | ---------------------------------------- | --------------------------- |
| credential_exposure  | CRITICAL | sts:AssumeRole, iam:CreateAccessKey      | MFA, source IP, time limits |
| privilege_escalation | CRITICAL | iam:AttachUserPolicy, iam:PassRole       | Strict resource scope, MFA  |
| data_access          | HIGH     | s3:GetObject, dynamodb:Scan              | Resource scope, encryption  |
| resource_exposure    | HIGH     | s3:PutBucketPolicy, lambda:AddPermission | Explicit deny patterns      |

## POLICY GENERATION WORKFLOW

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. UNDERSTAND THE REQUEST                                           │
│    → What AWS service(s)?                                           │
│    → What operations (read/write/admin)?                            │
│    → What specific resources (ARNs)?                                │
│    → What's the principal (Lambda, EC2, role)?                      |
│    → Are there existing org restrictions? (get_organization_config) │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. CHOOSE GENERATION APPROACH                                   │
│                                                                 │
│    Template exists? → generate_policy_from_template             │
│    Custom needs?    → build_minimal_policy                      │
│    Unknown actions? → suggest_actions → build_minimal_policy    │
│                                                                 │
│    Use list_templates first to check for pre-built secure       │
│    templates (s3-read-only, lambda-basic-execution, etc.)       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. VALIDATE ONCE                                                │
│                                                                 │
│    validate_policy → check for issues                           │
│    ⚠️  VALIDATE ONLY ONCE - DO NOT LOOP                         │
│                                                                 │
│    BLOCKING (must fix before presenting):                       │
│    → severity="error" - Policy won't work in AWS                │
│    → severity="critical" - Severe security risk                 │
│                                                                 │
│    NON-BLOCKING (present with warnings):                        │
│    → severity="high/medium/low/warning" - Security advice       │
│    → Present policy WITH these warnings, let user decide        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. PRESENT TO USER (even with warnings)                         │
│                                                                 │
│    → Show the policy immediately after ONE validation           │
│    → List any warnings/suggestions for user awareness           │
│    → DO NOT keep fixing and re-validating in a loop             │
│    → Let the user decide if they want changes                   │
└─────────────────────────────────────────────────────────────────┘
```

## TOOL SELECTION GUIDE

| Task                  | Primary Tool                                   | Fallback                     |
| --------------------- | ---------------------------------------------- | ---------------------------- |
| Create policy         | list_templates → generate_policy_from_template | build_minimal_policy         |
| Validate policy       | validate_policy                                | quick_validate (summary)     |
| Fix structural issues | fix_policy_issues                              | -                            |
| Get fix guidance      | get_issue_guidance                             | read issue.example field     |
| Find actions          | query_service_actions                          | suggest_actions              |
| Check action risks    | check_sensitive_actions                        | get_required_conditions      |
| Get ARN formats       | query_arn_formats                              | query_action_details         |
| Expand wildcards      | expand_wildcard_action                         | -                            |
| Batch operations      | validate_policies_batch, query_actions_batch   | -                            |
| Session config        | set_organization_config, check_org_compliance  | -                            |

### Tool Hierarchy (prefer tools higher in list)
1. **validate_policy** - Full validation with detailed issue information
2. **fix_policy_issues** - Structural fixes only (Version, SIDs, action case)
3. **get_issue_guidance** - Detailed fix instructions for specific check_ids

## ANTI-PATTERNS TO PREVENT

1. **Overly Broad Resources**
   BAD: `"Resource": "arn:aws:s3:::*"`
   GOOD: `"Resource": "arn:aws:s3:::my-specific-bucket/*"`

2. **Service Wildcards Without Conditions**
   BAD: `"Action": "s3:*"`
   GOOD: `"Action": ["s3:GetObject", "s3:ListBucket"]` with specific resources

3. **PassRole Without Service Restriction**
   BAD: `"Action": "iam:PassRole", "Resource": "*"`
   GOOD: Add `"Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}`

4. **Missing Secure Transport**
   For S3, always add: `"Condition": {"StringLike": {"aws:ResourceAccount": "<aws-account-id> OR ${aws:PrincipalAccount}"}}`

5. **Cross-Account Without Controls**
   If Principal includes external accounts, require: source IP, or org restrictions

## TRUST POLICY SPECIFICS

Trust policies control WHO can assume a role. Key differences:
- Principal is REQUIRED (AWS account, service, or federated user)
- Resource is NOT used (the role itself is the resource)
- Action is typically `sts:AssumeRole` only

Use validate_policy with auto-detection - it recognizes trust policies automatically.
For cross-account: generate_policy_from_template("cross-account-assume-role")

## HANDLING USER REQUESTS

**"Give me full access to..."**
→ Explain the security risks
→ Ask: "What specific operations do you need?"
→ Use suggest_actions to find minimal permissions
→ Never generate `"Action": "*"`

**"Just make it work"**
→ Still apply least privilege
→ Validate thoroughly
→ Present with security_notes explaining any risks

**After 3 failed fix attempts**
→ Stop and ask user for clarification
→ Present the specific blockers clearly
→ Suggest alternatives

## EXAMPLE INTERACTIONS

### Example 1: Lambda needs S3 access
User: "Create a policy for my Lambda to read from S3 bucket my-data-bucket"

Your workflow:
1. list_templates → find "s3-read-only" template
2. generate_policy_from_template("s3-read-only", {"bucket_name": "my-data-bucket"})
3. validate_policy ONCE → check result
4. Present policy to user with any warnings (DO NOT re-validate)

### Example 2: User requests overly broad access
User: "Give me full S3 access"

Your workflow:
1. Ask: "What specific S3 operations do you need? (read, write, delete, list)"
2. After clarification → query_service_actions("s3", access_level="read")
3. build_minimal_policy with specific actions and resources
4. validate_policy ONCE and present immediately (warnings are informational)

### Example 3: Validation returns warnings (DO NOT LOOP)
After validate_policy returns warnings like "wildcard_resource" or "sensitive_action":

WRONG approach (causes infinite loop):
❌ validate → fix → validate → fix → validate...

CORRECT approach:
✅ validate ONCE → present policy WITH warnings → let user decide
✅ Say: "Here's your policy. Note: it has these security considerations: [list warnings]"
✅ Only fix if user explicitly asks for changes

## VALIDATION ISSUE FIELDS

Each issue contains actionable guidance:
- `severity`: error/warning/critical/high/medium/low
- `message`: What's wrong
- `suggestion`: How to fix it
- `example`: **USE THIS** - shows the exact correct format
- `check_id`: For get_issue_guidance lookup
- `risk_explanation`: Why this matters
- `remediation_steps`: Step-by-step fix

## RESOURCES AND PROMPTS AVAILABLE

### Prompts (use for guided workflows)
- `generate_secure_policy` - Step-by-step policy creation with validation
- `fix_policy_issues_workflow` - Systematic issue fixing (max 2 iterations)
- `review_policy_security` - Security analysis without modification

### Resources (reference data)
- `iam://templates` - Pre-built secure templates
- `iam://checks` - All 19 validation checks
- `iam://sensitive-categories` - Sensitive action categories
- `iam://config-schema` - Configuration settings schema
- `iam://config-examples` - Example configurations
- `iam://workflow-examples` - Detailed step-by-step examples

Read iam://workflow-examples for comprehensive usage patterns.

## IAM ACTION AND POLICY FORMATTING RULES

### Action Formatting (CRITICAL)
- **Service prefix MUST be lowercase**: `s3:GetObject` ✓, `S3:GetObject` ✗
- **Action name uses PascalCase**: `s3:GetObject` ✓, `s3:getobject` ✗
- **Full format**: `<service>:<ActionName>` (e.g., `lambda:InvokeFunction`)
- **Wildcards**: Use `*` for patterns (`s3:Get*`, `s3:*Object`, `s3:*`)
- **Common mistakes to avoid**:
  - `S3:GetObject` → should be `s3:GetObject` (lowercase service)
  - `s3:getObject` → should be `s3:GetObject` (PascalCase action)
  - `s3.GetObject` → should be `s3:GetObject` (colon separator)
  - `arn:aws:s3:::bucket` in Action → Actions are not ARNs

### Policy Structure (REQUIRED FORMAT)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "UniqueStatementId",
      "Effect": "Allow",
      "Action": ["service:ActionName"],
      "Resource": ["arn:aws:service:region:account:resource"]
    }
  ]
}
```

### Version Field
- ALWAYS use `"Version": "2012-10-17"` (current version)
- `"2008-10-17"` is deprecated and lacks features like policy variables

### Statement Fields
| Field       | Required    | Type          | Valid Values                                |
| ----------- | ----------- | ------------- | ------------------------------------------- |
| Effect      | Yes         | string        | `"Allow"` or `"Deny"`                       |
| Action      | Yes*        | string/array  | Service actions like `"s3:GetObject"`       |
| NotAction   | No*         | string/array  | Actions to exclude                          |
| Resource    | Yes*        | string/array  | ARNs like `"arn:aws:s3:::bucket/*"`         |
| NotResource | No*         | string/array  | Resources to exclude                        |
| Principal   | Conditional | string/object | For resource policies only                  |
| Condition   | No          | object        | Condition operators and keys                |
| Sid         | No          | string        | Statement identifier (unique within policy) |

*Either Action or NotAction required; Either Resource or NotResource required

### Resource ARN Formatting
- **Format**: `arn:aws:<service>:<region>:<account>:<resource>`
- **S3 buckets**: `arn:aws:s3:::<bucket-name>` (no region/account)
- **S3 objects**: `arn:aws:s3:::<bucket-name>/<key-path>`
- **DynamoDB tables**: `arn:aws:dynamodb:<region>:<account>:table/<table-name>`
- **Lambda functions**: `arn:aws:lambda:<region>:<account>:function:<function-name>`
- **Wildcards**: Use `*` for patterns (`arn:aws:s3:::my-bucket/*`)
- Use query_arn_formats to get correct ARN patterns for any service

### Condition Block Formatting
```json
"Condition": {
  "<ConditionOperator>": {
    "<ConditionKey>": "<value>"
  }
}
```

**Common operators**:
- `StringEquals`, `StringNotEquals`, `StringLike`, `StringNotLike`
- `ArnEquals`, `ArnLike`, `ArnNotEquals`, `ArnNotLike`
- `NumericEquals`, `NumericLessThan`, `NumericGreaterThan`
- `DateEquals`, `DateLessThan`, `DateGreaterThan`
- `Bool` (for boolean conditions like `aws:SecureTransport`)
- `IpAddress`, `NotIpAddress` (for source IP restrictions)

**Set operators** (for multi-value keys):
- `ForAllValues:StringEquals` - All values must match
- `ForAnyValue:StringEquals` - At least one value must match

### Principal Formatting (Resource Policies Only)
```json
"Principal": {
  "AWS": "arn:aws:iam::123456789012:role/RoleName"
}
```
Or for service principals:
```json
"Principal": {
  "Service": "lambda.amazonaws.com"
}
```

### Common Formatting Errors to Catch
1. **Missing Version**: Always include `"Version": "2012-10-17"`
2. **Effect typos**: `"allow"` → `"Allow"`, `"DENY"` → `"Deny"`
3. **Invalid ARN format**: Missing colons or wrong segment count
4. **Single string vs array**: `"Action": "s3:GetObject"` works but `["s3:GetObject"]` preferred

ALWAYS validate actions exist using query_action_details or validate_policy before presenting to users.
""",
)


# =============================================================================
# Validation Tools
# =============================================================================


@mcp.tool()
async def validate_policy(
    policy: dict[str, Any],
    policy_type: str | None = None,
    verbose: bool = True,
    use_org_config: bool = True,
) -> dict[str, Any]:
    """Validate an IAM policy.

    Validates a policy against AWS IAM rules and security best practices.
    Runs all enabled checks and returns validation results.

    Policy Type Auto-Detection:
    If policy_type is None (default), the policy type is automatically detected:
    - "trust" if contains sts:AssumeRole action (trust/assume role policy)
    - "resource" if contains Principal/NotPrincipal (resource-based policy)
    - "identity" otherwise (identity-based policy attached to users/roles/groups)

    If an organization config is set and use_org_config=True, the validation
    will use organization-specific check overrides, ignore patterns, and
    severity settings.

    Args:
        policy: IAM policy as a dictionary
        policy_type: Type of policy to validate. If None (default), auto-detects from structure.
            Explicit options:
            - "identity": Identity-based policy (attached to users/roles/groups)
            - "resource": Resource-based policy (attached to resources like S3 buckets)
            - "trust": Trust policy (role assumption policy)
        verbose: If True (default), return all issue fields. If False, return only
            essential fields (severity, message, suggestion, check_id) to reduce tokens.
        use_org_config: Whether to apply session organization config (default: True)

    Returns:
        Dictionary with:
            - is_valid: True if no errors/warnings found
            - issues: List of validation issues
            - policy_file: Source identifier
    """
    from iam_validator.mcp.tools.validation import validate_policy as _validate

    result = await _validate(policy=policy, policy_type=policy_type, use_org_config=use_org_config)

    # Build issue list based on verbosity
    if verbose:
        issues = [
            {
                "severity": issue.severity,
                "message": issue.message,
                "suggestion": issue.suggestion,
                "example": issue.example,
                "check_id": issue.check_id,
                "statement_index": issue.statement_index,
                "action": getattr(issue, "action", None),
                "resource": getattr(issue, "resource", None),
                "field_name": getattr(issue, "field_name", None),
                "risk_explanation": issue.risk_explanation,
                "documentation_url": issue.documentation_url,
                "remediation_steps": issue.remediation_steps,
            }
            for issue in result.issues
        ]
    else:
        # Lean response - only essential fields
        issues = [
            {
                "severity": issue.severity,
                "message": issue.message,
                "suggestion": issue.suggestion,
                "check_id": issue.check_id,
            }
            for issue in result.issues
        ]

    return {
        "is_valid": result.is_valid,
        "issues": issues,
        "policy_file": result.policy_file,
    }


@mcp.tool()
async def quick_validate(policy: dict[str, Any]) -> dict[str, Any]:
    """Quick pass/fail validation check for a policy.

    Lightweight validation that returns essential information:
    whether the policy is valid, number of issues, and critical issues.

    Args:
        policy: IAM policy as a Python dictionary

    Returns:
        Dictionary with:
            - is_valid: Whether the policy passed validation
            - issue_count: Total number of issues found
            - critical_issues: List of critical/high severity issue messages
    """
    from iam_validator.mcp.tools.validation import quick_validate as _quick_validate

    return await _quick_validate(policy=policy)


# =============================================================================
# Generation Tools
# =============================================================================


@mcp.tool()
async def generate_policy_from_template(
    template_name: str,
    variables: dict[str, str],
) -> dict[str, Any]:
    """Generate an IAM policy from a built-in template.

    IMPORTANT: Call list_templates first to see available templates and their
    required variables with descriptions.

    Args:
        template_name: Template name from list_templates. Common templates:
            - s3-read-only: Read from S3 bucket
            - s3-read-write: Read/write to S3 bucket
            - lambda-basic-execution: Basic Lambda with CloudWatch logs
            - lambda-s3-trigger: Lambda triggered by S3 events
            - dynamodb-crud: DynamoDB table operations
            - cloudwatch-logs: Write to CloudWatch Logs
        variables: Dictionary of variable values. Get required variables from
            list_templates. Common variables:
            - bucket_name: S3 bucket name (without arn: prefix)
            - function_name: Lambda function name
            - table_name: DynamoDB table name
            - account_id: 12-digit AWS account ID
            - region: AWS region (e.g., us-east-1)

    Returns:
        Dictionary with:
            - policy: The generated IAM policy (ready to use)
            - validation: Validation results with any issues found
            - security_notes: Security warnings to review
            - template_used: Template name for reference

    Example:
        # First check what variables lambda-s3-trigger needs:
        templates = await list_templates()

        # Then generate with all required variables:
        result = await generate_policy_from_template(
            template_name="lambda-s3-trigger",
            variables={
                "bucket_name": "my-bucket",
                "function_name": "my-function",
                "account_id": "123456789012",
                "region": "us-east-1"
            }
        )
    """
    from iam_validator.mcp.tools.generation import (
        generate_policy_from_template as _generate,
    )

    result = await _generate(template_name=template_name, variables=variables)
    return {
        "policy": result.policy,
        "validation": {
            "is_valid": result.validation.is_valid,
            "issues": [
                {
                    "severity": issue.severity,
                    "message": issue.message,
                    "suggestion": issue.suggestion,
                    "example": issue.example,
                    "check_id": issue.check_id,
                    "risk_explanation": issue.risk_explanation,
                    "remediation_steps": issue.remediation_steps,
                }
                for issue in result.validation.issues
            ],
        },
        "security_notes": result.security_notes,
        "template_used": result.template_used,
    }


@mcp.tool()
async def build_minimal_policy(
    actions: list[str],
    resources: list[str],
    conditions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a minimal IAM policy from explicit actions and resources.

    Constructs a policy statement from provided actions and resources.
    Validates that actions exist in AWS using built-in checks, warns about
    sensitive actions, and returns security notes from validation.

    Args:
        actions: List of AWS actions (e.g., ["s3:GetObject", "s3:ListBucket"])
        resources: List of resource ARNs (e.g., ["arn:aws:s3:::my-bucket/*"])
        conditions: Optional conditions to add to the statement

    Returns:
        Dictionary with:
            - policy: The generated IAM policy
            - validation: Validation results from built-in checks
            - security_notes: Security warnings from validation
    """
    from iam_validator.mcp.tools.generation import build_minimal_policy as _build

    result = await _build(actions=actions, resources=resources, conditions=conditions)
    return {
        "policy": result.policy,
        "validation": {
            "is_valid": result.validation.is_valid,
            "issues": [
                {
                    "severity": issue.severity,
                    "message": issue.message,
                    "suggestion": issue.suggestion,
                    "example": issue.example,
                    "check_id": issue.check_id,
                    "risk_explanation": issue.risk_explanation,
                    "remediation_steps": issue.remediation_steps,
                }
                for issue in result.validation.issues
            ],
        },
        "security_notes": result.security_notes,
    }


@mcp.tool()
async def list_templates() -> list[dict[str, Any]]:
    """List all available policy templates with their required variables.

    IMPORTANT: Always call this BEFORE generate_policy_from_template to see
    what variables each template requires.

    Returns:
        List of template dictionaries, each containing:
            - name: Template identifier (pass to generate_policy_from_template)
            - description: What the template does
            - variables: List of required variables with:
                - name: Variable name (key for the variables dict)
                - description: What value to provide (e.g., "AWS account ID (12-digit number)")
                - required: Whether the variable must be provided
    """
    from iam_validator.mcp.tools.generation import list_templates as _list_templates

    return await _list_templates()


@mcp.tool()
async def suggest_actions(
    description: str,
    service: str | None = None,
) -> list[str]:
    """Suggest AWS actions based on a natural language description.

    Uses keyword pattern matching to suggest appropriate AWS actions.
    Useful for discovering actions when building policies.

    Args:
        description: Natural language description (e.g., "read files from S3")
        service: Optional AWS service to limit suggestions (e.g., "s3", "lambda")

    Returns:
        List of suggested action names
    """
    from iam_validator.mcp.tools.generation import suggest_actions as _suggest

    return await _suggest(description=description, service=service)


@mcp.tool()
async def get_required_conditions(actions: list[str]) -> dict[str, Any]:
    """Get the conditions required for a list of actions.

    Analyzes actions and returns condition requirements based on security
    best practices (e.g., MFA for sensitive actions, IP restrictions).

    Args:
        actions: List of AWS actions to analyze

    Returns:
        Dictionary mapping condition keys to required values, grouped by type
    """
    from iam_validator.mcp.tools.generation import (
        get_required_conditions as _get_conditions,
    )

    return await _get_conditions(actions=actions)


@mcp.tool()
async def check_sensitive_actions(actions: list[str]) -> dict[str, Any]:
    """Check if any actions are sensitive and get remediation guidance.

    Analyzes actions against the sensitive actions catalog (490+ actions)
    and returns risk category, severity, and **REMEDIATION GUIDANCE** including
    recommended IAM conditions and mitigation steps.

    Args:
        actions: List of AWS actions to check (e.g., ["iam:PassRole", "s3:GetObject"])

    Returns:
        Dictionary with:
            - sensitive_actions: List of dictionaries for each sensitive action found
                - action: The action name
                - category: Risk category (credential_exposure, data_access, priv_esc, resource_exposure)
                - severity: Severity level (critical or high)
                - description: Category description
                - remediation: Mitigation guidance including:
                    - risk_level: CRITICAL or HIGH
                    - why_dangerous: Explanation of the risk
                    - recommended_conditions: List of IAM conditions to add
                    - mitigation_steps: Steps to reduce risk
                    - condition_example: JSON example of the condition block to add
                    - specific_guidance: Action-specific advice (for iam:PassRole, sts:AssumeRole, etc.)
            - total_checked: Number of actions checked
            - sensitive_count: Number of sensitive actions found
            - categories_found: List of unique risk categories found
            - has_critical: Whether any critical severity actions were found
            - summary: Quick summary with top recommendations

    Example response for iam:PassRole:
        {
            "action": "iam:PassRole",
            "category": "priv_esc",
            "severity": "critical",
            "remediation": {
                "recommended_conditions": [{"condition": "iam:PassedToService", ...}],
                "condition_example": {"Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}},
                "specific_guidance": "Always restrict iam:PassRole to specific services..."
            }
        }
    """
    from iam_validator.mcp.tools.generation import (
        check_sensitive_actions as _check_sensitive,
    )

    return await _check_sensitive(actions=actions)


# =============================================================================
# Query Tools
# =============================================================================


@mcp.tool()
async def query_service_actions(
    service: str,
    access_level: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """Get all actions for a service, optionally filtered by access level.

    Args:
        service: AWS service prefix (e.g., "s3", "iam", "ec2")
        access_level: Optional filter (read|write|list|tagging|permissions-management)
        limit: Maximum number of actions to return (default: all)
        offset: Number of actions to skip for pagination (default: 0)

    Returns:
        Dictionary with:
            - actions: List of action names
            - total: Total number of actions available
            - has_more: Whether more actions are available
    """
    from iam_validator.mcp.tools.query import query_service_actions as _query

    all_actions = await _query(service=service, access_level=access_level)
    total = len(all_actions)

    # Apply pagination
    if offset:
        all_actions = all_actions[offset:]
    if limit:
        all_actions = all_actions[:limit]

    return {
        "actions": all_actions,
        "total": total,
        "has_more": offset + len(all_actions) < total,
    }


@mcp.tool()
async def query_action_details(action: str) -> dict[str, Any] | None:
    """Get detailed information about a specific action.

    Args:
        action: Full action name (e.g., "s3:GetObject", "iam:CreateUser")

    Returns:
        Dictionary with action metadata (access_level, resource_types, condition_keys),
        or None if not found
    """
    from iam_validator.mcp.tools.query import query_action_details as _query

    result = await _query(action=action)
    if result is None:
        return None
    return {
        "action": result.action,
        "service": result.service,
        "access_level": result.access_level,
        "resource_types": result.resource_types,
        "condition_keys": result.condition_keys,
        "description": result.description,
    }


@mcp.tool()
async def expand_wildcard_action(pattern: str) -> list[str]:
    """Expand wildcards like "s3:Get*" to specific actions.

    Args:
        pattern: Action pattern with wildcards (e.g., "s3:Get*", "iam:*User*")

    Returns:
        List of matching action names
    """
    from iam_validator.mcp.tools.query import expand_wildcard_action as _expand

    return await _expand(pattern=pattern)


@mcp.tool()
async def query_condition_keys(service: str) -> list[str]:
    """Get all condition keys for a service.

    Args:
        service: AWS service prefix (e.g., "s3", "iam")

    Returns:
        List of condition key names (e.g., ["s3:prefix", "s3:x-amz-acl"])
    """
    from iam_validator.mcp.tools.query import query_condition_keys as _query

    return await _query(service=service)


@mcp.tool()
async def query_arn_formats(service: str) -> list[dict[str, Any]]:
    """Get ARN formats for a service's resources.

    Args:
        service: AWS service prefix (e.g., "s3", "iam")

    Returns:
        List of dictionaries with resource_type and arn_formats keys
    """
    from iam_validator.mcp.tools.query import query_arn_formats as _query

    return await _query(service=service)


@mcp.tool()
async def list_checks() -> list[dict[str, Any]]:
    """List all available validation checks.

    Returns:
        List of dictionaries with check_id, description, and default_severity
    """
    # Use cached registry instead of creating new one each call
    # Convert tuple back to list for API compatibility
    return list(_get_cached_checks())


@mcp.tool()
async def get_policy_summary(policy: dict[str, Any]) -> dict[str, Any]:
    """Analyze a policy and return summary statistics.

    Args:
        policy: IAM policy as a dictionary

    Returns:
        Dictionary with:
            - total_statements: Number of statements
            - allow_statements: Number of Allow statements
            - deny_statements: Number of Deny statements
            - services_used: List of AWS services referenced
            - actions_count: Total number of actions
            - has_wildcards: Whether policy contains wildcards
            - has_conditions: Whether policy has conditions
    """
    from iam_validator.mcp.tools.query import get_policy_summary as _get_summary

    result = await _get_summary(policy=policy)
    return {
        "total_statements": result.total_statements,
        "allow_statements": result.allow_statements,
        "deny_statements": result.deny_statements,
        "services_used": result.services_used,
        "actions_count": result.actions_count,
        "has_wildcards": result.has_wildcards,
        "has_conditions": result.has_conditions,
    }


@mcp.tool()
async def list_sensitive_actions(
    category: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """List sensitive actions, optionally filtered by category.

    The sensitive actions catalog contains 490+ actions across 4 categories.

    Args:
        category: Optional filter:
            - credential_exposure: Actions that can expose credentials (46 actions)
            - data_access: Actions that access data (109 actions)
            - privilege_escalation: Actions that can escalate privileges (27 actions)
            - resource_exposure: Actions that can expose resources (321 actions)
        limit: Maximum number of actions to return (default: all)
        offset: Number of actions to skip for pagination (default: 0)

    Returns:
        Dictionary with:
            - actions: List of sensitive action names
            - total: Total number of actions available
            - has_more: Whether more actions are available
    """
    from iam_validator.mcp.tools.query import list_sensitive_actions as _list_sensitive

    all_actions = await _list_sensitive(category=category)
    total = len(all_actions)

    # Apply pagination
    if offset:
        all_actions = all_actions[offset:]
    if limit:
        all_actions = all_actions[:limit]

    return {
        "actions": all_actions,
        "total": total,
        "has_more": offset + len(all_actions) < total,
    }


@mcp.tool()
async def get_condition_requirements_for_action(action: str) -> dict[str, Any] | None:
    """Get required conditions for a specific action.

    Checks if the action has condition requirements based on the sensitive
    actions catalog and condition requirements configuration.

    Args:
        action: Full action name (e.g., "iam:PassRole", "s3:GetObject")

    Returns:
        Dictionary with condition requirements, or None if no requirements
    """
    from iam_validator.mcp.tools.query import get_condition_requirements as _get_reqs

    return await _get_reqs(action=action)


# =============================================================================
# Fix and Help Tools
# =============================================================================


@mcp.tool()
async def fix_policy_issues(
    policy: dict[str, Any],
    issues_to_fix: list[str] | None = None,
    policy_type: str | None = None,
) -> dict[str, Any]:
    """Attempt to automatically fix common structural policy issues.

    This tool applies simple structural fixes. For security-related fixes
    (conditions, sensitive actions), use the suggestion and example fields
    from validate_policy to apply fixes manually.

    Auto-fixable issues (structural only):
    - Missing Version field → adds "2012-10-17"
    - Duplicate SIDs → makes them unique
    - Action case normalization → converts "S3:GetObject" to "s3:GetObject"

    NOT auto-fixable (require user input):
    - Action: "*" → requires user to specify which actions
    - Resource: "*" → requires user to specify which resources
    - Missing conditions → use validate_policy example field to see correct fix
    - Invalid actions → use query_service_actions to find valid actions

    Args:
        policy: The IAM policy to fix
        issues_to_fix: Optional list of check_ids to fix. If None, attempts all fixes.
            Example: ["policy_structure", "sid_uniqueness", "action_validation"]
        policy_type: Type of policy. If None (default), auto-detects from structure.
            Options: "identity", "resource", "trust"

    Returns:
        Dictionary with:
            - fixed_policy: The policy with structural fixes applied
            - fixes_applied: List of fixes that were applied
            - unfixed_issues: Issues that require manual intervention (with guidance)
            - validation: New validation result after fixes
    """
    import copy

    from iam_validator.mcp.tools.validation import _detect_policy_type
    from iam_validator.mcp.tools.validation import validate_policy as _validate

    fixed_policy = copy.deepcopy(policy)
    fixes_applied: list[str] = []
    unfixed_issues: list[dict[str, Any]] = []

    # Auto-detect policy type if not provided
    effective_policy_type = policy_type if policy_type else _detect_policy_type(policy)

    # First, validate to get current issues
    initial_result = await _validate(policy=policy, policy_type=effective_policy_type)
    issue_check_ids = {issue.check_id for issue in initial_result.issues if issue.check_id}

    # Apply fixes based on check_ids
    def should_fix(check_id: str) -> bool:
        return issues_to_fix is None or check_id in issues_to_fix

    # Fix 1: Missing or invalid Version (structural fix)
    if should_fix("policy_structure"):
        if "Version" not in fixed_policy or fixed_policy.get("Version") not in [
            "2012-10-17",
            "2008-10-17",
        ]:
            fixed_policy["Version"] = "2012-10-17"
            fixes_applied.append("Added Version: 2012-10-17")

    # Fix 2: Duplicate SIDs (structural fix)
    if should_fix("sid_uniqueness") and "sid_uniqueness" in issue_check_ids:
        statements = fixed_policy.get("Statement", [])
        seen_sids: dict[str, int] = {}
        for i, stmt in enumerate(statements):
            sid = stmt.get("Sid")
            if sid:
                if sid in seen_sids:
                    new_sid = f"{sid}_{i}"
                    stmt["Sid"] = new_sid
                    fixes_applied.append(f"Renamed duplicate SID '{sid}' to '{new_sid}'")
                else:
                    seen_sids[sid] = i

    # Fix 3: Normalize action case (service prefix should be lowercase)
    if should_fix("action_validation"):
        statements = fixed_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            actions = stmt.get("Action", [])
            was_string = isinstance(actions, str)
            if was_string:
                actions = [actions]

            normalized = []
            for action in actions:
                if ":" in action:
                    service, name = action.split(":", 1)
                    if service != service.lower():
                        new_action = f"{service.lower()}:{name}"
                        normalized.append(new_action)
                        fixes_applied.append(f"Normalized action case: {action} → {new_action}")
                    else:
                        normalized.append(action)
                else:
                    normalized.append(action)

            if normalized:
                stmt["Action"] = (
                    normalized[0] if (was_string and len(normalized) == 1) else normalized
                )

    # Collect issues that require manual intervention
    # Include the example and suggestion from the validator for guidance
    for issue in initial_result.issues:
        check_id = issue.check_id or "unknown"

        # Skip structural issues we can fix
        if check_id in {"policy_structure", "sid_uniqueness", "action_validation"}:
            continue

        # All other issues need manual fix - include validator's guidance
        unfixed_issues.append(
            {
                "check_id": check_id,
                "message": issue.message,
                "suggestion": issue.suggestion,
                "example": issue.example,
                "severity": issue.severity,
            }
        )

    # Re-validate the fixed policy
    final_result = await _validate(policy=fixed_policy, policy_type=effective_policy_type)

    return {
        "fixed_policy": fixed_policy,
        "fixes_applied": fixes_applied,
        "unfixed_issues": unfixed_issues,
        "validation": {
            "is_valid": final_result.is_valid,
            "issue_count": len(final_result.issues),
            "issues": [
                {
                    "severity": issue.severity,
                    "message": issue.message,
                    "suggestion": issue.suggestion,
                    "example": issue.example,
                    "check_id": issue.check_id,
                }
                for issue in final_result.issues
            ],
        },
    }


@mcp.tool()
async def get_issue_guidance(check_id: str) -> dict[str, Any]:
    """Get detailed guidance on how to fix a specific validation issue.

    Use this when you encounter a validation issue and need detailed
    instructions on how to resolve it. Provides step-by-step fixes.

    Args:
        check_id: The check ID from the validation issue (e.g., "wildcard_action",
            "action_validation", "sensitive_action")

    Returns:
        Dictionary with:
            - check_id: The check identifier
            - description: What this check validates
            - common_causes: Why this issue typically occurs
            - fix_steps: Step-by-step instructions to fix
            - example_before: Example of problematic policy
            - example_after: Example of fixed policy
            - related_tools: MCP tools that can help fix this issue
    """
    guidance_db: dict[str, dict[str, Any]] = {
        "wildcard_action": {
            "check_id": "wildcard_action",
            "description": "Detects policies that use Action: '*' granting all permissions",
            "common_causes": [
                "Trying to grant broad access without knowing specific actions",
                "Copy-pasted from an overly permissive example",
            ],
            "fix_steps": [
                "1. Identify what the policy user actually needs to do",
                "2. Use suggest_actions('describe what you need', 'service') to find actions",
                "3. Replace '*' with the specific action list",
                "4. Re-validate with validate_policy",
            ],
            "example_before": '{"Action": "*", "Resource": "*"}',
            "example_after": '{"Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "arn:aws:s3:::my-bucket/*"}',
            "related_tools": ["suggest_actions", "query_service_actions", "list_templates"],
        },
        "wildcard_resource": {
            "check_id": "wildcard_resource",
            "description": "Detects policies that use Resource: '*' granting access to all resources",
            "common_causes": [
                "Not knowing the correct ARN format",
                "Wanting the policy to work across multiple resources",
            ],
            "fix_steps": [
                "1. Determine which specific resources need access",
                "2. Use query_arn_formats('service') to get ARN patterns",
                "3. Replace '*' with specific ARNs or ARN patterns",
                "4. Re-validate with validate_policy",
            ],
            "example_before": '{"Action": ["s3:GetObject"], "Resource": "*"}',
            "example_after": '{"Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket"]}',
            "related_tools": ["query_arn_formats", "get_policy_summary"],
        },
        "action_validation": {
            "check_id": "action_validation",
            "description": "Detects actions that don't exist in AWS",
            "common_causes": [
                "Typo in action name (e.g., 'S3:GetObject' instead of 's3:GetObject')",
                "Using deprecated action name",
                "Wrong service prefix",
            ],
            "fix_steps": [
                "1. Check the service prefix is lowercase (s3, not S3)",
                "2. Use query_service_actions('service') to list valid actions",
                "3. Use query_action_details('service:action') to verify action exists",
                "4. Fix the action name and re-validate",
            ],
            "example_before": '{"Action": ["S3:GetObjects"]}',
            "example_after": '{"Action": ["s3:GetObject"]}',
            "related_tools": [
                "query_service_actions",
                "query_action_details",
                "expand_wildcard_action",
            ],
        },
        "sensitive_action": {
            "check_id": "sensitive_action",
            "description": "Detects high-risk actions that can lead to privilege escalation or data exposure",
            "common_causes": [
                "Granting IAM, STS, or KMS permissions without restrictions",
                "Allowing actions that can modify security settings",
            ],
            "fix_steps": [
                "1. Verify the sensitive action is truly needed",
                "2. Use check_sensitive_actions(['action']) to understand the risk",
                "3. Use get_required_conditions(['action']) to get recommended conditions",
                "4. Add conditions to restrict when the action can be used",
                "5. Re-validate with validate_policy",
            ],
            "example_before": '{"Action": ["iam:PassRole"], "Resource": "*"}',
            "example_after": '{"Action": ["iam:PassRole"], "Resource": "arn:aws:iam::123456789012:role/LambdaRole", "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}}',
            "related_tools": [
                "check_sensitive_actions",
                "get_required_conditions",
                "fix_policy_issues",
            ],
        },
        "action_condition_enforcement": {
            "check_id": "action_condition_enforcement",
            "description": "Detects sensitive actions that should have conditions but don't",
            "common_causes": [
                "Not aware that certain actions need conditions",
                "Conditions were forgotten during policy creation",
            ],
            "fix_steps": [
                "1. Use get_required_conditions(['action']) to see what's needed",
                "2. Add the Condition block to the statement",
                "3. Common conditions: MFA, SourceIp, PassedToService",
                "4. Use fix_policy_issues to auto-add basic conditions",
            ],
            "example_before": '{"Action": ["iam:CreateUser"], "Resource": "*"}',
            "example_after": '{"Action": ["iam:CreateUser"], "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}',
            "related_tools": [
                "get_required_conditions",
                "fix_policy_issues",
                "check_sensitive_actions",
            ],
        },
        "policy_structure": {
            "check_id": "policy_structure",
            "description": "Detects missing or malformed policy structure",
            "common_causes": [
                "Missing Version field",
                "Missing Statement array",
                "Invalid Effect value",
            ],
            "fix_steps": [
                "1. Ensure Version is '2012-10-17' (recommended)",
                "2. Ensure Statement is an array of statement objects",
                "3. Each statement must have Effect, Action, and Resource",
                "4. Use fix_policy_issues to auto-fix structure issues",
            ],
            "example_before": '{"Statement": [{"Action": "s3:*"}]}',
            "example_after": '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/*"}]}',
            "related_tools": ["fix_policy_issues", "validate_policy"],
        },
    }

    if check_id in guidance_db:
        return guidance_db[check_id]

    # Generic guidance for unknown check_id
    return {
        "check_id": check_id,
        "description": f"Validation check: {check_id}",
        "common_causes": ["Check the validation message for specific details"],
        "fix_steps": [
            "1. Read the issue message and suggestion from validate_policy",
            "2. Use the example field if provided",
            "3. Use list_checks() to get more info about available checks",
            "4. Consult AWS IAM documentation",
        ],
        "example_before": "See the issue's example field",
        "example_after": "Apply the suggestion from the issue",
        "related_tools": ["validate_policy", "list_checks", "fix_policy_issues"],
    }


# =============================================================================
# Advanced Analysis Tools
# =============================================================================


@mcp.tool()
async def get_check_details(check_id: str) -> dict[str, Any]:
    """Get full documentation for a specific validation check.

    Returns comprehensive information about a check including its description,
    severity, configuration options, example violations, and fixes.

    Args:
        check_id: The check ID (e.g., "wildcard_action", "sensitive_action")

    Returns:
        Dictionary with:
            - check_id: The check identifier
            - description: Full description of what the check validates
            - default_severity: Default severity level
            - category: Check category (security, aws, structure)
            - example_violation: Example policy that would trigger this check
            - example_fix: How to fix the violation
            - configuration: Available configuration options
            - related_checks: Related check IDs
    """
    from iam_validator.core.check_registry import create_default_registry

    registry = create_default_registry()

    # Check metadata database
    check_metadata: dict[str, dict[str, Any]] = {
        "wildcard_action": {
            "category": "security",
            "example_violation": {"Effect": "Allow", "Action": "*", "Resource": "*"},
            "example_fix": {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            },
            "configuration": {"enabled": True, "severity": "configurable"},
            "related_checks": ["wildcard_resource", "full_wildcard", "service_wildcard"],
        },
        "wildcard_resource": {
            "category": "security",
            "example_violation": {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": "*",
            },
            "example_fix": {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            },
            "configuration": {"enabled": True, "severity": "configurable"},
            "related_checks": ["wildcard_action", "full_wildcard"],
        },
        "sensitive_action": {
            "category": "security",
            "example_violation": {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey"],
                "Resource": "*",
            },
            "example_fix": {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey"],
                "Resource": "arn:aws:iam::123456789012:user/${aws:username}",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            },
            "configuration": {"enabled": True, "severity": "high"},
            "related_checks": ["action_condition_enforcement"],
        },
        "action_validation": {
            "category": "aws",
            "example_violation": {"Effect": "Allow", "Action": ["S3:GetObjects"], "Resource": "*"},
            "example_fix": {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
            "configuration": {"enabled": True},
            "related_checks": ["policy_structure"],
        },
        "policy_structure": {
            "category": "structure",
            "example_violation": {"Statement": [{"Action": "s3:*"}]},
            "example_fix": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
            },
            "configuration": {"enabled": True},
            "related_checks": ["sid_uniqueness"],
        },
    }

    # Get check from registry
    if check_id in registry._checks:
        check = registry._checks[check_id]
        metadata = check_metadata.get(check_id, {})

        return {
            "check_id": check_id,
            "description": check.description,
            "default_severity": check.default_severity,
            "category": metadata.get("category", "general"),
            "example_violation": metadata.get("example_violation"),
            "example_fix": metadata.get("example_fix"),
            "configuration": metadata.get("configuration", {"enabled": True}),
            "related_checks": metadata.get("related_checks", []),
        }

    return {
        "check_id": check_id,
        "description": "Check not found",
        "default_severity": "unknown",
        "category": "unknown",
        "example_violation": None,
        "example_fix": None,
        "configuration": {},
        "related_checks": [],
    }


@mcp.tool()
async def explain_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Generate a human-readable explanation of what a policy allows or denies.

    Analyzes the policy structure and produces a plain-language summary
    of the effective permissions, including security concerns.

    Args:
        policy: IAM policy as a dictionary

    Returns:
        Dictionary with:
            - summary: Brief one-line summary
            - statements: Detailed explanation of each statement
            - services_accessed: List of AWS services with access types
            - security_concerns: Identified security issues
            - recommendations: Suggested improvements
    """
    from iam_validator.mcp.tools.query import get_policy_summary as _get_summary

    summary = await _get_summary(policy)
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    statement_explanations = []
    security_concerns = []
    recommendations = []
    services_with_access: dict[str, set[str]] = {}

    for idx, stmt in enumerate(statements):
        effect = stmt.get("Effect", "Allow")
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        conditions = stmt.get("Condition", {})

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # Analyze actions by service
        for action in actions:
            if ":" in action:
                service = action.split(":")[0]
                action_name = action.split(":")[1]
                if service not in services_with_access:
                    services_with_access[service] = set()

                if action_name == "*":
                    services_with_access[service].add("full")
                elif (
                    action_name.startswith("Get")
                    or action_name.startswith("List")
                    or action_name.startswith("Describe")
                ):
                    services_with_access[service].add("read")
                elif (
                    action_name.startswith("Put")
                    or action_name.startswith("Create")
                    or action_name.startswith("Update")
                ):
                    services_with_access[service].add("write")
                elif action_name.startswith("Delete") or action_name.startswith("Remove"):
                    services_with_access[service].add("delete")
                else:
                    services_with_access[service].add("other")
            elif action == "*":
                security_concerns.append(f"Statement {idx}: Full admin access with Action: '*'")
                recommendations.append("Replace Action: '*' with specific actions")

        # Check for wildcards
        if "*" in resources:
            if effect == "Allow":
                security_concerns.append(f"Statement {idx}: Allows access to all resources")
                recommendations.append(f"Statement {idx}: Scope resources to specific ARNs")

        # Build explanation
        action_desc = ", ".join(actions[:3]) + ("..." if len(actions) > 3 else "")
        resource_desc = ", ".join(resources[:2]) + ("..." if len(resources) > 2 else "")
        condition_desc = f" with {len(conditions)} condition(s)" if conditions else ""

        explanation = f"{effect}s {action_desc} on {resource_desc}{condition_desc}"
        statement_explanations.append(
            {
                "index": idx,
                "sid": stmt.get("Sid", f"Statement{idx}"),
                "effect": effect,
                "explanation": explanation,
                "action_count": len(actions),
                "has_conditions": bool(conditions),
            }
        )

    # Build services summary
    services_summary = []
    for service, access_types in services_with_access.items():
        services_summary.append(
            {
                "service": service,
                "access_types": sorted(access_types),
            }
        )

    # Generate summary
    total_allow = sum(1 for s in statements if s.get("Effect") == "Allow")
    total_deny = len(statements) - total_allow
    brief_summary = f"Policy with {len(statements)} statement(s): {total_allow} Allow, {total_deny} Deny across {len(services_with_access)} service(s)"

    return {
        "summary": brief_summary,
        "statements": statement_explanations,
        "services_accessed": services_summary,
        "security_concerns": security_concerns,
        "recommendations": recommendations,
        "has_wildcards": summary.has_wildcards,
        "has_conditions": summary.has_conditions,
    }


@mcp.tool()
async def build_arn(
    service: str,
    resource_type: str,
    resource_name: str,
    region: str = "",
    account_id: str = "",
    partition: str = "aws",
) -> dict[str, Any]:
    """Build a valid ARN from components.

    Helps construct ARNs with proper format validation for the specified service.

    Args:
        service: AWS service (e.g., "s3", "lambda", "dynamodb")
        resource_type: Type of resource (e.g., "bucket", "function", "table")
        resource_name: Name of the resource
        region: AWS region (required for regional resources, empty for global)
        account_id: AWS account ID (12 digits, empty for some services like S3)
        partition: AWS partition (default: "aws", or "aws-cn", "aws-us-gov")

    Returns:
        Dictionary with:
            - arn: The constructed ARN
            - valid: Whether the ARN format is valid
            - notes: Any notes about the ARN format
    """
    # ARN format patterns by service
    arn_patterns: dict[str, dict[str, Any]] = {
        "s3": {
            "bucket": {
                "format": "arn:{partition}:s3:::{resource}",
                "needs_region": False,
                "needs_account": False,
            },
            "object": {
                "format": "arn:{partition}:s3:::{resource}",
                "needs_region": False,
                "needs_account": False,
            },
        },
        "lambda": {
            "function": {
                "format": "arn:{partition}:lambda:{region}:{account}:function:{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "dynamodb": {
            "table": {
                "format": "arn:{partition}:dynamodb:{region}:{account}:table/{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "iam": {
            "user": {
                "format": "arn:{partition}:iam::{account}:user/{resource}",
                "needs_region": False,
                "needs_account": True,
            },
            "role": {
                "format": "arn:{partition}:iam::{account}:role/{resource}",
                "needs_region": False,
                "needs_account": True,
            },
            "policy": {
                "format": "arn:{partition}:iam::{account}:policy/{resource}",
                "needs_region": False,
                "needs_account": True,
            },
        },
        "sqs": {
            "queue": {
                "format": "arn:{partition}:sqs:{region}:{account}:{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "sns": {
            "topic": {
                "format": "arn:{partition}:sns:{region}:{account}:{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "ec2": {
            "instance": {
                "format": "arn:{partition}:ec2:{region}:{account}:instance/{resource}",
                "needs_region": True,
                "needs_account": True,
            },
            "vpc": {
                "format": "arn:{partition}:ec2:{region}:{account}:vpc/{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "secretsmanager": {
            "secret": {
                "format": "arn:{partition}:secretsmanager:{region}:{account}:secret:{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "kms": {
            "key": {
                "format": "arn:{partition}:kms:{region}:{account}:key/{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
    }

    notes: list[str] = []
    valid = True

    # Get pattern for service/resource type
    service_patterns = arn_patterns.get(service.lower(), {})
    pattern_info = service_patterns.get(resource_type.lower())

    if not pattern_info:
        # Generic fallback
        if region and account_id:
            arn = f"arn:{partition}:{service}:{region}:{account_id}:{resource_type}/{resource_name}"
        elif account_id:
            arn = f"arn:{partition}:{service}::{account_id}:{resource_type}/{resource_name}"
        else:
            arn = f"arn:{partition}:{service}:::{resource_type}/{resource_name}"
        notes.append("Unknown service/resource combination. Using generic format.")
        return {"arn": arn, "valid": True, "notes": notes}

    # Validate required fields
    if pattern_info["needs_region"] and not region:
        notes.append(f"Region is required for {service}:{resource_type}")
        valid = False
        region = "{region}"

    if pattern_info["needs_account"] and not account_id:
        notes.append(f"Account ID is required for {service}:{resource_type}")
        valid = False
        account_id = "{account_id}"

    # Build ARN from pattern
    arn = pattern_info["format"].format(
        partition=partition,
        region=region,
        account=account_id,
        resource=resource_name,
    )

    return {"arn": arn, "valid": valid, "notes": notes}


@mcp.tool()
async def compare_policies(
    policy_a: dict[str, Any],
    policy_b: dict[str, Any],
) -> dict[str, Any]:
    """Compare two IAM policies and highlight differences.

    Analyzes both policies and shows what permissions differ between them.

    Args:
        policy_a: First IAM policy (baseline)
        policy_b: Second IAM policy (comparison)

    Returns:
        Dictionary with:
            - summary: Brief comparison summary
            - added_actions: Actions in policy_b but not in policy_a
            - removed_actions: Actions in policy_a but not in policy_b
            - added_resources: Resources in policy_b but not in policy_a
            - removed_resources: Resources in policy_a but not in policy_b
            - condition_changes: Differences in conditions
            - effect_changes: Statements with different effects
    """

    def extract_policy_elements(policy: dict[str, Any]) -> dict[str, Any]:
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        all_actions: set[str] = set()
        all_resources: set[str] = set()
        all_conditions: list[dict[str, Any]] = []
        effects: dict[str, str] = {}

        for idx, stmt in enumerate(statements):
            sid = stmt.get("Sid", f"stmt_{idx}")
            effect = stmt.get("Effect", "Allow")
            effects[sid] = effect

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            all_actions.update(actions)

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            all_resources.update(resources)

            if "Condition" in stmt:
                all_conditions.append({"sid": sid, "condition": stmt["Condition"]})

        return {
            "actions": all_actions,
            "resources": all_resources,
            "conditions": all_conditions,
            "effects": effects,
        }

    elements_a = extract_policy_elements(policy_a)
    elements_b = extract_policy_elements(policy_b)

    added_actions = sorted(elements_b["actions"] - elements_a["actions"])
    removed_actions = sorted(elements_a["actions"] - elements_b["actions"])
    added_resources = sorted(elements_b["resources"] - elements_a["resources"])
    removed_resources = sorted(elements_a["resources"] - elements_b["resources"])

    # Compare effects for matching SIDs
    effect_changes = []
    common_sids = set(elements_a["effects"].keys()) & set(elements_b["effects"].keys())
    for sid in common_sids:
        if elements_a["effects"][sid] != elements_b["effects"][sid]:
            effect_changes.append(
                {
                    "sid": sid,
                    "policy_a": elements_a["effects"][sid],
                    "policy_b": elements_b["effects"][sid],
                }
            )

    # Summarize
    changes = []
    if added_actions:
        changes.append(f"{len(added_actions)} action(s) added")
    if removed_actions:
        changes.append(f"{len(removed_actions)} action(s) removed")
    if added_resources:
        changes.append(f"{len(added_resources)} resource(s) added")
    if removed_resources:
        changes.append(f"{len(removed_resources)} resource(s) removed")
    if effect_changes:
        changes.append(f"{len(effect_changes)} effect change(s)")

    summary = ", ".join(changes) if changes else "No significant differences found"

    return {
        "summary": summary,
        "added_actions": added_actions,
        "removed_actions": removed_actions,
        "added_resources": added_resources,
        "removed_resources": removed_resources,
        "condition_changes": {
            "policy_a_conditions": len(elements_a["conditions"]),
            "policy_b_conditions": len(elements_b["conditions"]),
        },
        "effect_changes": effect_changes,
    }


# =============================================================================
# Batch Operations (Reduced Round-Trips)
# =============================================================================


@mcp.tool()
async def validate_policies_batch(
    policies: list[dict[str, Any]],
    ctx: Context,
    policy_type: str | None = None,
    verbose: bool = False,
) -> list[dict[str, Any]]:
    """Validate multiple IAM policies in a single call.

    More efficient than calling validate_policy multiple times when you need
    to validate several policies at once. Validations run in parallel.

    Policy Type Auto-Detection:
    If policy_type is None (default), each policy's type is automatically detected
    from its structure (see validate_policy for detection rules).

    Args:
        ctx: FastMCP context (automatically passed by framework)
        policies: List of IAM policy dictionaries to validate
        policy_type: Type of policies. If None (default), auto-detects each policy.
            Options: "identity", "resource", "trust"
        verbose: If True, return all issue fields. If False (default), return
            only essential fields to reduce tokens.

    Returns:
        List of validation results, each containing:
            - policy_index: Index of the policy in the input list
            - is_valid: Whether the policy passed validation
            - issues: List of validation issues
    """
    import asyncio

    from iam_validator.mcp.tools.validation import validate_policy as _validate

    # Ensure shared fetcher is available (validates actions exist)
    _ = get_shared_fetcher(ctx)

    async def validate_one(idx: int, policy: dict[str, Any]) -> dict[str, Any]:
        result = await _validate(policy=policy, policy_type=policy_type)

        if verbose:
            issues = [
                {
                    "severity": issue.severity,
                    "message": issue.message,
                    "suggestion": issue.suggestion,
                    "example": issue.example,
                    "check_id": issue.check_id,
                    "statement_index": issue.statement_index,
                    "action": getattr(issue, "action", None),
                    "resource": getattr(issue, "resource", None),
                    "field_name": getattr(issue, "field_name", None),
                }
                for issue in result.issues
            ]
        else:
            issues = [
                {
                    "severity": issue.severity,
                    "message": issue.message,
                    "check_id": issue.check_id,
                }
                for issue in result.issues
            ]

        return {
            "policy_index": idx,
            "is_valid": result.is_valid,
            "issues": issues,
        }

    # Run all validations in parallel
    results = await asyncio.gather(*[validate_one(i, p) for i, p in enumerate(policies)])
    return list(results)


@mcp.tool()
async def query_actions_batch(actions: list[str], ctx: Context) -> dict[str, dict[str, Any] | None]:
    """Get details for multiple actions in a single call.

    More efficient than calling query_action_details multiple times when you
    need information about several actions at once.

    Args:
        ctx: FastMCP context (automatically passed by framework)
        actions: List of full action names (e.g., ["s3:GetObject", "iam:CreateUser"])

    Returns:
        Dictionary mapping action names to their details (or None if not found).
        Each action detail contains: service, access_level, resource_types, condition_keys
    """
    import asyncio

    from iam_validator.mcp.tools.query import query_action_details as _query

    # Use shared fetcher from context
    shared_fetcher = get_shared_fetcher(ctx)

    async def query_one(action: str) -> tuple[str, dict[str, Any] | None]:
        """Query a single action and return (action, details) tuple."""
        try:
            details = await _query(action=action, fetcher=shared_fetcher)
            if details:
                return (
                    action,
                    {
                        "service": details.service,
                        "access_level": details.access_level,
                        "resource_types": details.resource_types,
                        "condition_keys": details.condition_keys,
                        "description": details.description,
                    },
                )
            return (action, None)
        except Exception:
            return (action, None)

    # Run all queries in parallel
    query_results = await asyncio.gather(*[query_one(action) for action in actions])
    return dict(query_results)


@mcp.tool()
async def check_actions_batch(actions: list[str], ctx: Context) -> dict[str, Any]:
    """Validate and check sensitivity for multiple actions in one call.

    Combines action validation and sensitivity checking into a single tool
    for efficient batch processing.

    Args:
        ctx: FastMCP context (automatically passed by framework)
        actions: List of AWS actions to check (e.g., ["s3:GetObject", "iam:PassRole"])

    Returns:
        Dictionary with:
            - valid_actions: List of actions that exist in AWS
            - invalid_actions: List of actions that don't exist (with error messages)
            - sensitive_actions: List of sensitive actions with their categories
    """
    import asyncio

    from iam_validator.core.aws_service import AWSServiceFetcher
    from iam_validator.core.config.sensitive_actions import (
        SENSITIVE_ACTION_CATEGORIES,
        get_category_for_action,
    )

    async def check_one_action(action: str, fetcher: AWSServiceFetcher) -> dict[str, Any]:
        """Check a single action for validity and sensitivity."""
        result: dict[str, Any] = {
            "action": action,
            "is_valid": False,
            "error": None,
            "sensitive": None,
        }

        # Check if action is valid
        try:
            if "*" in action:
                # Wildcard - try to expand
                expanded = await fetcher.expand_wildcard_action(action)
                if expanded:
                    result["is_valid"] = True
                else:
                    result["error"] = "No matching actions"
            else:
                is_valid, error, _ = await fetcher.validate_action(action)
                if is_valid:
                    result["is_valid"] = True
                else:
                    result["error"] = error or "Unknown error"
        except Exception as e:
            result["error"] = str(e)

        # Check sensitivity (even for invalid actions - they might be typos of sensitive ones)
        category = get_category_for_action(action)
        if category:
            category_data = SENSITIVE_ACTION_CATEGORIES[category]
            result["sensitive"] = {
                "category": category,
                "severity": category_data["severity"],
                "name": category_data["name"],
            }

        return result

    # Try to get shared fetcher from context, fall back to creating new one
    shared_fetcher = get_shared_fetcher(ctx)
    if shared_fetcher:
        # Use shared fetcher - run all checks in parallel
        check_results = await asyncio.gather(
            *[check_one_action(action, shared_fetcher) for action in actions]
        )
    else:
        # Fall back to creating new fetcher
        async with AWSServiceFetcher() as fetcher:
            check_results = await asyncio.gather(
                *[check_one_action(action, fetcher) for action in actions]
            )

    # Aggregate results
    valid_actions: list[str] = []
    invalid_actions: list[dict[str, str]] = []
    sensitive_actions: list[dict[str, Any]] = []

    for result in check_results:
        action = result["action"]
        if result["is_valid"]:
            valid_actions.append(action)
        elif result["error"]:
            invalid_actions.append({"action": action, "error": result["error"]})

        if result["sensitive"]:
            sensitive_actions.append({"action": action, **result["sensitive"]})

    return {
        "valid_actions": valid_actions,
        "invalid_actions": invalid_actions,
        "sensitive_actions": sensitive_actions,
    }


# =============================================================================
# Organization Configuration Tools
# =============================================================================


@mcp.tool()
async def set_organization_config(
    config: dict[str, Any],
) -> dict[str, Any]:
    """Set validator configuration for this MCP session.

    The configuration uses the same format as the iam-validator YAML config files.
    It applies to all subsequent validation operations until cleared or updated.

    Args:
        config: Validator configuration dictionary with:
            - settings: Global settings
                - fail_on_severity: List of severities that cause failure
                  (e.g., ["error", "critical", "high"])
                - parallel_execution: Enable parallel check execution (default: true)
                - fail_fast: Stop on first error (default: false)
            - Check IDs as keys with configuration:
                - enabled: Enable/disable the check (default: true)
                - severity: Override check severity (error|critical|high|medium|low|warning)
                - ignore_patterns: Patterns to skip (see docs for pattern syntax)

    Returns:
        Dictionary with:
            - success: Whether config was set successfully
            - applied_config: The effective configuration (settings + checks)
            - warnings: Any configuration warnings

    Example:
        >>> result = await set_organization_config({
        ...     "settings": {"fail_on_severity": ["error", "critical"]},
        ...     "wildcard_action": {"enabled": True, "severity": "critical"},
        ...     "sensitive_action": {"enabled": True, "severity": "high"},
        ...     "policy_size": {"enabled": False}  # Disable a check
        ... })
    """
    from iam_validator.mcp.tools.org_config_tools import set_organization_config_impl

    return await set_organization_config_impl(config)


@mcp.tool()
async def get_organization_config() -> dict[str, Any]:
    """Get the current organization configuration for this session.

    Returns:
        Dictionary with:
            - has_config: Whether an organization config is currently set
            - config: The current configuration (or null if not set)
            - source: Where the config came from ("session", "yaml", or "none")
    """
    from iam_validator.mcp.tools.org_config_tools import get_organization_config_impl

    return await get_organization_config_impl()


@mcp.tool()
async def clear_organization_config() -> dict[str, str]:
    """Clear the organization configuration for this session.

    After clearing, validation and generation will use default settings
    without any organization-specific restrictions.

    Returns:
        Dictionary with:
            - status: "cleared" if config was removed, "no_config_set" if none existed
    """
    from iam_validator.mcp.tools.org_config_tools import clear_organization_config_impl

    return await clear_organization_config_impl()


@mcp.tool()
async def load_organization_config_from_yaml(
    yaml_content: str,
) -> dict[str, Any]:
    """Load validator configuration from YAML content.

    Parses YAML configuration and sets it as the session config.
    Uses the same format as iam-validator.yaml configuration files.

    Args:
        yaml_content: YAML configuration string. Example:
            settings:
              fail_on_severity:
                - error
                - critical
                - high

            # Enable/disable/configure specific checks
            wildcard_action:
              enabled: true
              severity: critical

            sensitive_action:
              enabled: true
              severity: high
              ignore_patterns:
                - action: "^s3:Get.*"  # Ignore S3 read actions

            policy_size:
              enabled: false  # Disable this check

    Returns:
        Dictionary with:
            - success: Whether config was loaded successfully
            - applied_config: The effective configuration (settings + checks)
            - warnings: Any warnings (unknown keys, etc.)
            - error: Error message if loading failed
    """
    from iam_validator.mcp.tools.org_config_tools import (
        load_organization_config_from_yaml_impl,
    )

    return await load_organization_config_from_yaml_impl(yaml_content)


@mcp.tool()
async def check_org_compliance(
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Validate a policy using the current session configuration.

    Runs the full IAM validator with the session configuration applied.
    This includes all enabled checks with their configured severity levels
    and ignore patterns.

    If no session config is set, uses default validator settings.

    Args:
        policy: IAM policy as a dictionary

    Returns:
        Dictionary with:
            - compliant: True if no issues exceed fail_on_severity threshold
            - has_org_config: Whether a session config is set
            - violations: List of validation issues found (type, message, severity)
            - warnings: List of warnings
            - suggestions: How to fix issues
    """
    from iam_validator.mcp.tools.org_config_tools import check_org_compliance_impl

    return await check_org_compliance_impl(policy)


@mcp.tool()
async def validate_with_config(
    policy: dict[str, Any],
    config: dict[str, Any],
    policy_type: str | None = None,
) -> dict[str, Any]:
    """Validate a policy with explicit inline configuration.

    Useful for one-off validation with specific settings without modifying
    the session config. The provided config is used only for this call.

    Policy Type Auto-Detection:
    If policy_type is None (default), the policy type is automatically detected
    from the policy structure (see validate_policy for detection rules).

    Args:
        policy: IAM policy to validate
        config: Inline configuration (same format as set_organization_config):
            - settings: Global settings (fail_on_severity, parallel_execution, etc.)
            - Check IDs as keys: {enabled, severity, ignore_patterns}
        policy_type: Type of policy ("identity", "resource", "trust")

    Returns:
        Dictionary with:
            - is_valid: Whether the policy passed all checks
            - issues: List of validation issues (severity, message, suggestion, check_id)
            - config_applied: The configuration that was used

    Example:
        >>> result = await validate_with_config(
        ...     policy=my_policy,
        ...     config={
        ...         "settings": {"fail_on_severity": ["error"]},
        ...         "wildcard_action": {"severity": "warning"}  # Downgrade to warning
        ...     }
        ... )
    """
    from iam_validator.mcp.tools.org_config_tools import validate_with_config_impl

    return await validate_with_config_impl(policy, config, policy_type)


# =============================================================================
# MCP Resources (Static Data - Client Cacheable)
# =============================================================================


@mcp.resource("iam://templates")
async def templates_resource() -> str:
    """List of all available policy templates.

    This resource provides metadata about built-in policy templates
    that can be used with generate_policy_from_template.
    """
    import json

    from iam_validator.mcp.tools.generation import list_templates as _list_templates

    templates = await _list_templates()
    return json.dumps(templates, indent=2)


@mcp.resource("iam://checks")
async def checks_resource() -> str:
    """List of all available validation checks.

    This resource provides metadata about all validation checks
    including their IDs, descriptions, and default severities.
    """
    import json

    return json.dumps(_get_cached_checks(), indent=2)


@mcp.resource("iam://sensitive-categories")
async def sensitive_categories_resource() -> str:
    """Sensitive action categories and their descriptions.

    This resource describes the 4 categories of sensitive actions
    that the validator tracks.
    """
    import json

    from iam_validator.core.config.sensitive_actions import SENSITIVE_ACTION_CATEGORIES

    # Convert frozensets to lists for JSON serialization
    serializable = {
        category_id: {
            "name": data["name"],
            "description": data["description"],
            "severity": data["severity"],
            "action_count": len(data["actions"]),
        }
        for category_id, data in SENSITIVE_ACTION_CATEGORIES.items()
    }

    return json.dumps(serializable, indent=2)


@mcp.resource("iam://config-schema")
def config_schema_resource() -> str:
    """JSON Schema for session configuration.

    Returns the schema for valid configuration settings,
    useful for AI assistants to validate config before setting.
    """
    import json

    from iam_validator.core.config.config_loader import SettingsSchema

    return json.dumps(SettingsSchema.model_json_schema(), indent=2)


@mcp.resource("iam://config-examples")
def config_examples_resource() -> str:
    """Example configurations for common scenarios.

    Provides examples for different security postures and use cases.
    These configurations use the same format as the CLI validator YAML config.
    All validation is done by the IAM validator's built-in checks.
    """
    return """
# Configuration Examples

These configurations can be used with both the CLI (`--config`) and MCP server.
They control which checks run and their severity levels.

## 1. Enterprise Security (Strict)
Maximum security - all wildcards are critical, sensitive actions flagged.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
    - high

# Make all wildcard checks critical severity
wildcard_action:
  enabled: true
  severity: critical

wildcard_resource:
  enabled: true
  severity: critical

full_wildcard:
  enabled: true
  severity: critical

service_wildcard:
  enabled: true
  severity: critical

# Flag all sensitive/privileged actions
sensitive_action:
  enabled: true
  severity: high

# Require conditions on sensitive actions
action_condition_enforcement:
  enabled: true
  severity: error
```

## 2. Development Environment (Permissive)
Relaxed settings for dev/sandbox - only catch critical issues.

```yaml
settings:
  fail_on_severity:
    - error
    - critical

# Disable sensitive action warnings in dev
sensitive_action:
  enabled: false

# Lower severity for wildcards (warn but don't fail)
wildcard_action:
  enabled: true
  severity: medium

wildcard_resource:
  enabled: true
  severity: medium

# Still catch full admin access
full_wildcard:
  enabled: true
  severity: critical
```

## 3. Compliance-Focused
Emphasizes policy structure and AWS validation.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
    - high

# Ensure all actions are valid AWS actions
action_validation:
  enabled: true
  severity: error

# Validate condition keys and operators
condition_key_validation:
  enabled: true
  severity: error

condition_type_mismatch:
  enabled: true
  severity: error

# Ensure proper policy structure
policy_structure:
  enabled: true
  severity: error

# Check policy size limits
policy_size:
  enabled: true
  severity: error
```

## 4. Security Audit
Comprehensive security review - everything enabled at high severity.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
    - high
    - medium

# All security checks at high severity
wildcard_action:
  enabled: true
  severity: high

wildcard_resource:
  enabled: true
  severity: high

full_wildcard:
  enabled: true
  severity: critical

service_wildcard:
  enabled: true
  severity: high

sensitive_action:
  enabled: true
  severity: high

action_condition_enforcement:
  enabled: true
  severity: high

# Catch NotAction/NotResource anti-patterns
not_action_not_resource:
  enabled: true
  severity: high
```

## 5. Minimal Validation
Quick validation - only structural and critical issues.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
  parallel: true

# Only critical checks
policy_structure:
  enabled: true
  severity: error

full_wildcard:
  enabled: true
  severity: critical

# Disable detailed checks for speed
action_validation:
  enabled: false

sensitive_action:
  enabled: false

condition_key_validation:
  enabled: false
```
"""


@mcp.resource("iam://workflow-examples")
def workflow_examples_resource() -> str:
    """Detailed workflow examples for common IAM policy tasks.

    This resource contains step-by-step examples showing how to use
    the IAM Policy Validator tools effectively.
    """
    return """
# IAM Policy Validator - Workflow Examples

## Example 1: Create Policy from Template

USER: "I need a policy for Lambda to read from S3"

STEPS:
1. list_templates → found "lambda-s3-trigger"
2. ASK USER: "What's your S3 bucket name?"
3. generate_policy_from_template(
     template_name="lambda-s3-trigger",
     variables={"bucket_name": "user-bucket", "function_name": "my-func", ...}
   )
4. validate_policy on result
5. Present validated policy to user

## Example 2: Validate Overly Permissive Policy

USER: "Validate this policy: {Action: *, Resource: *}"

STEPS:
1. validate_policy → returns issues (wildcard_action, wildcard_resource)
2. fix_policy_issues → unfixed_issues shows wildcards can't be auto-fixed
3. RESPOND to user:
   "This policy grants full admin access. I need to know:
   - Which AWS service(s) do you need access to?
   - What operations (read/write/delete)?
   - Which specific resources (bucket names, table names, etc.)?"

## Example 3: Build Custom Policy

USER: "Create a policy to read DynamoDB table 'users' and write to S3 bucket 'backups'"

STEPS:
1. suggest_actions("read DynamoDB", "dynamodb") → get read actions
2. suggest_actions("write S3", "s3") → get write actions
3. build_minimal_policy(
     actions=["dynamodb:GetItem", "dynamodb:Query", "s3:PutObject"],
     resources=[
       "arn:aws:dynamodb:us-east-1:123456789012:table/users",
       "arn:aws:s3:::backups/*"
     ]
   )
4. validate_policy on result
5. Review security_notes and present to user

## Example 4: Fix Validation Issues

USER provides policy with issues

STEPS:
1. validate_policy → returns is_valid=false with issues
2. For each issue, read the `example` field - it shows the exact fix
3. fix_policy_issues → applies auto-fixes (Version, SIDs)
4. For remaining unfixed_issues:
   - If wildcard: ask user for specific actions/resources
   - If missing condition: use get_required_conditions to see what's needed
5. Re-validate until is_valid=true

## Example 5: Research Actions

USER: "What S3 write actions exist?"

STEPS:
1. query_service_actions(service="s3", access_level="write")
2. Present the list to user
3. If they pick actions, use check_sensitive_actions to warn about risks

## Example 6: Batch Validation

USER provides multiple policies to check

STEPS:
1. validate_policies_batch(policies=[...], verbose=False)
2. For each result, show policy_index and is_valid
3. Detail issues only for invalid policies
"""


# =============================================================================
# Prompts - Guided Workflows for LLM Clients
# =============================================================================


@mcp.prompt
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

### Step 1: Find a Template
Call `list_templates` to check if a pre-built secure template exists for {service}.
If found, use `generate_policy_from_template` with the resource values.

### Step 2: If No Template, Build Manually
1. Call `query_service_actions("{service}")` to find exact action names
2. Call `query_arn_formats("{service}")` to get correct ARN patterns
3. Call `build_minimal_policy` with the specific actions and resources

### Step 3: Validate ONCE
Call `validate_policy` on the generated policy.

### Step 4: Fix Only BLOCKING Issues
BLOCKING issues (MUST fix): severity = "error" or "critical"
- Use the `example` field from the issue - it shows the exact fix
- Apply the fix directly

NON-BLOCKING issues (present with warnings): severity = "high", "medium", "low", "warning"
- Do NOT try to fix these automatically
- Present them to the user as security recommendations

### Step 5: Present the Policy
Show the final policy with:
1. The complete JSON policy
2. Any non-blocking warnings as "Security Considerations"
3. Explanation of what permissions are granted

⚠️ IMPORTANT: Do NOT validate more than once. Do NOT loop trying to fix warnings.
"""


@mcp.prompt
def fix_policy_issues_workflow(policy_json: str, issues_description: str) -> str:
    """Systematic workflow to fix IAM policy validation issues.

    Use this prompt when you have a policy with validation issues and need
    to fix them systematically without getting into a loop.

    Args:
        policy_json: The IAM policy JSON that has issues
        issues_description: Description of the issues found (from validate_policy)
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
2. Apply the fix to the policy
3. For structural issues (Version, Effect case), use `fix_policy_issues` tool

### After Fixing:
Call `validate_policy` ONE more time to verify blocking issues are resolved.

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


@mcp.prompt
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
Call `validate_policy` with the policy above.

### Step 2: Check Sensitive Actions
Call `check_sensitive_actions` to identify high-risk permissions.

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
- [List any sensitive actions and their risk category]

**Overall Assessment**:
[Brief summary of the policy's security posture]

⚠️ Do NOT attempt to fix the policy unless the user asks. Just report findings.
"""


# =============================================================================
# Server Entry Points
# =============================================================================


def create_server() -> FastMCP:
    """Create and return the configured MCP server instance.

    Returns:
        FastMCP: The configured MCP server with all tools registered
    """
    return mcp


def run_server() -> None:
    """Run the MCP server.

    This is the entry point for the iam-validator-mcp command.
    Uses stdio transport by default for Claude Desktop integration.
    """
    mcp.run()


__all__ = ["mcp", "create_server", "run_server"]

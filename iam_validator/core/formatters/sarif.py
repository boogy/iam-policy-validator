"""SARIF (Static Analysis Results Interchange Format) formatter for GitHub integration.

This formatter produces SARIF 2.1.0 output that integrates with GitHub Code Scanning,
providing rich issue details including:
- Risk explanations and remediation guidance
- Suggested fixes and code examples
- Links to documentation
- Affected policy fields (action, resource, condition)

The output appears in GitHub's Security tab as code scanning alerts with inline
annotations on affected lines.
"""

import json
from datetime import datetime, timezone
from typing import Any

from iam_validator.core.formatters.base import OutputFormatter
from iam_validator.core.models import ValidationIssue, ValidationReport


class SARIFFormatter(OutputFormatter):
    """Formats validation results in SARIF format for GitHub code scanning.

    Produces rich SARIF output with:
    - Dynamic rule definitions based on check IDs
    - Full issue context (risk, remediation, examples)
    - Suggested fixes as SARIF fix objects
    - Related locations for affected fields
    """

    @property
    def format_id(self) -> str:
        return "sarif"

    @property
    def description(self) -> str:
        return "SARIF format for GitHub code scanning integration"

    @property
    def file_extension(self) -> str:
        return "sarif"

    @property
    def content_type(self) -> str:
        return "application/sarif+json"

    def format(self, report: ValidationReport, **kwargs) -> str:
        """Format report as SARIF.

        Args:
            report: The validation report
            **kwargs: Additional options like 'tool_version'

        Returns:
            SARIF JSON string
        """
        sarif = self._create_sarif_output(report, **kwargs)
        return json.dumps(sarif, indent=2)

    def _create_sarif_output(self, report: ValidationReport, **kwargs) -> dict[str, Any]:
        """Create SARIF output structure."""
        tool_version = kwargs.get("tool_version", "1.0.0")

        # Map severity levels to SARIF - support both IAM validity and security severities
        severity_map = {
            "error": "error",
            "critical": "error",
            "high": "error",
            "warning": "warning",
            "medium": "warning",
            "info": "note",
            "low": "note",
        }

        # Collect all unique check_ids from issues for dynamic rule generation
        all_issues: list[ValidationIssue] = []
        for policy_result in report.results:
            all_issues.extend(policy_result.issues)

        # Create SARIF structure
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "IAM Validator",
                            "version": tool_version,
                            "informationUri": "https://github.com/boogy/iam-validator",
                            "rules": self._create_rules_from_issues(all_issues),
                        }
                    },
                    "results": self._create_results(report, severity_map),
                    "invocations": [
                        {
                            "executionSuccessful": len([r for r in report.results if r.is_valid])
                            > 0,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                }
            ],
        }

        return sarif

    def _create_rules_from_issues(self, issues: list[ValidationIssue]) -> list[dict[str, Any]]:
        """Create SARIF rules dynamically from actual issues found.

        This generates rules based on the check_id and issue_type of actual findings,
        ensuring all rules referenced by results are defined.

        Args:
            issues: List of all validation issues

        Returns:
            List of SARIF rule definitions
        """
        # Track unique rules by check_id (or issue_type as fallback)
        rules_map: dict[str, dict[str, Any]] = {}

        # Severity to SARIF level mapping
        severity_to_level = {
            "error": "error",
            "critical": "error",
            "high": "error",
            "warning": "warning",
            "medium": "warning",
            "info": "note",
            "low": "note",
        }

        for issue in issues:
            rule_id = self._get_rule_id(issue)

            # Skip if already defined
            if rule_id in rules_map:
                continue

            # Build rule from issue metadata
            rule: dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": self._get_rule_short_description(issue)},
                "fullDescription": {"text": self._get_rule_full_description(issue)},
                "defaultConfiguration": {"level": severity_to_level.get(issue.severity, "warning")},
            }

            # Add help URI if available
            if issue.documentation_url:
                rule["helpUri"] = issue.documentation_url
            else:
                # Use default AWS docs based on issue type
                rule["helpUri"] = self._get_default_help_uri(issue)

            # Add rich help text with risk explanation and remediation
            help_text = self._build_help_markdown(issue)
            if help_text:
                rule["help"] = {"text": help_text, "markdown": help_text}

            rules_map[rule_id] = rule

        # Return rules sorted by ID for consistent output
        return list(sorted(rules_map.values(), key=lambda r: r["id"]))

    def _get_rule_short_description(self, issue: ValidationIssue) -> str:
        """Get a short description for the rule based on check_id or issue_type."""
        # Map check_id to human-readable short descriptions
        descriptions = {
            "action_validation": "Invalid IAM Action",
            "condition_key_validation": "Invalid Condition Key",
            "condition_type_mismatch": "Condition Type Mismatch",
            "resource_validation": "Invalid Resource ARN",
            "sid_uniqueness": "Duplicate Statement ID",
            "policy_size": "Policy Size Exceeded",
            "policy_structure": "Invalid Policy Structure",
            "set_operator_validation": "Invalid Set Operator",
            "mfa_condition_check": "Missing MFA Condition",
            "principal_validation": "Invalid Principal",
            "policy_type_validation": "Policy Type Mismatch",
            "action_resource_matching": "Action-Resource Mismatch",
            "trust_policy_validation": "Trust Policy Issue",
            "wildcard_action": "Wildcard Action",
            "wildcard_resource": "Wildcard Resource",
            "full_wildcard": "Full Wildcard Permission",
            "service_wildcard": "Service-Wide Wildcard",
            "sensitive_action": "Sensitive Action",
            "action_condition_enforcement": "Missing Required Condition",
        }

        if issue.check_id and issue.check_id in descriptions:
            return descriptions[issue.check_id]

        # Fall back to formatting issue_type
        return issue.issue_type.replace("_", " ").title()

    def _get_rule_full_description(self, issue: ValidationIssue) -> str:
        """Get a full description for the rule, using risk_explanation if available."""
        if issue.risk_explanation:
            return issue.risk_explanation

        # Default descriptions based on check_id
        descriptions = {
            "action_validation": "The specified IAM action does not exist in AWS or is incorrectly formatted.",
            "condition_key_validation": "The specified condition key is not valid for this action or service.",
            "condition_type_mismatch": "The condition operator does not match the expected type for the condition key.",
            "resource_validation": "The resource ARN format is invalid or does not match the expected pattern.",
            "sid_uniqueness": "Multiple statements use the same Statement ID (Sid), which can cause confusion and policy conflicts.",
            "policy_size": "The policy exceeds AWS size limits and may fail to apply.",
            "policy_structure": "The policy structure is invalid and will be rejected by AWS.",
            "wildcard_action": "Using wildcard (*) in actions grants broader permissions than necessary, violating least privilege.",
            "wildcard_resource": "Using wildcard (*) in resources allows actions on all resources of that type.",
            "full_wildcard": "Using Action: '*' with Resource: '*' grants full administrative access.",
            "service_wildcard": "Using service:* grants all permissions for a service, which is overly permissive.",
            "sensitive_action": "This action can modify security-critical resources and should be carefully restricted.",
            "action_condition_enforcement": "Sensitive actions require specific conditions to prevent security issues.",
        }

        if issue.check_id and issue.check_id in descriptions:
            return descriptions[issue.check_id]

        return issue.message

    def _get_default_help_uri(self, issue: ValidationIssue) -> str:
        """Get default AWS documentation URL based on issue type."""
        uri_map = {
            "action_validation": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html",
            "condition_key_validation": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html",
            "resource_validation": "https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html",
            "sid_uniqueness": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_sid.html",
            "principal_validation": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html",
            "wildcard_action": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
            "wildcard_resource": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
            "sensitive_action": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-policy-conditions",
        }

        if issue.check_id and issue.check_id in uri_map:
            return uri_map[issue.check_id]

        return "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"

    def _build_help_markdown(self, issue: ValidationIssue) -> str:
        """Build markdown help text with remediation guidance.

        Args:
            issue: The validation issue

        Returns:
            Markdown-formatted help text
        """
        parts: list[str] = []

        # Add risk explanation
        if issue.risk_explanation:
            parts.append(f"**Why this matters:** {issue.risk_explanation}")
            parts.append("")

        # Add remediation steps
        if issue.remediation_steps:
            parts.append("**How to fix:**")
            for i, step in enumerate(issue.remediation_steps, 1):
                parts.append(f"{i}. {step}")
            parts.append("")

        # Add suggestion
        if issue.suggestion:
            parts.append(f"**Suggestion:** {issue.suggestion}")
            parts.append("")

        # Add example
        if issue.example:
            parts.append("**Example:**")
            parts.append("```json")
            parts.append(issue.example)
            parts.append("```")

        return "\n".join(parts) if parts else ""

    def _create_results(
        self, report: ValidationReport, severity_map: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Create SARIF results from validation issues with full context.

        Each result includes:
        - Rule reference and severity level
        - Full message with risk explanation
        - Location with line number
        - Related locations for affected fields
        - Fix suggestions with examples
        - Properties with additional metadata
        """
        results = []

        for policy_result in report.results:
            if not policy_result.issues:
                continue

            for issue in policy_result.issues:
                result = {
                    "ruleId": self._get_rule_id(issue),
                    "level": severity_map.get(issue.severity, "note"),
                    "message": {"text": self._build_result_message(issue)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": policy_result.policy_file,
                                    "uriBaseId": "SRCROOT",
                                },
                                "region": {
                                    "startLine": issue.line_number or 1,
                                    "startColumn": 1,
                                },
                            }
                        }
                    ],
                }

                # Add fix suggestions if available
                fixes = self._build_fixes(issue)
                if fixes:
                    result["fixes"] = fixes

                # Add related locations for affected fields
                related = self._build_related_locations(issue, policy_result.policy_file)
                if related:
                    result["relatedLocations"] = related

                # Add properties with additional metadata
                properties = self._build_properties(issue)
                if properties:
                    result["properties"] = properties

                results.append(result)

        return results

    def _build_result_message(self, issue: ValidationIssue) -> str:
        """Build a comprehensive result message including context.

        Args:
            issue: The validation issue

        Returns:
            Formatted message string
        """
        parts = [issue.message]

        # Add risk explanation if present
        if issue.risk_explanation:
            parts.append(f"\n\nWhy this matters: {issue.risk_explanation}")

        # Add affected fields context
        affected = []
        if issue.action:
            affected.append(f"Action: {issue.action}")
        if issue.resource:
            affected.append(f"Resource: {issue.resource}")
        if issue.condition_key:
            affected.append(f"Condition Key: {issue.condition_key}")

        if affected:
            parts.append(f"\n\nAffected: {', '.join(affected)}")

        return "".join(parts)

    def _build_fixes(self, issue: ValidationIssue) -> list[dict[str, Any]]:
        """Build SARIF fix objects from issue suggestions.

        Args:
            issue: The validation issue

        Returns:
            List of SARIF fix objects
        """
        fixes = []

        # Add suggestion as a fix
        if issue.suggestion:
            fix: dict[str, Any] = {"description": {"text": issue.suggestion}}

            # If we have an example, include it as replacement text
            if issue.example:
                fix["description"]["text"] += f"\n\nExample:\n{issue.example}"

            fixes.append(fix)

        # Add remediation steps as a separate fix entry
        if issue.remediation_steps:
            remediation_text = "How to fix:\n" + "\n".join(
                f"{i}. {step}" for i, step in enumerate(issue.remediation_steps, 1)
            )
            fixes.append({"description": {"text": remediation_text}})

        return fixes

    def _build_related_locations(
        self, issue: ValidationIssue, policy_file: str
    ) -> list[dict[str, Any]]:
        """Build related locations for affected fields.

        Args:
            issue: The validation issue
            policy_file: Path to the policy file

        Returns:
            List of SARIF related location objects
        """
        related = []

        # Add statement context
        if issue.statement_sid:
            related.append(
                {
                    "id": 0,
                    "message": {"text": f"Statement: {issue.statement_sid}"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": policy_file, "uriBaseId": "SRCROOT"},
                        "region": {"startLine": issue.line_number or 1},
                    },
                }
            )

        return related

    def _build_properties(self, issue: ValidationIssue) -> dict[str, Any]:
        """Build SARIF properties with additional metadata.

        Args:
            issue: The validation issue

        Returns:
            Dictionary of custom properties
        """
        properties: dict[str, Any] = {}

        # Add check ID
        if issue.check_id:
            properties["checkId"] = issue.check_id

        # Add issue type
        properties["issueType"] = issue.issue_type

        # Add statement info
        properties["statementIndex"] = issue.statement_index
        if issue.statement_sid:
            properties["statementSid"] = issue.statement_sid

        # Add severity category
        if issue.is_security_severity():
            properties["severityCategory"] = "security"
        else:
            properties["severityCategory"] = "validity"

        # Add affected fields
        if issue.action:
            properties["action"] = issue.action
        if issue.resource:
            properties["resource"] = issue.resource
        if issue.condition_key:
            properties["conditionKey"] = issue.condition_key
        if issue.field_name:
            properties["fieldName"] = issue.field_name

        # Add documentation URL
        if issue.documentation_url:
            properties["documentationUrl"] = issue.documentation_url

        # Add remediation steps as array
        if issue.remediation_steps:
            properties["remediationSteps"] = issue.remediation_steps

        return properties

    def _get_rule_id(self, issue: ValidationIssue) -> str:
        """Map issue to SARIF rule ID.

        Uses check_id as the primary identifier (matches dynamically generated rules).
        Falls back to issue_type if check_id is not available.

        Args:
            issue: The validation issue

        Returns:
            SARIF rule ID string
        """
        # Prefer check_id as it's more specific and matches the check that raised it
        if issue.check_id:
            return issue.check_id

        # Fall back to issue_type
        return issue.issue_type

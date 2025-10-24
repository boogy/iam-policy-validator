"""SARIF (Static Analysis Results Interchange Format) formatter for GitHub integration."""

import json
from datetime import datetime, timezone
from typing import Any

from iam_validator.core.formatters.base import OutputFormatter
from iam_validator.core.models import ValidationIssue, ValidationReport


class SARIFFormatter(OutputFormatter):
    """Formats validation results in SARIF format for GitHub code scanning."""

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

    def _create_sarif_output(
        self, report: ValidationReport, **kwargs
    ) -> dict[str, Any]:
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
                            "rules": self._create_rules(),
                        }
                    },
                    "results": self._create_results(report, severity_map),
                    "invocations": [
                        {
                            "executionSuccessful": len(
                                [r for r in report.results if r.is_valid]
                            )
                            > 0,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                }
            ],
        }

        return sarif

    def _create_rules(self) -> list[dict[str, Any]]:
        """Create SARIF rules definitions."""
        return [
            {
                "id": "invalid-action",
                "shortDescription": {"text": "Invalid IAM Action"},
                "fullDescription": {
                    "text": "The specified IAM action does not exist in AWS"
                },
                "helpUri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html",
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "invalid-condition-key",
                "shortDescription": {"text": "Invalid Condition Key"},
                "fullDescription": {
                    "text": "The specified condition key is not valid for this action"
                },
                "helpUri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html",
                "defaultConfiguration": {"level": "warning"},
            },
            {
                "id": "invalid-resource",
                "shortDescription": {"text": "Invalid Resource ARN"},
                "fullDescription": {"text": "The resource ARN format is invalid"},
                "helpUri": "https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html",
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "security-wildcard",
                "shortDescription": {"text": "Overly Permissive Wildcard"},
                "fullDescription": {
                    "text": "Using wildcards in actions or resources can be a security risk"
                },
                "helpUri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                "defaultConfiguration": {"level": "warning"},
            },
            {
                "id": "security-sensitive-action",
                "shortDescription": {"text": "Sensitive Action Without Conditions"},
                "fullDescription": {
                    "text": "Sensitive actions should have condition restrictions"
                },
                "defaultConfiguration": {"level": "warning"},
            },
        ]

    def _create_results(
        self, report: ValidationReport, severity_map: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Create SARIF results from validation issues."""
        results = []

        for policy_result in report.results:
            if not policy_result.issues:
                continue

            for issue in policy_result.issues:
                result = {
                    "ruleId": self._get_rule_id(issue),
                    "level": severity_map.get(issue.severity, "note"),
                    "message": {"text": issue.message},
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
                if issue.suggestion:
                    result["fixes"] = [
                        {
                            "description": {"text": issue.suggestion},
                        }
                    ]

                results.append(result)

        return results

    def _get_rule_id(self, issue: ValidationIssue) -> str:
        """Map issue to SARIF rule ID."""
        message_lower = issue.message.lower()

        if "action" in message_lower and "not found" in message_lower:
            return "invalid-action"
        elif "condition key" in message_lower:
            return "invalid-condition-key"
        elif "arn" in message_lower or "resource" in message_lower:
            return "invalid-resource"
        elif "wildcard" in message_lower or "*" in issue.message:
            return "security-wildcard"
        elif "sensitive" in message_lower:
            return "security-sensitive-action"
        else:
            return "general-issue"

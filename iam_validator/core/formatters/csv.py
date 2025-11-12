"""CSV formatter for IAM Policy Validator."""

import csv
import io
from typing import Any

from iam_validator.core import constants
from iam_validator.core.formatters.base import OutputFormatter
from iam_validator.core.models import ValidationReport


class CSVFormatter(OutputFormatter):
    """Formats validation results as CSV for spreadsheet analysis."""

    @property
    def format_id(self) -> str:
        return "csv"

    @property
    def description(self) -> str:
        return "CSV format for spreadsheet import and analysis"

    @property
    def file_extension(self) -> str:
        return "csv"

    @property
    def content_type(self) -> str:
        return "text/csv"

    def format(self, report: ValidationReport, **kwargs) -> str:
        """Format report as CSV.

        Args:
            report: The validation report
            **kwargs: Additional options like 'include_summary'

        Returns:
            CSV string
        """
        include_summary = kwargs.get("include_summary", True)
        include_header = kwargs.get("include_header", True)

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        if include_summary:
            self._write_summary_section(writer, report)
            writer.writerow([])  # Empty row separator

        self._write_issues_section(writer, report, include_header)

        return output.getvalue()

    def _write_summary_section(self, writer: Any, report: ValidationReport) -> None:
        """Write summary statistics to CSV."""
        # Count issues by severity - support both IAM validity and security severities
        errors = sum(
            1
            for r in report.results
            for i in r.issues
            if i.severity in constants.HIGH_SEVERITY_LEVELS
        )
        warnings = sum(
            1 for r in report.results for i in r.issues if i.severity in ("warning", "medium")
        )
        infos = sum(1 for r in report.results for i in r.issues if i.severity in ("info", "low"))

        writer.writerow(["Summary Statistics"])
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Total Policies", report.total_policies])
        writer.writerow(["Valid Policies (IAM)", report.valid_policies])
        writer.writerow(["Invalid Policies (IAM)", report.invalid_policies])
        writer.writerow(["Policies with Security Findings", report.policies_with_security_issues])
        writer.writerow(["Total Issues", report.total_issues])
        writer.writerow(["Validity Issues", report.validity_issues])
        writer.writerow(["Security Issues", report.security_issues])
        writer.writerow([""])
        writer.writerow(["Legacy Severity Breakdown"])
        writer.writerow(["Errors", errors])
        writer.writerow(["Warnings", warnings])
        writer.writerow(["Info", infos])

    def _write_issues_section(
        self, writer: Any, report: ValidationReport, include_header: bool
    ) -> None:
        """Write detailed issues to CSV."""
        if include_header:
            writer.writerow(
                [
                    "Policy File",
                    "Statement Index",
                    "Statement SID",
                    "Line Number",
                    "Severity",
                    "Issue Type",
                    "Action",
                    "Resource",
                    "Condition Key",
                    "Message",
                    "Suggestion",
                ]
            )

        for policy_result in report.results:
            for issue in policy_result.issues:
                writer.writerow(
                    [
                        policy_result.policy_file,
                        (issue.statement_index + 1 if issue.statement_index is not None else ""),
                        issue.statement_sid or "",
                        issue.line_number or "",
                        issue.severity,
                        issue.issue_type or "",
                        issue.action or "",
                        issue.resource or "",
                        issue.condition_key or "",
                        issue.message,
                        issue.suggestion or "",
                    ]
                )

    def format_pivot_table(self, report: ValidationReport) -> str:
        """Format report as a pivot table CSV for analysis.

        Groups issues by check_id and severity for easy analysis.
        """
        output = io.StringIO()
        writer = csv.writer(output)

        # Create pivot data
        pivot_data = self._create_pivot_data(report)

        # Write header
        writer.writerow(["Issue Type", "Severity", "Count", "Policy Files"])

        # Write pivot rows
        for (issue_type, severity), data in sorted(pivot_data.items()):
            writer.writerow(
                [
                    issue_type or "unknown",
                    severity,
                    data["count"],
                    "; ".join(data["files"][:5]) + ("..." if len(data["files"]) > 5 else ""),
                ]
            )

        return output.getvalue()

    def _create_pivot_data(self, report: ValidationReport) -> dict[tuple, dict[str, Any]]:
        """Create pivot table data structure."""
        pivot_data = {}

        for policy_result in report.results:
            for issue in policy_result.issues:
                key = (issue.issue_type or "unknown", issue.severity)

                if key not in pivot_data:
                    pivot_data[key] = {
                        "count": 0,
                        "files": set(),
                    }

                pivot_data[key]["count"] += 1
                pivot_data[key]["files"].add(policy_result.policy_file)

        # Convert sets to lists
        for key in pivot_data:
            pivot_data[key]["files"] = sorted(list(pivot_data[key]["files"]))

        return pivot_data

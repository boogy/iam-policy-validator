"""HTML formatter for IAM Policy Validator with interactive features."""

import html
from datetime import datetime

from iam_validator.core.formatters.base import OutputFormatter
from iam_validator.core.models import ValidationReport


class HTMLFormatter(OutputFormatter):
    """Formats validation results as interactive HTML report."""

    @property
    def format_id(self) -> str:
        return "html"

    @property
    def description(self) -> str:
        return "Interactive HTML report with filtering and search"

    @property
    def file_extension(self) -> str:
        return "html"

    @property
    def content_type(self) -> str:
        return "text/html"

    def format(self, report: ValidationReport, **kwargs) -> str:
        """Format report as HTML.

        Args:
            report: The validation report
            **kwargs: Additional options like 'title', 'include_charts'

        Returns:
            HTML string
        """
        title = kwargs.get("title", "IAM Policy Validation Report")
        include_charts = kwargs.get("include_charts", True)
        dark_mode = kwargs.get("dark_mode", False)

        html_content = f"""<!DOCTYPE html>
<html lang="en" class="{" dark" if dark_mode else ""}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    {self._get_styles(dark_mode)}
    {self._get_scripts(include_charts)}
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ {html.escape(title)}</h1>
            <div class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
        </header>

        {self._render_summary(report, include_charts)}
        {self._render_filters()}
        {self._render_issues_table(report)}
        {self._render_policy_details(report)}
    </div>

    {self._get_javascript()}
</body>
</html>"""

        return html_content

    def _get_styles(self, dark_mode: bool) -> str:
        """Get CSS styles for the report."""
        return """
    <style>
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
            --error-color: #dc3545;
            --warning-color: #ffc107;
            --info-color: #0dcaf0;
            --success-color: #198754;
        }

        .dark {
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --border-color: #404040;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }

        h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }

        .timestamp {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 20px;
            border: 1px solid var(--border-color);
            transition: transform 0.2s;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }

        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
        }

        .filters {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }

        .filter-row {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .filter-group {
            flex: 1;
            min-width: 200px;
        }

        .filter-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
        }

        .filter-group input,
        .filter-group select {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: var(--bg-primary);
            color: var(--text-primary);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }

        th {
            background: var(--bg-primary);
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid var(--border-color);
        }

        td {
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }

        tr:hover {
            background: var(--bg-primary);
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        /* IAM Validity Severities */
        .severity-error {
            background: #dc3545;
            color: white;
        }

        .severity-warning {
            background: #ffc107;
            color: #333;
        }

        .severity-info {
            background: #0dcaf0;
            color: white;
        }

        /* Security Severities */
        .severity-critical {
            background: #8b0000;
            color: white;
        }

        .severity-high {
            background: #ff6b6b;
            color: white;
        }

        .severity-medium {
            background: #ffa500;
            color: #333;
        }

        .severity-low {
            background: #90caf9;
            color: #333;
        }

        .chart-container {
            position: relative;
            height: 300px;
            margin: 20px 0;
        }

        .hidden {
            display: none;
        }

        .expandable {
            cursor: pointer;
        }

        .expandable:hover {
            text-decoration: underline;
        }

        .details-panel {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 15px;
            margin-top: 10px;
        }

        .code-block {
            background: #f5f5f5;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
        }

        .dark .code-block {
            background: #1e1e1e;
        }
    </style>
        """

    def _get_scripts(self, include_charts: bool) -> str:
        """Get JavaScript dependencies."""
        scripts = ""
        if include_charts:
            scripts += """
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            """
        return scripts

    def _render_summary(self, report: ValidationReport, include_charts: bool) -> str:
        """Render summary section with statistics."""
        total_issues = report.total_issues

        html_parts = [
            f"""
        <section class="summary">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="stat-card">
                    <div class="stat-value">{report.total_policies}</div>
                    <div class="stat-label">Total Policies</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--success-color)">{report.valid_policies}</div>
                    <div class="stat-label">Valid (IAM)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--error-color)">{report.invalid_policies}</div>
                    <div class="stat-label">Invalid (IAM)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--warning-color)">{report.policies_with_security_issues}</div>
                    <div class="stat-label">Security Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{total_issues}</div>
                    <div class="stat-label">Total Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--error-color)">{report.validity_issues}</div>
                    <div class="stat-label">Validity Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--warning-color)">{report.security_issues}</div>
                    <div class="stat-label">Security Issues</div>
                </div>
            </div>
        """
        ]

        if include_charts and total_issues > 0:
            html_parts.append(
                """
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
            """
            )

        html_parts.append("</section>")
        return "".join(html_parts)

    def _render_filters(self) -> str:
        """Render filter controls."""
        return """
        <section class="filters">
            <h2>Filters</h2>
            <div class="filter-row">
                <div class="filter-group">
                    <label for="searchInput">Search</label>
                    <input type="text" id="searchInput" placeholder="Search messages...">
                </div>
                <div class="filter-group">
                    <label for="severityFilter">Severity</label>
                    <select id="severityFilter">
                        <option value="">All</option>
                        <optgroup label="IAM Validity">
                            <option value="error">Error</option>
                            <option value="warning">Warning</option>
                            <option value="info">Info</option>
                        </optgroup>
                        <optgroup label="Security">
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </optgroup>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="fileFilter">Policy File</label>
                    <select id="fileFilter">
                        <option value="">All Files</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="checkFilter">Check Type</label>
                    <select id="checkFilter">
                        <option value="">All Checks</option>
                    </select>
                </div>
            </div>
        </section>
        """

    def _format_suggestion(self, suggestion: str) -> str:
        """Format suggestion field to show examples in code blocks."""
        if not suggestion:
            return "-"

        # Check if suggestion contains "Example:" section
        if "\nExample:\n" in suggestion:
            parts = suggestion.split("\nExample:\n", 1)
            text_part = html.escape(parts[0])
            code_part = html.escape(parts[1])

            return f"""
                <div>
                    <div>{text_part}</div>
                    <details style="margin-top: 10px;">
                        <summary style="cursor: pointer; font-weight: 500; color: var(--text-secondary);">
                            📖 View Example
                        </summary>
                        <pre class="code-block" style="margin-top: 10px; white-space: pre-wrap;">{code_part}</pre>
                    </details>
                </div>
            """
        else:
            return html.escape(suggestion)

    def _render_issues_table(self, report: ValidationReport) -> str:
        """Render issues table."""
        rows = []
        for policy_result in report.results:
            for issue in policy_result.issues:
                formatted_suggestion = self._format_suggestion(issue.suggestion)

                row = f"""
                <tr class="issue-row"
                    data-severity="{issue.severity}"
                    data-file="{html.escape(policy_result.policy_file)}"
                    data-check="{html.escape(issue.issue_type or "")}"
                    data-message="{html.escape(issue.message.lower())}">
                    <td>{html.escape(policy_result.policy_file)}</td>
                    <td>{issue.line_number or "-"}</td>
                    <td><span class="severity-badge severity-{issue.severity}">{issue.severity}</span></td>
                    <td>{html.escape(issue.issue_type or "-")}</td>
                    <td>{html.escape(issue.message)}</td>
                    <td>{formatted_suggestion}</td>
                </tr>
                """
                rows.append(row)

        return f"""
        <section class="issues">
            <h2>Issues</h2>
            <table id="issuesTable">
                <thead>
                    <tr>
                        <th>Policy File</th>
                        <th>Line</th>
                        <th>Severity</th>
                        <th>Check</th>
                        <th>Message</th>
                        <th>Suggestion</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(rows) if rows else '<tr><td colspan="6" style="text-align: center">No issues found</td></tr>'}
                </tbody>
            </table>
        </section>
        """

    def _render_policy_details(self, report: ValidationReport) -> str:
        """Render detailed policy information."""
        details = []
        for policy_result in report.results:
            if not policy_result.issues:
                continue

            issues_by_statement = {}
            for issue in policy_result.issues:
                stmt_idx = issue.statement_index or -1
                if stmt_idx not in issues_by_statement:
                    issues_by_statement[stmt_idx] = []
                issues_by_statement[stmt_idx].append(issue)

            detail = f"""
            <div class="policy-detail" data-file="{html.escape(policy_result.policy_file)}">
                <h3>{html.escape(policy_result.policy_file)}</h3>
                <p>Total Issues: {len(policy_result.issues)}</p>
            """

            for stmt_idx, issues in sorted(issues_by_statement.items()):
                detail += f"""
                <div class="statement-issues">
                    <h4>Statement {stmt_idx + 1 if stmt_idx >= 0 else "Global"}</h4>
                    <ul>
                """
                for issue in issues:
                    detail += f"""
                        <li>
                            <span class="severity-badge severity-{issue.severity}">{issue.severity}</span>
                            {html.escape(issue.message)}
                            {f"<br><em>{html.escape(issue.suggestion)}</em>" if issue.suggestion else ""}
                        </li>
                    """
                detail += """
                    </ul>
                </div>
                """

            detail += "</div>"
            details.append(detail)

        return f"""
        <section class="policy-details hidden">
            <h2>Policy Details</h2>
            {"".join(details)}
        </section>
        """

    def _get_javascript(self) -> str:
        """Get JavaScript for interactivity."""
        return """
    <script>
        // Populate filter dropdowns
        document.addEventListener('DOMContentLoaded', function() {
            const rows = document.querySelectorAll('.issue-row');
            const files = new Set();
            const checks = new Set();

            rows.forEach(row => {
                files.add(row.dataset.file);
                checks.add(row.dataset.check);
            });

            const fileFilter = document.getElementById('fileFilter');
            files.forEach(file => {
                const option = document.createElement('option');
                option.value = file;
                option.textContent = file;
                fileFilter.appendChild(option);
            });

            const checkFilter = document.getElementById('checkFilter');
            checks.forEach(check => {
                if (check) {
                    const option = document.createElement('option');
                    option.value = check;
                    option.textContent = check;
                    checkFilter.appendChild(option);
                }
            });

            // Draw severity chart if Chart.js is loaded
            if (typeof Chart !== 'undefined') {
                const ctx = document.getElementById('severityChart');
                if (ctx) {
                    // Count all severity types
                    const criticalCount = document.querySelectorAll('[data-severity="critical"]').length;
                    const highCount = document.querySelectorAll('[data-severity="high"]').length;
                    const mediumCount = document.querySelectorAll('[data-severity="medium"]').length;
                    const lowCount = document.querySelectorAll('[data-severity="low"]').length;
                    const errorCount = document.querySelectorAll('[data-severity="error"]').length;
                    const warningCount = document.querySelectorAll('[data-severity="warning"]').length;
                    const infoCount = document.querySelectorAll('[data-severity="info"]').length;

                    // Build labels and data arrays dynamically
                    const labels = [];
                    const data = [];
                    const colors = [];

                    if (criticalCount > 0) {
                        labels.push('Critical');
                        data.push(criticalCount);
                        colors.push('rgba(139, 0, 0, 0.8)');
                    }
                    if (highCount > 0) {
                        labels.push('High');
                        data.push(highCount);
                        colors.push('rgba(255, 107, 107, 0.8)');
                    }
                    if (errorCount > 0) {
                        labels.push('Error');
                        data.push(errorCount);
                        colors.push('rgba(220, 53, 69, 0.8)');
                    }
                    if (mediumCount > 0) {
                        labels.push('Medium');
                        data.push(mediumCount);
                        colors.push('rgba(255, 165, 0, 0.8)');
                    }
                    if (warningCount > 0) {
                        labels.push('Warning');
                        data.push(warningCount);
                        colors.push('rgba(255, 193, 7, 0.8)');
                    }
                    if (infoCount > 0) {
                        labels.push('Info');
                        data.push(infoCount);
                        colors.push('rgba(13, 202, 240, 0.8)');
                    }
                    if (lowCount > 0) {
                        labels.push('Low');
                        data.push(lowCount);
                        colors.push('rgba(144, 202, 249, 0.8)');
                    }

                    new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: labels,
                            datasets: [{
                                data: data,
                                backgroundColor: colors
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    position: 'bottom',
                                }
                            }
                        }
                    });
                }
            }
        });

        // Filter functionality
        function filterTable() {
            const searchValue = document.getElementById('searchInput').value.toLowerCase();
            const severityValue = document.getElementById('severityFilter').value;
            const fileValue = document.getElementById('fileFilter').value;
            const checkValue = document.getElementById('checkFilter').value;

            const rows = document.querySelectorAll('.issue-row');

            rows.forEach(row => {
                const matchesSearch = !searchValue || row.dataset.message.includes(searchValue);
                const matchesSeverity = !severityValue || row.dataset.severity === severityValue;
                const matchesFile = !fileValue || row.dataset.file === fileValue;
                const matchesCheck = !checkValue || row.dataset.check === checkValue;

                if (matchesSearch && matchesSeverity && matchesFile && matchesCheck) {
                    row.classList.remove('hidden');
                } else {
                    row.classList.add('hidden');
                }
            });
        }

        // Attach filter event listeners
        document.getElementById('searchInput').addEventListener('input', filterTable);
        document.getElementById('severityFilter').addEventListener('change', filterTable);
        document.getElementById('fileFilter').addEventListener('change', filterTable);
        document.getElementById('checkFilter').addEventListener('change', filterTable);
    </script>
        """

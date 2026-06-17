#!/usr/bin/env python3
"""Render iam-policy-validator JSON findings into PR-comment markdown.

Portable, stdlib-only (Python 3.10+). Turns the JSON produced by
`iam-validator validate --format json` into the same comment layout the
validator posts itself — so a *separate* agent can verify findings and post
them, without re-implementing the rendering or depending on the validator's
source tree.

The layout mirrors `ValidationIssue.to_pr_comment()` but omits the validator's
hidden HTML bot/identifier markers (those exist only for the validator's own
comment-cleanup lifecycle and are not wanted when another agent posts).

Usage:
    # Human-readable: every finding's comment body, divider-separated
    python3 render_pr_comments.py findings.json

    # Machine-readable: JSON array of {policy_file, line_number, ..., body}
    python3 render_pr_comments.py findings.json --format json

    # Read from stdin and filter by minimum severity
    iam-validator validate --path ./policies/ --format json \\
        | python3 render_pr_comments.py - --min-severity high --format json
"""

from __future__ import annotations

import argparse
import json
import sys

# Severity → (emoji, action guidance). Mirrors core/constants.py SEVERITY_CONFIG.
SEVERITY_CONFIG: dict[str, tuple[str, str]] = {
    "critical": ("🔴", "Block deployment"),
    "high": ("🟠", "Fix before merge"),
    "medium": ("🟡", "Address soon"),
    "low": ("🔵", "Consider fixing"),
    "error": ("❌", "Must fix - AWS will reject"),
    "warning": ("⚠️", "Review"),
    "info": ("ℹ️", "Optional"),
}

# Higher = more severe. Used by --min-severity. Mirrors SEVERITY_RANK.
SEVERITY_RANK: dict[str, int] = {
    "error": 100,
    "critical": 90,
    "high": 70,
    "warning": 50,
    "medium": 40,
    "low": 20,
    "info": 10,
}

# Risk category → icon. Mirrors config/check_documentation.py RISK_CATEGORY_ICONS.
RISK_CATEGORY_ICONS: dict[str, str] = {
    "privilege_escalation": "🔐",
    "data_exfiltration": "📤",
    "denial_of_service": "🚫",
    "resource_exposure": "🌐",
    "credential_exposure": "🔑",
    "compliance": "📋",
    "configuration": "⚙️",
    "validation": "✅",
}


def render_body(issue: dict) -> str:
    """Build the PR-comment markdown body for one finding."""
    severity = issue.get("severity", "info")
    emoji, action_guidance = SEVERITY_CONFIG.get(severity, ("•", "Review"))

    risk_icon = ""
    risk_category = issue.get("risk_category")
    if risk_category:
        icon = RISK_CATEGORY_ICONS.get(risk_category, "")
        if icon:
            label = risk_category.replace("_", " ").title()
            risk_icon = f" | {icon} {label}"

    parts: list[str] = [f"{emoji} **{severity.upper()}** - {action_guidance}{risk_icon}", ""]

    context = f"Statement[{issue.get('statement_index')}]"
    if issue.get("statement_sid"):
        context = f"`{issue['statement_sid']}` ({context})"
    if issue.get("line_number"):
        context = f"{context} (line {issue['line_number']})"
    parts.append(f"**Statement:** {context}")
    parts.append("")
    parts.append(issue.get("message", ""))

    if issue.get("risk_explanation"):
        parts.append("")
        parts.append(f"> **Why this matters:** {issue['risk_explanation']}")

    field_action = issue.get("action")
    resource = issue.get("resource")
    condition_key = issue.get("condition_key")
    suggestion = issue.get("suggestion")
    example = issue.get("example")
    remediation_steps = issue.get("remediation_steps")

    if field_action or resource or condition_key or suggestion or example or remediation_steps:
        parts.extend(["", "<details>", "<summary>📋 <b>View Details</b></summary>", "", ""])

        if field_action or resource or condition_key:
            parts.append("**Affected Fields:**")
            if field_action:
                parts.append(f"  - Action: `{field_action}`")
            if resource:
                parts.append(f"  - Resource: `{resource}`")
            if condition_key:
                parts.append(f"  - Condition Key: `{condition_key}`")
            parts.append("")

        if remediation_steps:
            parts.append("**🔧 How to Fix:**")
            for i, step in enumerate(remediation_steps, 1):
                parts.append(f"  {i}. {step}")
            parts.append("")

        if suggestion:
            parts.extend(["**💡 Suggested Fix:**", "", suggestion, ""])

        if example:
            parts.extend(["**Example:**", "```json", example, "```"])

        parts.extend(["", "</details>"])

    footer: list[str] = []
    if issue.get("check_id"):
        footer.append(f"*Check: `{issue['check_id']}`*")
    if issue.get("documentation_url"):
        footer.append(f"[📖 Documentation]({issue['documentation_url']})")
    if footer:
        parts.extend(["", "---", " | ".join(footer)])

    return "\n".join(parts)


def iter_findings(report: dict, min_rank: int):
    """Yield (policy_file, issue) pairs above the severity threshold."""
    for result in report.get("results", []):
        policy_file = result.get("policy_file", "")
        for issue in result.get("issues", []):
            severity = issue.get("severity", "info")
            if severity == "none":
                continue
            if SEVERITY_RANK.get(severity, 0) < min_rank:
                continue
            yield policy_file, issue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", nargs="?", default="-", help="Validator JSON file, or '-' for stdin (default)")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format")
    parser.add_argument(
        "--min-severity",
        choices=list(SEVERITY_RANK),
        default="info",
        help="Drop findings below this severity (default: info = keep all)",
    )
    args = parser.parse_args(argv)

    raw = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8").read()
    try:
        report = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: input is not valid JSON: {exc}", file=sys.stderr)
        return 2

    min_rank = SEVERITY_RANK[args.min_severity]
    comments = []
    for policy_file, issue in iter_findings(report, min_rank):
        comments.append(
            {
                "policy_file": policy_file,
                "statement_index": issue.get("statement_index"),
                "statement_sid": issue.get("statement_sid"),
                "line_number": issue.get("line_number"),
                "field_name": issue.get("field_name"),
                "check_id": issue.get("check_id"),
                "issue_type": issue.get("issue_type"),
                "severity": issue.get("severity"),
                "action": issue.get("action"),
                "resource": issue.get("resource"),
                "condition_key": issue.get("condition_key"),
                "body": render_body(issue),
            }
        )

    if args.format == "json":
        print(json.dumps(comments, indent=2, ensure_ascii=False))
    else:
        for i, c in enumerate(comments):
            if i:
                print("\n\n")
            print(f"<!-- {c['policy_file']} | {c['check_id']} | statement {c['statement_index']} -->")
            print(c["body"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Validate command for IAM Policy Validator."""

import argparse
import logging
import os
from typing import cast

from iam_validator.commands.base import Command
from iam_validator.core.models import PolicyType, ValidationReport
from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.report import ReportGenerator
from iam_validator.integrations.github_integration import GitHubIntegration


class ValidateCommand(Command):
    """Command to validate IAM policies."""

    @property
    def name(self) -> str:
        return "validate"

    @property
    def help(self) -> str:
        return "Validate IAM policies"

    @property
    def epilog(self) -> str:
        return """
Examples:
  # Validate a single policy file
  iam-validator validate --path policy.json

  # Validate all policies in a directory
  iam-validator validate --path ./policies/

  # Validate multiple paths (files and directories)
  iam-validator validate --path policy1.json --path ./policies/ --path ./more-policies/

  # Read policy from stdin
  cat policy.json | iam-validator validate --stdin
  echo '{"Version":"2012-10-17","Statement":[...]}' | iam-validator validate --stdin

  # Use custom checks from a directory
  iam-validator validate --path ./policies/ --custom-checks-dir ./my-checks

  # Use offline mode with pre-downloaded AWS service definitions
  iam-validator validate --path ./policies/ --aws-services-dir ./aws_services

  # Generate JSON output
  iam-validator validate --path ./policies/ --format json --output report.json

  # Validate resource policies (S3 bucket policies, SNS topics, etc.)
  iam-validator validate --path ./bucket-policies/ --policy-type RESOURCE_POLICY

  # GitHub integration - all options (PR comment + review comments + job summary)
  iam-validator validate --path ./policies/ --github-comment --github-review --github-summary

  # Only line-specific review comments (clean, minimal)
  iam-validator validate --path ./policies/ --github-review

  # Only PR summary comment
  iam-validator validate --path ./policies/ --github-comment

  # Only GitHub Actions job summary
  iam-validator validate --path ./policies/ --github-summary
        """

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add validate command arguments."""
        # Create mutually exclusive group for input sources
        input_group = parser.add_mutually_exclusive_group(required=True)

        input_group.add_argument(
            "--path",
            "-p",
            action="append",
            dest="paths",
            help="Path to IAM policy file or directory (can be specified multiple times)",
        )

        input_group.add_argument(
            "--stdin",
            action="store_true",
            help="Read policy from stdin (JSON format)",
        )

        parser.add_argument(
            "--format",
            "-f",
            choices=["console", "enhanced", "json", "markdown", "html", "csv", "sarif"],
            default="console",
            help="Output format (default: console). Use 'enhanced' for modern visual output with Rich library",
        )

        parser.add_argument(
            "--output",
            "-o",
            help="Output file path (for json/markdown/html/csv/sarif formats)",
        )

        parser.add_argument(
            "--no-recursive",
            action="store_true",
            help="Don't recursively search directories",
        )

        parser.add_argument(
            "--fail-on-warnings",
            action="store_true",
            help="Fail validation if warnings are found (default: only fail on errors)",
        )

        parser.add_argument(
            "--policy-type",
            "-t",
            choices=[
                "IDENTITY_POLICY",
                "RESOURCE_POLICY",
                "TRUST_POLICY",
                "SERVICE_CONTROL_POLICY",
                "RESOURCE_CONTROL_POLICY",
            ],
            default="IDENTITY_POLICY",
            help="Type of IAM policy being validated (default: IDENTITY_POLICY). "
            "IDENTITY_POLICY: Attached to users/groups/roles | "
            "RESOURCE_POLICY: S3/SNS/SQS policies | "
            "TRUST_POLICY: Role assumption policies | "
            "SERVICE_CONTROL_POLICY: AWS Orgs SCPs | "
            "RESOURCE_CONTROL_POLICY: AWS Orgs RCPs",
        )

        parser.add_argument(
            "--github-comment",
            action="store_true",
            help="Post summary comment to PR conversation",
        )

        parser.add_argument(
            "--github-review",
            action="store_true",
            help="Create line-specific review comments on PR files",
        )

        parser.add_argument(
            "--github-summary",
            action="store_true",
            help="Write summary to GitHub Actions job summary (visible in Actions tab)",
        )

        parser.add_argument(
            "--verbose",
            "-v",
            action="store_true",
            help="Enable verbose logging",
        )

        parser.add_argument(
            "--config",
            "-c",
            help="Path to configuration file (default: auto-discover iam-validator.yaml)",
        )

        parser.add_argument(
            "--custom-checks-dir",
            help="Path to directory containing custom checks for auto-discovery",
        )

        parser.add_argument(
            "--aws-services-dir",
            help="Path to directory containing pre-downloaded AWS service definitions "
            "(enables offline mode, avoids API rate limiting). "
            "Use 'iam-validator download-services' to create this directory.",
        )

        parser.add_argument(
            "--stream",
            action="store_true",
            help="Process files one-by-one (memory efficient, progressive feedback)",
        )

        parser.add_argument(
            "--batch-size",
            type=int,
            default=10,
            help="Number of policies to process per batch (default: 10, only with --stream)",
        )

        parser.add_argument(
            "--no-summary",
            action="store_true",
            help="Hide Executive Summary section in enhanced format output",
        )

        parser.add_argument(
            "--no-severity-breakdown",
            action="store_true",
            help="Hide Issue Severity Breakdown section in enhanced format output",
        )

    async def execute(self, args: argparse.Namespace) -> int:
        """Execute the validate command."""
        # Check if streaming mode is enabled
        use_stream = getattr(args, "stream", False)

        # Auto-enable streaming for CI environments or large policy sets
        # to provide progressive feedback
        if not use_stream and os.getenv("CI"):
            logging.info(
                "CI environment detected, enabling streaming mode for progressive feedback"
            )
            use_stream = True

        if use_stream:
            return await self._execute_streaming(args)
        else:
            return await self._execute_batch(args)

    async def _execute_batch(self, args: argparse.Namespace) -> int:
        """Execute validation by loading all policies at once (original behavior)."""
        # Load policies from all specified paths or stdin
        loader = PolicyLoader()

        if args.stdin:
            # Read from stdin
            import json
            import sys

            stdin_content = sys.stdin.read()
            if not stdin_content.strip():
                logging.error("No policy data provided on stdin")
                return 1

            try:
                policy_data = json.loads(stdin_content)
                # Create a synthetic policy entry
                policies = [("stdin", policy_data)]
                logging.info("Loaded policy from stdin")
            except json.JSONDecodeError as e:
                logging.error(f"Invalid JSON from stdin: {e}")
                return 1
        else:
            # Load from paths
            policies = loader.load_from_paths(args.paths, recursive=not args.no_recursive)

            if not policies:
                logging.error(f"No valid IAM policies found in: {', '.join(args.paths)}")
                return 1

            logging.info(f"Loaded {len(policies)} policies from {len(args.paths)} path(s)")

        # Validate policies
        config_path = getattr(args, "config", None)
        custom_checks_dir = getattr(args, "custom_checks_dir", None)
        aws_services_dir = getattr(args, "aws_services_dir", None)
        policy_type = cast(PolicyType, getattr(args, "policy_type", "IDENTITY_POLICY"))
        results = await validate_policies(
            policies,
            config_path=config_path,
            custom_checks_dir=custom_checks_dir,
            policy_type=policy_type,
            aws_services_dir=aws_services_dir,
        )

        # Generate report (include parsing errors if any)
        generator = ReportGenerator()
        report = generator.generate_report(results, parsing_errors=loader.parsing_errors)

        # Output results
        if args.format is None:
            # Default: use classic console output (direct Rich printing)
            generator.print_console_report(report)
        elif args.format == "json":
            if args.output:
                generator.save_json_report(report, args.output)
            else:
                print(generator.generate_json_report(report))
        elif args.format == "markdown":
            if args.output:
                generator.save_markdown_report(report, args.output)
            else:
                print(generator.generate_github_comment(report))
        else:
            # Use formatter registry for other formats (enhanced, html, csv, sarif)
            # Pass options for enhanced format
            format_options = {}
            if args.format == "enhanced":
                format_options["show_summary"] = not getattr(args, "no_summary", False)
                format_options["show_severity_breakdown"] = not getattr(
                    args, "no_severity_breakdown", False
                )
            output_content = generator.format_report(report, args.format, **format_options)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output_content)
                logging.info(f"Saved {args.format.upper()} report to {args.output}")
            else:
                print(output_content)

        # Post to GitHub if configured
        if args.github_comment or getattr(args, "github_review", False):
            from iam_validator.core.config.config_loader import ConfigLoader
            from iam_validator.core.pr_commenter import PRCommenter

            # Load config to get fail_on_severity and severity_labels settings
            config = ConfigLoader.load_config(config_path)
            fail_on_severities = config.get_setting("fail_on_severity", ["error", "critical"])
            severity_labels = config.get_setting("severity_labels", {})

            async with GitHubIntegration() as github:
                commenter = PRCommenter(
                    github,
                    fail_on_severities=fail_on_severities,
                    severity_labels=severity_labels,
                )
                success = await commenter.post_findings_to_pr(
                    report,
                    create_review=getattr(args, "github_review", False),
                    add_summary_comment=args.github_comment,
                )
                if not success:
                    logging.error("Failed to post to GitHub PR")

        # Write to GitHub Actions job summary if configured
        if getattr(args, "github_summary", False):
            self._write_github_actions_summary(report)

        # Return exit code based on validation results
        if args.fail_on_warnings:
            return 0 if report.total_issues == 0 else 1
        else:
            return 0 if report.invalid_policies == 0 else 1

    async def _execute_streaming(self, args: argparse.Namespace) -> int:
        """Execute validation by streaming policies one-by-one.

        This provides:
        - Lower memory usage
        - Progressive feedback (see results as they come)
        - Partial results if errors occur
        - Better for CI/CD pipelines
        """
        loader = PolicyLoader()
        generator = ReportGenerator()
        config_path = getattr(args, "config", None)
        custom_checks_dir = getattr(args, "custom_checks_dir", None)
        policy_type = cast(PolicyType, getattr(args, "policy_type", "IDENTITY_POLICY"))

        all_results = []
        total_processed = 0

        # Clean up old review comments at the start (before posting any new ones)
        if getattr(args, "github_review", False):
            await self._cleanup_old_comments()

        logging.info(f"Starting streaming validation from {len(args.paths)} path(s)")

        # Process policies one at a time
        for file_path, policy in loader.stream_from_paths(
            args.paths, recursive=not args.no_recursive
        ):
            total_processed += 1
            logging.info(f"[{total_processed}] Processing: {file_path}")

            # Validate single policy
            results = await validate_policies(
                [(file_path, policy)],
                config_path=config_path,
                custom_checks_dir=custom_checks_dir,
                policy_type=policy_type,
            )

            if results:
                result = results[0]
                all_results.append(result)

                # Print immediate feedback for this file
                if args.format == "console":
                    if result.is_valid:
                        logging.info(f"  ✓ {file_path}: Valid")
                    else:
                        logging.warning(f"  ✗ {file_path}: {len(result.issues)} issue(s) found")
                        # Note: validation_success tracks overall status

                # Post to GitHub immediately for this file (progressive PR comments)
                if getattr(args, "github_review", False):
                    await self._post_file_review(result, args)

        if total_processed == 0:
            logging.error(f"No valid IAM policies found in: {', '.join(args.paths)}")
            return 1

        logging.info(f"\nCompleted validation of {total_processed} policies")

        # Generate final summary report
        report = generator.generate_report(all_results)

        # Output final results
        if args.format == "console":
            # Classic console output (direct Rich printing from report.py)
            generator.print_console_report(report)
        elif args.format == "json":
            if args.output:
                generator.save_json_report(report, args.output)
            else:
                print(generator.generate_json_report(report))
        elif args.format == "markdown":
            if args.output:
                generator.save_markdown_report(report, args.output)
            else:
                print(generator.generate_github_comment(report))
        else:
            # Use formatter registry for other formats (enhanced, html, csv, sarif)
            # Pass options for enhanced format
            format_options = {}
            if args.format == "enhanced":
                format_options["show_summary"] = not getattr(args, "no_summary", False)
                format_options["show_severity_breakdown"] = not getattr(
                    args, "no_severity_breakdown", False
                )
            output_content = generator.format_report(report, args.format, **format_options)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output_content)
                logging.info(f"Saved {args.format.upper()} report to {args.output}")
            else:
                print(output_content)

        # Post summary comment to GitHub (if requested and not already posted per-file reviews)
        if args.github_comment:
            from iam_validator.core.config.config_loader import ConfigLoader
            from iam_validator.core.pr_commenter import PRCommenter

            # Load config to get fail_on_severity and severity_labels settings
            config = ConfigLoader.load_config(config_path)
            fail_on_severities = config.get_setting("fail_on_severity", ["error", "critical"])
            severity_labels = config.get_setting("severity_labels", {})

            async with GitHubIntegration() as github:
                commenter = PRCommenter(
                    github,
                    fail_on_severities=fail_on_severities,
                    severity_labels=severity_labels,
                )
                success = await commenter.post_findings_to_pr(
                    report,
                    create_review=False,  # Already posted per-file reviews in streaming mode
                    add_summary_comment=True,
                )
                if not success:
                    logging.error("Failed to post summary to GitHub PR")

        # Write to GitHub Actions job summary if configured
        if getattr(args, "github_summary", False):
            self._write_github_actions_summary(report)

        # Return exit code based on validation results
        if args.fail_on_warnings:
            return 0 if report.total_issues == 0 else 1
        else:
            return 0 if report.invalid_policies == 0 else 1

    async def _cleanup_old_comments(self) -> None:
        """Clean up old bot review comments from previous validation runs.

        This ensures the PR stays clean without duplicate/stale comments.
        """
        try:
            from iam_validator.core.pr_commenter import PRCommenter

            async with GitHubIntegration() as github:
                if not github.is_configured():
                    return

                logging.info("Cleaning up old review comments from previous runs...")
                deleted = await github.cleanup_bot_review_comments(PRCommenter.REVIEW_IDENTIFIER)
                if deleted > 0:
                    logging.info(f"Removed {deleted} old comment(s)")
        except Exception as e:
            logging.warning(f"Failed to cleanup old comments: {e}")

    async def _post_file_review(self, result, args: argparse.Namespace) -> None:
        """Post review comments for a single file immediately.

        This provides progressive feedback in PRs as files are processed.
        """
        try:
            from iam_validator.core.config.config_loader import ConfigLoader
            from iam_validator.core.pr_commenter import PRCommenter

            async with GitHubIntegration() as github:
                if not github.is_configured():
                    return

                # Load config to get fail_on_severity setting
                config_path = getattr(args, "config", None)
                config = ConfigLoader.load_config(config_path)
                fail_on_severities = config.get_setting("fail_on_severity", ["error", "critical"])

                # In streaming mode, don't cleanup comments (we want to keep earlier files)
                # Cleanup will happen once at the end
                commenter = PRCommenter(
                    github,
                    cleanup_old_comments=False,
                    fail_on_severities=fail_on_severities,
                )

                # Create a mini-report for just this file
                generator = ReportGenerator()
                mini_report = generator.generate_report([result])

                # Post line-specific comments
                await commenter.post_findings_to_pr(
                    mini_report,
                    create_review=True,
                    add_summary_comment=False,  # Summary comes later
                )
        except Exception as e:
            logging.warning(f"Failed to post review for {result.policy_file}: {e}")

    def _write_github_actions_summary(self, report: ValidationReport) -> None:
        """Write a high-level summary to GitHub Actions job summary.

        This appears in the Actions tab and provides a quick overview without all details.
        Uses GITHUB_STEP_SUMMARY environment variable.

        Args:
            report: Validation report to summarize
        """
        summary_file = os.getenv("GITHUB_STEP_SUMMARY")
        if not summary_file:
            logging.warning(
                "--github-summary specified but GITHUB_STEP_SUMMARY env var not found. "
                "This feature only works in GitHub Actions."
            )
            return

        try:
            # Generate high-level summary (no detailed issue list)
            summary_parts = []

            # Header with status
            if report.total_issues == 0:
                summary_parts.append("# ✅ IAM Policy Validation - Passed")
            elif report.invalid_policies > 0:
                summary_parts.append("# ❌ IAM Policy Validation - Failed")
            else:
                summary_parts.append("# ⚠️ IAM Policy Validation - Security Issues Found")

            summary_parts.append("")

            # Summary table
            summary_parts.append("## Summary")
            summary_parts.append("")
            summary_parts.append("| Metric | Count |")
            summary_parts.append("|--------|-------|")
            summary_parts.append(f"| Total Policies | {report.total_policies} |")
            summary_parts.append(f"| Valid Policies | {report.valid_policies} |")
            summary_parts.append(f"| Invalid Policies | {report.invalid_policies} |")
            summary_parts.append(
                f"| Policies with Security Issues | {report.policies_with_security_issues} |"
            )
            summary_parts.append(f"| **Total Issues** | **{report.total_issues}** |")

            # Issue breakdown by severity if there are issues
            if report.total_issues > 0:
                summary_parts.append("")
                summary_parts.append("## 📊 Issues by Severity")
                summary_parts.append("")

                # Count issues by severity
                severity_counts: dict[str, int] = {}
                for result in report.results:
                    for issue in result.issues:
                        severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1

                # Sort by severity rank (highest first)
                from iam_validator.core.models import ValidationIssue

                sorted_severities = sorted(
                    severity_counts.items(),
                    key=lambda x: ValidationIssue.SEVERITY_RANK.get(x[0], 0),
                    reverse=True,
                )

                summary_parts.append("| Severity | Count |")
                summary_parts.append("|----------|-------|")
                for severity, count in sorted_severities:
                    emoji = {
                        "error": "❌",
                        "critical": "🔴",
                        "high": "🟠",
                        "warning": "⚠️",
                        "medium": "🟡",
                        "low": "🔵",
                        "info": "ℹ️",
                    }.get(severity, "•")
                    summary_parts.append(f"| {emoji} {severity.upper()} | {count} |")

            # Add footer with links
            summary_parts.append("")
            summary_parts.append("---")
            summary_parts.append("")
            summary_parts.append(
                "📝 For detailed findings, check the PR comments or review the workflow logs."
            )

            # Write to summary file (append mode)
            with open(summary_file, "a", encoding="utf-8") as f:
                f.write("\n".join(summary_parts))
                f.write("\n")

            logging.info("Wrote summary to GitHub Actions job summary")

        except Exception as e:
            logging.warning(f"Failed to write GitHub Actions summary: {e}")

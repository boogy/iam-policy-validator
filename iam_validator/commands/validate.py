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

  # CI mode: show enhanced output in logs, save JSON to file
  iam-validator validate --path ./policies/ --ci --github-review
  iam-validator validate --path ./policies/ --ci --ci-output results.json
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
            "--summary",
            action="store_true",
            help="Show Executive Summary section in enhanced format output",
        )

        parser.add_argument(
            "--severity-breakdown",
            action="store_true",
            help="Show Issue Severity Breakdown section in enhanced format output",
        )

        parser.add_argument(
            "--allow-owner-ignore",
            action="store_true",
            default=True,
            help="Allow CODEOWNERS to ignore findings by replying 'ignore' to review comments (default: enabled)",
        )

        parser.add_argument(
            "--no-owner-ignore",
            action="store_true",
            help="Disable CODEOWNERS ignore feature",
        )

        parser.add_argument(
            "--ci",
            action="store_true",
            help="CI mode: print enhanced console output for visibility in job logs, "
            "and write JSON report to file (use --ci-output to specify filename, "
            "defaults to 'validation-report.json').",
        )

        parser.add_argument(
            "--ci-output",
            default="validation-report.json",
            help="Output file for JSON report in CI mode (default: validation-report.json)",
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

        # Handle --ci flag: show enhanced output in console, write JSON to file
        ci_mode = getattr(args, "ci", False)
        if ci_mode:
            # CI mode: enhanced output to console, JSON to file
            self._print_ci_console_output(report, generator)
            ci_output_file = getattr(args, "ci_output", "validation-report.json")
            generator.save_json_report(report, ci_output_file)
            logging.info(f"Saved JSON report to {ci_output_file}")
        elif args.format is None:
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
                format_options["show_summary"] = getattr(args, "summary", False)
                format_options["show_severity_breakdown"] = getattr(
                    args, "severity_breakdown", False
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

            # Load config to get fail_on_severity, severity_labels, and ignore settings
            config = ConfigLoader.load_config(config_path)
            fail_on_severities = config.get_setting("fail_on_severity", ["error", "critical"])
            severity_labels = config.get_setting("severity_labels", {})

            # Get ignore settings from config, but CLI flag can override
            ignore_settings = config.get_setting("ignore_settings", {})
            enable_ignore = ignore_settings.get("enabled", True)
            # CLI --no-owner-ignore takes precedence
            if getattr(args, "no_owner_ignore", False):
                enable_ignore = False
            allowed_users = ignore_settings.get("allowed_users", [])

            async with GitHubIntegration() as github:
                commenter = PRCommenter(
                    github,
                    fail_on_severities=fail_on_severities,
                    severity_labels=severity_labels,
                    enable_codeowners_ignore=enable_ignore,
                    allowed_ignore_users=allowed_users,
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
        # Track all validated files across the streaming session for final cleanup
        all_validated_files: set[str] = set()

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

                # Track validated file (convert to relative path for cleanup)
                relative_path = self._make_relative_path(file_path)
                if relative_path:
                    all_validated_files.add(relative_path)

                # Print immediate feedback for this file
                if args.format == "console":
                    if result.is_valid:
                        logging.info(f"  ✓ {file_path}: Valid")
                    else:
                        logging.warning(f"  ✗ {file_path}: {len(result.issues)} issue(s) found")
                        # Note: validation_success tracks overall status

                # Post to GitHub immediately for this file (progressive PR comments)
                # skip_cleanup=True because we process files one at a time and don't want
                # to delete comments from files processed earlier. Cleanup runs at the end.
                if getattr(args, "github_review", False):
                    await self._post_file_review(result, args)

        if total_processed == 0:
            logging.error(f"No valid IAM policies found in: {', '.join(args.paths)}")
            return 1

        logging.info(f"\nCompleted validation of {total_processed} policies")

        # Run final cleanup after all files are processed
        # This uses the full report to know all current findings and deletes stale comments
        if getattr(args, "github_review", False):
            await self._run_final_review_cleanup(args, all_results, all_validated_files)

        # Generate final summary report
        report = generator.generate_report(all_results)

        # Handle --ci flag: show enhanced output in console, write JSON to file
        ci_mode = getattr(args, "ci", False)
        if ci_mode:
            # CI mode: enhanced output to console, JSON to file
            self._print_ci_console_output(report, generator)
            ci_output_file = getattr(args, "ci_output", "validation-report.json")
            generator.save_json_report(report, ci_output_file)
            logging.info(f"Saved JSON report to {ci_output_file}")
        elif args.format == "console":
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
                format_options["show_summary"] = getattr(args, "summary", False)
                format_options["show_severity_breakdown"] = getattr(
                    args, "severity_breakdown", False
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

            # Load config to get fail_on_severity, severity_labels, and ignore settings
            config = ConfigLoader.load_config(config_path)
            fail_on_severities = config.get_setting("fail_on_severity", ["error", "critical"])
            severity_labels = config.get_setting("severity_labels", {})

            # Get ignore settings from config, but CLI flag can override
            ignore_settings = config.get_setting("ignore_settings", {})
            enable_ignore = ignore_settings.get("enabled", True)
            # CLI --no-owner-ignore takes precedence
            if getattr(args, "no_owner_ignore", False):
                enable_ignore = False
            allowed_users = ignore_settings.get("allowed_users", [])

            async with GitHubIntegration() as github:
                commenter = PRCommenter(
                    github,
                    fail_on_severities=fail_on_severities,
                    severity_labels=severity_labels,
                    enable_codeowners_ignore=enable_ignore,
                    allowed_ignore_users=allowed_users,
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

    async def _cleanup_old_comments(self, args: argparse.Namespace) -> None:
        """Clean up old bot review comments from previous validation runs.

        Note: This method is kept for backward compatibility but cleanup is now handled
        automatically by update_or_create_review_comments(). It will update existing
        comments, create new ones, and delete resolved ones smartly.

        Args:
            args: Command-line arguments (kept for compatibility)
        """
        # Cleanup is now handled automatically by update_or_create_review_comments()
        # No action needed here
        logging.debug("Comment cleanup will be handled automatically during review posting")

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

                # Load config to get fail_on_severity and ignore settings
                config_path = getattr(args, "config", None)
                config = ConfigLoader.load_config(config_path)
                fail_on_severities = config.get_setting("fail_on_severity", ["error", "critical"])

                # Get ignore settings from config, but CLI flag can override
                ignore_settings = config.get_setting("ignore_settings", {})
                enable_ignore = ignore_settings.get("enabled", True)
                # CLI --no-owner-ignore takes precedence
                if getattr(args, "no_owner_ignore", False):
                    enable_ignore = False
                allowed_users = ignore_settings.get("allowed_users", [])

                # In streaming mode, don't cleanup comments (we want to keep earlier files)
                # Cleanup will happen once at the end
                commenter = PRCommenter(
                    github,
                    cleanup_old_comments=False,
                    fail_on_severities=fail_on_severities,
                    enable_codeowners_ignore=enable_ignore,
                    allowed_ignore_users=allowed_users,
                )

                # Create a mini-report for just this file
                generator = ReportGenerator()
                mini_report = generator.generate_report([result])

                # Post line-specific comments (skip cleanup - runs at end of streaming)
                await commenter.post_findings_to_pr(
                    mini_report,
                    create_review=True,
                    add_summary_comment=False,  # Summary comes later
                )
        except Exception as e:
            logging.warning(f"Failed to post review for {result.policy_file}: {e}")

    def _make_relative_path(self, file_path: str) -> str | None:
        """Convert absolute path to relative path for GitHub.

        Args:
            file_path: Absolute or relative path to file

        Returns:
            Relative path from repository root, or None if cannot be determined
        """
        from pathlib import Path

        # If already relative, use as-is
        if not os.path.isabs(file_path):
            return file_path

        # Try to get workspace path from environment
        workspace = os.getenv("GITHUB_WORKSPACE")
        if workspace:
            try:
                abs_file_path = Path(file_path).resolve()
                workspace_path = Path(workspace).resolve()

                if abs_file_path.is_relative_to(workspace_path):
                    relative = abs_file_path.relative_to(workspace_path)
                    return str(relative).replace("\\", "/")
            except (ValueError, OSError) as exc:
                logging.debug(f"Could not make path relative to GitHub workspace: {exc}")

        # Fallback: try current working directory
        try:
            cwd = Path.cwd()
            abs_file_path = Path(file_path).resolve()
            if abs_file_path.is_relative_to(cwd):
                relative = abs_file_path.relative_to(cwd)
                return str(relative).replace("\\", "/")
        except (ValueError, OSError) as exc:
            logging.debug(f"Could not make path relative to cwd: {exc}")

        return None

    async def _run_final_review_cleanup(
        self,
        args: argparse.Namespace,
        all_results: list,
        all_validated_files: set[str],
    ) -> None:
        """Run final cleanup after all files are processed in streaming mode.

        This deletes stale comments for findings that are no longer present,
        using the complete set of validated files and current findings.

        Args:
            args: Command-line arguments
            all_results: All validation results from the streaming session
            all_validated_files: Set of all validated file paths (relative)
        """
        try:
            from iam_validator.core.config.config_loader import ConfigLoader
            from iam_validator.core.pr_commenter import PRCommenter

            async with GitHubIntegration() as github:
                if not github.is_configured():
                    return

                # Load config
                config_path = getattr(args, "config", None)
                config = ConfigLoader.load_config(config_path)
                fail_on_severities = config.get_setting("fail_on_severity", ["error", "critical"])

                # Get ignore settings
                ignore_settings = config.get_setting("ignore_settings", {})
                enable_ignore = ignore_settings.get("enabled", True)
                if getattr(args, "no_owner_ignore", False):
                    enable_ignore = False
                allowed_users = ignore_settings.get("allowed_users", [])

                # Create commenter WITH cleanup enabled for the final pass
                commenter = PRCommenter(
                    github,
                    cleanup_old_comments=True,  # Enable cleanup for final pass
                    fail_on_severities=fail_on_severities,
                    enable_codeowners_ignore=enable_ignore,
                    allowed_ignore_users=allowed_users,
                )

                # Create a full report with all results
                generator = ReportGenerator()
                full_report = generator.generate_report(all_results)

                # Post with create_review=True to run the full update/create/delete logic
                # but pass all_validated_files so cleanup knows the full scope
                logging.info("Running final comment cleanup...")
                await commenter.post_findings_to_pr(
                    full_report,
                    create_review=True,
                    add_summary_comment=False,
                    manage_labels=False,  # Labels are managed separately
                    process_ignores=False,  # Already processed per-file
                )

        except Exception as e:
            logging.warning(f"Failed to run final review cleanup: {e}")

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

    def _print_ci_console_output(
        self, report: ValidationReport, generator: ReportGenerator
    ) -> None:
        """Print enhanced console output for CI visibility.

        This shows validation results in the CI job logs in a human-readable format.
        JSON output is written to a separate file (specified by --ci-output).

        Args:
            report: Validation report to print
            generator: ReportGenerator instance
        """
        # Generate enhanced format output with summary and severity breakdown
        try:
            enhanced_output = generator.format_report(
                report,
                "enhanced",
                show_summary=True,
                show_severity_breakdown=True,
            )
            print(enhanced_output)

        except Exception as e:
            # Fallback to basic summary if enhanced format fails
            logging.warning(f"Failed to generate enhanced output: {e}")
            print("\nValidation Summary:")
            print(f"  Total policies: {report.total_policies}")
            print(f"  Valid: {report.valid_policies}")
            print(f"  Invalid: {report.invalid_policies}")
            print(f"  Total issues: {report.total_issues}\n")

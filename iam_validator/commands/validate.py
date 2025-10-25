"""Validate command for IAM Policy Validator."""

import argparse
import logging
import os

from iam_validator.commands.base import Command
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

  # Use custom checks from a directory
  iam-validator validate --path ./policies/ --custom-checks-dir ./my-checks

  # Generate JSON output
  iam-validator validate --path ./policies/ --format json --output report.json

  # Post to GitHub PR with line comments
  iam-validator validate --path ./policies/ --github-comment --github-review
        """

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add validate command arguments."""
        parser.add_argument(
            "--path",
            "-p",
            required=True,
            action="append",
            dest="paths",
            help="Path to IAM policy file or directory (can be specified multiple times)",
        )

        parser.add_argument(
            "--format",
            "-f",
            choices=["console", "json", "markdown", "html", "csv", "sarif"],
            default="console",
            help="Output format (default: console)",
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
            "--github-comment",
            action="store_true",
            help="Post validation results as GitHub PR comment",
        )

        parser.add_argument(
            "--github-review",
            action="store_true",
            help="Create line-specific review comments on PR (requires --github-comment)",
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
            "--no-registry",
            action="store_true",
            help="Use legacy validation (disable check registry system)",
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
        # Load policies from all specified paths
        loader = PolicyLoader()
        policies = loader.load_from_paths(args.paths, recursive=not args.no_recursive)

        if not policies:
            logging.error(f"No valid IAM policies found in: {', '.join(args.paths)}")
            return 1

        logging.info(f"Loaded {len(policies)} policies from {len(args.paths)} path(s)")

        # Validate policies
        use_registry = not getattr(args, "no_registry", False)
        config_path = getattr(args, "config", None)
        custom_checks_dir = getattr(args, "custom_checks_dir", None)
        results = await validate_policies(
            policies,
            config_path=config_path,
            use_registry=use_registry,
            custom_checks_dir=custom_checks_dir,
        )

        # Generate report
        generator = ReportGenerator()
        report = generator.generate_report(results)

        # Output results
        if args.format == "console":
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
            # Use formatter registry for other formats (html, csv, sarif)
            output_content = generator.format_report(report, args.format)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output_content)
                logging.info(f"Saved {args.format.upper()} report to {args.output}")
            else:
                print(output_content)

        # Post to GitHub if configured
        if args.github_comment:
            from iam_validator.core.pr_commenter import PRCommenter

            async with GitHubIntegration() as github:
                commenter = PRCommenter(github)
                success = await commenter.post_findings_to_pr(
                    report,
                    create_review=getattr(args, "github_review", True),
                    add_summary_comment=True,
                )
                if not success:
                    logging.error("Failed to post to GitHub PR")

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
        use_registry = not getattr(args, "no_registry", False)
        config_path = getattr(args, "config", None)
        custom_checks_dir = getattr(args, "custom_checks_dir", None)

        all_results = []
        total_processed = 0

        # Clean up old review comments at the start (before posting any new ones)
        if args.github_comment and getattr(args, "github_review", False):
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
                use_registry=use_registry,
                custom_checks_dir=custom_checks_dir,
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
                if args.github_comment and getattr(args, "github_review", False):
                    await self._post_file_review(result, args)

        if total_processed == 0:
            logging.error(f"No valid IAM policies found in: {', '.join(args.paths)}")
            return 1

        logging.info(f"\nCompleted validation of {total_processed} policies")

        # Generate final summary report
        report = generator.generate_report(all_results)

        # Output final results
        if args.format == "console":
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
            # Use formatter registry for other formats (html, csv, sarif)
            output_content = generator.format_report(report, args.format)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output_content)
                logging.info(f"Saved {args.format.upper()} report to {args.output}")
            else:
                print(output_content)

        # Post summary comment to GitHub
        if args.github_comment:
            from iam_validator.core.pr_commenter import PRCommenter

            async with GitHubIntegration() as github:
                commenter = PRCommenter(github)
                success = await commenter.post_findings_to_pr(
                    report,
                    create_review=False,  # Already posted per-file reviews
                    add_summary_comment=True,
                )
                if not success:
                    logging.error("Failed to post summary to GitHub PR")

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
            from iam_validator.core.pr_commenter import PRCommenter

            async with GitHubIntegration() as github:
                if not github.is_configured():
                    return

                # In streaming mode, don't cleanup comments (we want to keep earlier files)
                # Cleanup will happen once at the end
                commenter = PRCommenter(github, cleanup_old_comments=False)

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

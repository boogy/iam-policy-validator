"""Analyze command for IAM Policy Validator using AWS IAM Access Analyzer."""

import argparse
import logging

from iam_validator.commands.base import Command
from iam_validator.core.access_analyzer import (
    AccessAnalyzerReport,
    PolicyType,
    ResourceType,
    validate_policies_with_analyzer,
)
from iam_validator.core.access_analyzer_report import AccessAnalyzerReportFormatter
from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.report import ReportGenerator
from iam_validator.integrations.github_integration import GitHubIntegration


class AnalyzeCommand(Command):
    """Command to analyze IAM policies using AWS IAM Access Analyzer."""

    @property
    def name(self) -> str:
        return "analyze"

    @property
    def help(self) -> str:
        return "Analyze IAM policies using AWS IAM Access Analyzer"

    @property
    def epilog(self) -> str:
        return """
Examples:
  # Analyze identity-based policies
  iam-validator analyze --path ./policies/ --policy-type IDENTITY_POLICY

  # Analyze resource-based policies (e.g., S3 bucket policies)
  iam-validator analyze --path ./bucket-policies/ --policy-type RESOURCE_POLICY

  # Analyze multiple paths
  iam-validator analyze --path ./iam/ --path ./s3-policies/ --path bucket-policy.json

  # Use specific AWS region and profile
  iam-validator analyze --path ./policies/ --region us-west-2 --profile prod

  # Run full validation if Access Analyzer passes
  iam-validator analyze --path ./policies/ --run-all-checks

  # Custom Policy Checks:

  # Check that policies do NOT grant specific dangerous actions
  iam-validator analyze --path ./policies/ --check-access-not-granted s3:DeleteBucket s3:DeleteObject

  # Check that policies do NOT grant access to specific resources
  iam-validator analyze --path ./policies/ \\
    --check-access-not-granted s3:PutObject \\
    --check-access-resources "arn:aws:s3:::production-bucket/*"

  # Check that updated policies don't grant new access
  iam-validator analyze --path ./new-policy.json \\
    --check-no-new-access ./old-policy.json

  # Check that S3 bucket policies don't allow public access
  iam-validator analyze --path ./bucket-policy.json \\
    --policy-type RESOURCE_POLICY \\
    --check-no-public-access \\
    --public-access-resource-type "AWS::S3::Bucket"
        """

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add analyze command arguments."""
        parser.add_argument(
            "--path",
            "-p",
            required=True,
            action="append",
            dest="paths",
            help="Path to IAM policy file or directory (can be specified multiple times)",
        )

        parser.add_argument(
            "--policy-type",
            "-t",
            choices=["IDENTITY_POLICY", "RESOURCE_POLICY", "SERVICE_CONTROL_POLICY"],
            default="IDENTITY_POLICY",
            help="Type of IAM policy to validate (default: IDENTITY_POLICY)",
        )

        parser.add_argument(
            "--region",
            default="us-east-1",
            help="AWS region for Access Analyzer (default: us-east-1)",
        )

        parser.add_argument(
            "--profile",
            help="AWS profile to use for Access Analyzer",
        )

        parser.add_argument(
            "--format",
            "-f",
            choices=["console", "json", "markdown"],
            default="console",
            help="Output format (default: console)",
        )

        parser.add_argument(
            "--output",
            "-o",
            help="Output file path (only for json/markdown formats)",
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
            "--github-summary",
            action="store_true",
            help="Write validation summary to GitHub Actions job summary (works for all workflow runs)",
        )

        parser.add_argument(
            "--run-all-checks",
            action="store_true",
            help="Run full validation checks if Access Analyzer passes",
        )

        # Custom policy check arguments
        parser.add_argument(
            "--check-access-not-granted",
            nargs="+",
            metavar="ACTION",
            help="Check that policy does NOT grant specific actions (e.g., s3:DeleteBucket)",
        )

        parser.add_argument(
            "--check-access-resources",
            nargs="+",
            metavar="RESOURCE",
            help="Resources to check with --check-access-not-granted (e.g., arn:aws:s3:::bucket/*)",
        )

        parser.add_argument(
            "--check-no-new-access",
            metavar="EXISTING_POLICY",
            help="Path to existing policy to compare against for new access checks",
        )

        parser.add_argument(
            "--check-no-public-access",
            action="store_true",
            help="Check that resource policy does not allow public access (for RESOURCE_POLICY type only)",
        )

        parser.add_argument(
            "--public-access-resource-type",
            nargs="+",
            choices=[
                "all",  # Special value to check all types
                # Storage
                "AWS::S3::Bucket",
                "AWS::S3::AccessPoint",
                "AWS::S3::MultiRegionAccessPoint",
                "AWS::S3Express::DirectoryBucket",
                "AWS::S3Express::AccessPoint",
                "AWS::S3::Glacier",
                "AWS::S3Outposts::Bucket",
                "AWS::S3Outposts::AccessPoint",
                "AWS::S3Tables::TableBucket",
                "AWS::S3Tables::Table",
                "AWS::EFS::FileSystem",
                # Database
                "AWS::DynamoDB::Table",
                "AWS::DynamoDB::Stream",
                "AWS::OpenSearchService::Domain",
                # Messaging & Streaming
                "AWS::Kinesis::Stream",
                "AWS::Kinesis::StreamConsumer",
                "AWS::SNS::Topic",
                "AWS::SQS::Queue",
                # Security & Secrets
                "AWS::KMS::Key",
                "AWS::SecretsManager::Secret",
                "AWS::IAM::AssumeRolePolicyDocument",
                # Compute
                "AWS::Lambda::Function",
                # API & Integration
                "AWS::ApiGateway::RestApi",
                # DevOps & Management
                "AWS::CodeArtifact::Domain",
                "AWS::Backup::BackupVault",
                "AWS::CloudTrail::Dashboard",
                "AWS::CloudTrail::EventDataStore",
            ],
            default=["AWS::S3::Bucket"],
            help="Resource type(s) for public access check. Use 'all' to check all 29 types. Example: all OR AWS::S3::Bucket AWS::Lambda::Function",
        )

        parser.add_argument(
            "--verbose",
            "-v",
            action="store_true",
            help="Enable verbose logging",
        )

    async def execute(self, args: argparse.Namespace) -> int:
        """Execute the analyze command."""
        try:
            # Map string to PolicyType enum
            policy_type = PolicyType[args.policy_type]

            # Build custom checks configuration
            custom_checks = self._build_custom_checks(args)

            # Validate policies with Access Analyzer
            report = validate_policies_with_analyzer(
                path=args.paths,
                region=args.region,
                policy_type=policy_type,
                profile=args.profile if hasattr(args, "profile") else None,
                recursive=not args.no_recursive,
                custom_checks=custom_checks,
            )

            # Generate report
            formatter = AccessAnalyzerReportFormatter()

            # Output results
            if args.format == "console":
                formatter.print_console_report(report)
            elif args.format == "json":
                if args.output:
                    formatter.save_json_report(report, args.output)
                    logging.info(f"JSON report saved to {args.output}")
                else:
                    print(formatter.generate_json_report(report))
            elif args.format == "markdown":
                if args.output:
                    formatter.save_markdown_report(report, args.output)
                    logging.info(f"Markdown report saved to {args.output}")
                else:
                    print(formatter.generate_markdown_report(report))

            # Post to GitHub if configured
            if args.github_comment:
                async with GitHubIntegration() as github:
                    success = await self._post_to_github(github, report, formatter)
                    if not success:
                        logging.error("Failed to post Access Analyzer results to GitHub PR")

            # Write to GitHub Actions job summary if configured
            if getattr(args, "github_summary", False):
                self._write_github_actions_summary(report)

            # Determine exit code based on validation results
            if args.fail_on_warnings:
                exit_code = 0 if report.total_findings == 0 else 1
            else:
                exit_code = 0 if report.total_errors == 0 else 1

            # If Access Analyzer passes and --run-all-checks is set, run full validation
            if exit_code == 0 and getattr(args, "run_all_checks", False):
                exit_code = await self._run_full_validation(args)

            return exit_code

        except ValueError as e:
            logging.error(f"Validation error: {e}")
            return 1
        except Exception as e:
            logging.error(f"Access Analyzer validation failed: {e}", exc_info=args.verbose)
            return 1

    def _build_custom_checks(self, args: argparse.Namespace) -> dict | None:
        """Build custom checks configuration from CLI arguments.

        Args:
            args: Parsed command line arguments

        Returns:
            Dictionary with custom check configurations, or None if no checks specified
        """
        custom_checks = {}

        # Check access not granted
        if hasattr(args, "check_access_not_granted") and args.check_access_not_granted:
            custom_checks["access_not_granted"] = {
                "actions": args.check_access_not_granted,
            }
            if hasattr(args, "check_access_resources") and args.check_access_resources:
                custom_checks["access_not_granted"]["resources"] = args.check_access_resources

        # Check no new access
        if hasattr(args, "check_no_new_access") and args.check_no_new_access:
            # Load existing policy
            from iam_validator.core.policy_loader import PolicyLoader

            loader = PolicyLoader()
            existing_policies_loaded = loader.load_from_path(
                args.check_no_new_access, recursive=False
            )

            if existing_policies_loaded:
                # Build dict of existing policies
                existing_policies_dict = {
                    file_path: policy.model_dump(by_alias=True, exclude_none=True)
                    for file_path, policy in existing_policies_loaded
                }
                custom_checks["no_new_access"] = {"existing_policies": existing_policies_dict}
            else:
                logging.warning(f"Could not load existing policy from {args.check_no_new_access}")

        # Check no public access
        if hasattr(args, "check_no_public_access") and args.check_no_public_access:
            resource_types = getattr(args, "public_access_resource_type", ["AWS::S3::Bucket"])
            # Support both single string and list
            if isinstance(resource_types, str):
                resource_types = [resource_types]

            # Expand "all" to all resource types
            if "all" in resource_types:
                resource_types = [member.value for member in ResourceType]
                logging.info(
                    f"Checking all {len(resource_types)} supported resource types for public access"
                )

            # Convert to ResourceType enums
            resource_type_enums = [ResourceType(rt) for rt in resource_types]
            custom_checks["no_public_access"] = {"resource_types": resource_type_enums}

        return custom_checks if custom_checks else None

    async def _run_full_validation(self, args: argparse.Namespace) -> int:
        """Run full validation after Access Analyzer passes."""
        logging.info("Access Analyzer validation passed. Running full validation checks...")

        # Load policies again for full validation
        loader = PolicyLoader()
        policies = loader.load_from_paths(args.paths, recursive=not args.no_recursive)

        if not policies:
            logging.error(f"No valid IAM policies found in: {', '.join(args.paths)}")
            return 1

        # Run full validation
        results = await validate_policies(policies)

        # Generate report
        generator = ReportGenerator()
        validation_report = generator.generate_report(results)

        # Output results
        if args.format == "console":
            logging.info("\n=== Full Validation Results ===")
            generator.print_console_report(validation_report)
        elif args.format == "json":
            # Don't output JSON again if already saved
            if not args.output:
                print(generator.generate_json_report(validation_report))
        elif args.format == "markdown":
            # Don't output markdown again if already saved
            if not args.output:
                print(generator.generate_github_comment(validation_report))

        # Post to GitHub if configured
        if args.github_comment:
            from iam_validator.core.config.config_loader import ConfigLoader
            from iam_validator.core.pr_commenter import PRCommenter

            # Load config to get fail_on_severity, severity_labels, and ignore settings
            config_path = getattr(args, "config", None)
            config = ConfigLoader.load_config(config_path)
            fail_on_severities = config.get_setting("fail_on_severity", ["error", "critical"])
            severity_labels = config.get_setting("severity_labels", {})

            # Get ignore settings from config
            ignore_settings = config.get_setting("ignore_settings", {})
            enable_ignore = ignore_settings.get("enabled", True)
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
                    validation_report,
                    create_review=getattr(args, "github_review", False),
                    add_summary_comment=True,
                )
                if not success:
                    logging.error("Failed to post full validation to GitHub PR")

        # Update exit code based on full validation
        if args.fail_on_warnings:
            return 0 if validation_report.total_issues == 0 else 1
        else:
            return 0 if validation_report.invalid_policies == 0 else 1

    async def _post_to_github(
        self,
        github: GitHubIntegration,
        report: AccessAnalyzerReport,
        formatter: AccessAnalyzerReportFormatter,
    ) -> bool:
        """Post Access Analyzer results to GitHub PR."""
        if not github.is_configured():
            logging.error(
                "GitHub integration not configured. "
                "Required: GITHUB_TOKEN, GITHUB_REPOSITORY, and GITHUB_PR_NUMBER environment variables. "
                "Ensure your workflow is triggered by a pull_request event."
            )
            return False

        # Generate markdown comment (single part for now)
        markdown_content = formatter.generate_markdown_report(report)

        # Add identifier for updating existing comments
        identifier = "<!-- iam-access-analyzer-validator -->"

        # Check if content is too large for single comment
        if len(markdown_content) > 60000:
            # Split into multiple parts
            # For simplicity, we use a basic split for Access Analyzer reports
            # TODO: Implement proper multi-part splitting for Access Analyzer reports
            logging.warning("Access Analyzer report is large, posting as single comment")

        # Post or update comment
        logging.info("Posting Access Analyzer results to PR...")
        success = await github.update_or_create_comment(markdown_content, identifier)

        if success:
            logging.info("Successfully posted Access Analyzer results to PR")
        else:
            logging.error("Failed to post Access Analyzer results to PR")

        return success

    def _write_github_actions_summary(self, report: AccessAnalyzerReport) -> None:
        """Write a high-level summary to GitHub Actions job summary.

        This appears in the Actions tab and provides a quick overview of Access Analyzer results.
        Uses GITHUB_STEP_SUMMARY environment variable.

        Args:
            report: Access Analyzer report to summarize
        """
        import os

        summary_file = os.getenv("GITHUB_STEP_SUMMARY")
        if not summary_file:
            logging.warning(
                "--github-summary specified but GITHUB_STEP_SUMMARY env var not found. "
                "This feature only works in GitHub Actions."
            )
            return

        try:
            # Generate high-level summary
            summary_parts = []

            # Header with status
            if report.total_findings == 0:
                summary_parts.append("# ✅ IAM Policy Validation (Access Analyzer) - Passed")
            elif report.total_errors > 0:
                summary_parts.append("# ❌ IAM Policy Validation (Access Analyzer) - Failed")
            else:
                summary_parts.append("# ⚠️ IAM Policy Validation (Access Analyzer) - Issues Found")

            summary_parts.append("")

            # Summary table
            summary_parts.append("## Summary")
            summary_parts.append("")
            summary_parts.append("| Metric | Count |")
            summary_parts.append("|--------|-------|")
            summary_parts.append(f"| Total Policies Analyzed | {report.total_policies} |")
            summary_parts.append(f"| Policies with Findings | {report.policies_with_findings} |")
            summary_parts.append(f"| Total Findings | {report.total_findings} |")
            summary_parts.append(f"| Errors | {report.total_errors} |")
            summary_parts.append(f"| Warnings | {report.total_warnings} |")
            summary_parts.append(f"| Suggestions | {report.total_suggestions} |")

            # Finding breakdown by type if there are findings
            if report.total_findings > 0:
                summary_parts.append("")
                summary_parts.append("## 📊 Findings by Type")
                summary_parts.append("")

                # Count findings by type
                finding_types: dict[str, int] = {}
                for result in report.results:
                    for finding in result.findings:
                        finding_type = finding.finding_type
                        finding_types[finding_type] = finding_types.get(finding_type, 0) + 1

                # Sort by count (highest first)
                sorted_types = sorted(finding_types.items(), key=lambda x: x[1], reverse=True)

                summary_parts.append("| Finding Type | Count |")
                summary_parts.append("|--------------|-------|")
                for finding_type, count in sorted_types:
                    summary_parts.append(f"| {finding_type} | {count} |")

            # Add footer with links
            summary_parts.append("")
            summary_parts.append("---")
            summary_parts.append("")
            summary_parts.append(
                "📝 For detailed findings, check the PR comments or review the workflow logs."
            )
            summary_parts.append("")
            summary_parts.append("*Powered by AWS IAM Access Analyzer*")

            # Write to summary file (append mode)
            with open(summary_file, "a", encoding="utf-8") as f:
                f.write("\n".join(summary_parts))
                f.write("\n")

            logging.info("Wrote Access Analyzer summary to GitHub Actions job summary")

        except Exception as e:
            logging.warning(f"Failed to write GitHub Actions summary: {e}")

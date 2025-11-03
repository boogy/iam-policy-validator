"""Post-to-PR command for IAM Policy Validator."""

import argparse

from iam_validator.commands.base import Command
from iam_validator.core.pr_commenter import post_report_to_pr


class PostToPRCommand(Command):
    """Command to post a validation report to a GitHub PR."""

    @property
    def name(self) -> str:
        return "post-to-pr"

    @property
    def help(self) -> str:
        return "Post a JSON report to a GitHub PR"

    @property
    def epilog(self) -> str:
        return """
Examples:
  # Post report with line comments
  iam-validator post-to-pr --report report.json

  # Post only summary comment
  iam-validator post-to-pr --report report.json --no-review

  # Post only line comments (no summary)
  iam-validator post-to-pr --report report.json --no-summary
        """

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add post-to-pr command arguments."""
        parser.add_argument(
            "--report",
            "-r",
            required=True,
            help="Path to JSON report file",
        )

        parser.add_argument(
            "--create-review",
            action="store_true",
            default=True,
            help="Create line-specific review comments (default: True)",
        )

        parser.add_argument(
            "--no-review",
            action="store_false",
            dest="create_review",
            help="Don't create line-specific review comments",
        )

        parser.add_argument(
            "--add-summary",
            action="store_true",
            default=True,
            help="Add summary comment (default: True)",
        )

        parser.add_argument(
            "--no-summary",
            action="store_false",
            dest="add_summary",
            help="Don't add summary comment",
        )

        parser.add_argument(
            "--config",
            "-c",
            help="Path to configuration file (for fail_on_severity setting)",
        )

    async def execute(self, args: argparse.Namespace) -> int:
        """Execute the post-to-pr command."""
        success = await post_report_to_pr(
            args.report,
            create_review=args.create_review,
            add_summary=args.add_summary,
            config_path=getattr(args, "config", None),
        )

        return 0 if success else 1

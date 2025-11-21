"""Query AWS service definitions - actions, ARNs, and condition keys.

This command allows querying AWS IAM service metadata similar to policy_sentry.
Implementation inspired by: https://github.com/salesforce/policy_sentry

Examples:
    # Query all actions for a service
    iam-validator query action --service s3

    # Query write-level actions
    iam-validator query action --service s3 --access-level write

    # Query actions that support wildcard resource
    iam-validator query action --service s3 --resource-type "*"

    # Query action details
    iam-validator query action --service s3 --name GetObject

    # Query ARN formats for a service
    iam-validator query arn --service s3

    # Query specific ARN type
    iam-validator query arn --service s3 --name bucket

    # Query condition keys
    iam-validator query condition --service s3

    # Query specific condition key
    iam-validator query condition --service s3 --name s3:prefix

  # Text format for simple output (great for piping)
  iam-validator query action --service s3 --output text | grep Delete
  iam-validator query action --service iam --access-level write --output text
"""

import argparse
import json
import logging
import sys
from typing import Any

import yaml

from iam_validator.commands.base import Command
from iam_validator.core.aws_service.fetcher import AWSServiceFetcher

logger = logging.getLogger(__name__)


class QueryCommand(Command):
    """Query AWS service definitions."""

    @property
    def name(self) -> str:
        """Command name."""
        return "query"

    @property
    def help(self) -> str:
        """Command help text."""
        return "Query AWS service definitions (actions, ARNs, condition keys)"

    @property
    def epilog(self) -> str:
        """Command epilog with examples."""
        return """
examples:
  # Query all actions for a service
  iam-validator query action --service s3

  # Query write-level actions
  iam-validator query action --service s3 --access-level write

  # Query actions that support wildcard resource
  iam-validator query action --service s3 --resource-type "*"

  # Query action details
  iam-validator query action --service s3 --name GetObject

  # Query ARN formats for a service
  iam-validator query arn --service s3

  # Query specific ARN type
  iam-validator query arn --service s3 --name bucket

  # Query condition keys
  iam-validator query condition --service s3

  # Query specific condition key
  iam-validator query condition --service s3 --name s3:prefix

  # Text format for simple output (great for piping)
  iam-validator query action --service s3 --output text | grep Delete
  iam-validator query action --service iam --access-level write --output text

note:
  This feature is inspired by policy_sentry's query functionality.
  See: https://github.com/salesforce/policy_sentry
"""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add query command arguments."""
        # Add subparsers for different query types
        subparsers = parser.add_subparsers(
            dest="query_type",
            help="Type of query to perform",
            required=True,
        )

        # Action query
        action_parser = subparsers.add_parser(
            "action",
            help="Query IAM actions",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        action_parser.add_argument(
            "--service",
            required=True,
            help="AWS service prefix (e.g., s3, iam, ec2)",
        )
        action_parser.add_argument(
            "--name",
            help="Specific action name (e.g., GetObject, CreateUser)",
        )
        action_parser.add_argument(
            "--access-level",
            choices=["read", "write", "list", "tagging", "permissions-management"],
            help="Filter by access level",
        )
        action_parser.add_argument(
            "--resource-type",
            help='Filter by resource type (use "*" for wildcard-only actions)',
        )
        action_parser.add_argument(
            "--condition",
            help="Filter actions that support specific condition key",
        )
        action_parser.add_argument(
            "--output",
            choices=["json", "yaml", "text"],
            default="json",
            help="Output format (default: json)",
        )

        # ARN query
        arn_parser = subparsers.add_parser(
            "arn",
            help="Query ARN formats",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        arn_parser.add_argument(
            "--service",
            required=True,
            help="AWS service prefix (e.g., s3, iam, ec2)",
        )
        arn_parser.add_argument(
            "--name",
            help="Specific ARN resource type name (e.g., bucket, role)",
        )
        arn_parser.add_argument(
            "--list-arn-types",
            action="store_true",
            help="List all ARN types with their formats",
        )
        arn_parser.add_argument(
            "--output",
            choices=["json", "yaml", "text"],
            default="json",
            help="Output format (default: json)",
        )

        # Condition query
        condition_parser = subparsers.add_parser(
            "condition",
            help="Query condition keys",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        condition_parser.add_argument(
            "--service",
            required=True,
            help="AWS service prefix (e.g., s3, iam, ec2)",
        )
        condition_parser.add_argument(
            "--name",
            help="Specific condition key name (e.g., s3:prefix, iam:PolicyArn)",
        )
        condition_parser.add_argument(
            "--output",
            choices=["json", "yaml", "text"],
            default="json",
            help="Output format (default: json)",
        )

    async def execute(self, args: argparse.Namespace) -> int:
        """Execute query command."""
        try:
            async with AWSServiceFetcher(prefetch_common=False) as fetcher:
                if args.query_type == "action":
                    result = await self._query_action_table(fetcher, args)
                elif args.query_type == "arn":
                    result = await self._query_arn_table(fetcher, args)
                elif args.query_type == "condition":
                    result = await self._query_condition_table(fetcher, args)
                else:
                    logger.error(f"Unknown query type: {args.query_type}")
                    return 1

                # Output result
                self._print_result(result, args.output)
                return 0

        except ValueError as e:
            logger.error(f"Query failed: {e}")
            return 1
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"Unexpected error during query: {e}", exc_info=True)
            return 1

    def _get_access_level(self, action_detail: Any) -> str:
        """Derive access level from action annotations.

        AWS API provides Properties dict with boolean flags instead of AccessLevel string.
        We derive the access level from these flags.
        """
        if not action_detail.annotations:
            return "Unknown"

        props = action_detail.annotations.get("Properties", {})
        if not props:
            return "Unknown"

        # Check flags in priority order
        if props.get("IsPermissionManagement"):
            return "permissions-management"
        if props.get("IsTaggingOnly"):
            return "tagging"
        if props.get("IsWrite"):
            return "write"
        if props.get("IsList"):
            return "list"

        # Default to read if none of the above
        return "read"

    async def _query_action_table(
        self, fetcher: AWSServiceFetcher, args: argparse.Namespace
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Query action table."""
        service_detail = await fetcher.fetch_service_by_name(args.service)

        # If specific action requested, return its details
        if args.name:
            action_name = args.name
            # Try case-insensitive lookup
            action_detail = None
            for key, detail in service_detail.actions.items():
                if key.lower() == action_name.lower():
                    action_detail = detail
                    break

            if not action_detail:
                raise ValueError(f"Action '{args.name}' not found in service '{args.service}'")

            access_level = self._get_access_level(action_detail)
            description = (
                action_detail.annotations.get("Description", "N/A")
                if action_detail.annotations
                else "N/A"
            )

            return {
                "service": args.service,
                "action": action_detail.name,
                "description": description,
                "access_level": access_level,
                "resource_types": [r.get("Name", "*") for r in (action_detail.resources or [])],
                "condition_keys": action_detail.action_condition_keys or [],
            }

        # Filter actions based on criteria
        filtered_actions = []
        for action_name, action_detail in service_detail.actions.items():
            access_level = self._get_access_level(action_detail)

            # Apply filters
            if args.access_level:
                if access_level.lower() != args.access_level.lower():
                    continue

            if args.resource_type:
                resources = action_detail.resources or []

                # If filtering for wildcard-only actions (actions with no required resources)
                if args.resource_type == "*":
                    # Actions with empty resources list are wildcard-only
                    if resources:
                        continue
                else:
                    # Filter by specific resource type name
                    resource_names = [r.get("Name", "") for r in resources]
                    if args.resource_type not in resource_names:
                        continue

            if args.condition:
                condition_keys = action_detail.action_condition_keys or []
                if args.condition not in condition_keys:
                    continue

            description = (
                action_detail.annotations.get("Description", "N/A")
                if action_detail.annotations
                else "N/A"
            )

            # Add to filtered list
            filtered_actions.append(
                {
                    "action": f"{args.service}:{action_name}",
                    "access_level": access_level,
                    "description": description,
                }
            )

        return filtered_actions

    async def _query_arn_table(
        self, fetcher: AWSServiceFetcher, args: argparse.Namespace
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Query ARN table."""
        service_detail = await fetcher.fetch_service_by_name(args.service)

        # If specific ARN type requested
        if args.name:
            resource_type = None
            for key, rt in service_detail.resources.items():
                if key.lower() == args.name.lower():
                    resource_type = rt
                    break

            if not resource_type:
                raise ValueError(
                    f"ARN resource type '{args.name}' not found in service '{args.service}'"
                )

            return {
                "service": args.service,
                "resource_type": resource_type.name,
                "arn_formats": resource_type.arn_formats or [],
                "condition_keys": resource_type.condition_keys or [],
            }

        # List all ARN types
        if args.list_arn_types:
            return [
                {
                    "resource_type": rt.name,
                    "arn_formats": rt.arn_formats or [],
                }
                for rt in service_detail.resources.values()
            ]

        # Return all raw ARN formats
        all_arns = []
        for resource_type in service_detail.resources.values():
            if resource_type.arn_formats:
                all_arns.extend(resource_type.arn_formats)

        return list(set(all_arns))  # Remove duplicates

    async def _query_condition_table(
        self, fetcher: AWSServiceFetcher, args: argparse.Namespace
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Query condition table."""
        service_detail = await fetcher.fetch_service_by_name(args.service)

        # If specific condition key requested
        if args.name:
            condition_key = None
            for key, ck in service_detail.condition_keys.items():
                if key.lower() == args.name.lower():
                    condition_key = ck
                    break

            if not condition_key:
                raise ValueError(
                    f"Condition key '{args.name}' not found in service '{args.service}'"
                )

            return {
                "service": args.service,
                "condition_key": condition_key.name,
                "description": condition_key.description or "N/A",
                "types": condition_key.types or [],
            }

        # Return all condition keys
        return [
            {
                "condition_key": ck.name,
                "description": ck.description or "N/A",
                "types": ck.types or [],
            }
            for ck in service_detail.condition_keys.values()
        ]

    def _print_result(self, result: Any, fmt: str) -> None:
        """Print query result in specified format."""
        if fmt == "yaml":
            print(yaml.dump(result, default_flow_style=False, sort_keys=False))
        elif fmt == "text":
            self._print_text_format(result)
        else:  # json
            print(json.dumps(result, indent=2))

    def _print_text_format(self, result: Any) -> None:
        """Print result in simple text format.

        Text format outputs only the essential information:
        - For lists of actions: one action per line (service:action format)
        - For specific action: action name followed by key details
        - For ARNs: one ARN format per line
        - For condition keys: one condition key per line
        """
        if isinstance(result, list):
            # List of items (actions, ARNs, or condition keys)
            if not result:
                return

            first_item = result[0]
            if "action" in first_item:
                # Action list
                for item in result:
                    print(item["action"])
            elif "condition_key" in first_item:
                # Condition key list
                for item in result:
                    print(item["condition_key"])
            elif "resource_type" in first_item:
                # ARN type list
                for item in result:
                    print(f"{item['resource_type']}: {', '.join(item['arn_formats'])}")
            else:
                # Generic list (e.g., plain ARN formats)
                for item in result:
                    print(item)

        elif isinstance(result, dict):
            # Single item details
            if "action" in result:
                # Action details
                print(result["action"])
                if result.get("resource_types"):
                    print(f"  Resource types: {', '.join(result['resource_types'])}")
                if result.get("condition_keys"):
                    print(f"  Condition keys: {', '.join(result['condition_keys'])}")
                if result.get("access_level"):
                    print(f"  Access level: {result['access_level']}")

            elif "resource_type" in result:
                # ARN details
                print(result["resource_type"])
                if result.get("arn_formats"):
                    for arn in result["arn_formats"]:
                        print(f"  {arn}")
                if result.get("condition_keys"):
                    print(f"  Condition keys: {', '.join(result['condition_keys'])}")

            elif "condition_key" in result:
                # Condition key details
                print(result["condition_key"])
                if result.get("types"):
                    print(f"  Types: {', '.join(result['types'])}")
                if result.get("description") and result["description"] != "N/A":
                    print(f"  Description: {result['description']}")


# For testing
if __name__ == "__main__":
    import asyncio

    cmd = QueryCommand()
    arg_parser = argparse.ArgumentParser()
    cmd.add_arguments(arg_parser)
    parsed_args = arg_parser.parse_args()
    sys.exit(asyncio.run(cmd.execute(parsed_args)))

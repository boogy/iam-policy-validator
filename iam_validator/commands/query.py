"""Query AWS service definitions - actions, ARNs, condition keys, and global condition keys.

Implementation inspired by: https://github.com/salesforce/policy_sentry
Run ``iam-validator query examples`` for usage examples.
"""

import argparse
import asyncio
import json
import logging
import sys
from collections import defaultdict
from typing import Any

import yaml

from iam_validator.commands.base import Command
from iam_validator.commands.examples import ExampleSections, print_examples
from iam_validator.core.aws_service.fetcher import AWSServiceFetcher
from iam_validator.sdk.query_utils import query_global_condition_key, query_global_condition_keys

logger = logging.getLogger(__name__)

QUERY_EXAMPLES: dict[str, ExampleSections] = {
    "action": [
        ("All actions for a service", ["iam-validator query action --service s3"]),
        (
            "Filter by access level, resource type, or condition key",
            [
                "iam-validator query action --service s3 --access-level write",
                'iam-validator query action --service s3 --resource-type "*"',
                "iam-validator query action --service s3 --has-condition-key s3:ResourceAccount",
            ],
        ),
        (
            "Data-plane / control-plane actions (AWS IsDataPlane)",
            [
                "iam-validator query action --service s3 --data-plane --output text",
                "iam-validator query action --service s3 --control-plane --access-level write",
            ],
        ),
        (
            "Action details (two equivalent forms)",
            [
                "iam-validator query action --service s3 --name GetObject",
                "iam-validator query action --name s3:GetObject",
            ],
        ),
        (
            "Several actions and wildcards in one query",
            [
                "iam-validator query action --name dynamodb:Query dynamodb:Scan s3:GetObject",
                'iam-validator query action --name "iam:Get*" --output text',
                'iam-validator query action --name dynamodb:Query "dynamodb:Create*" --output yaml',
            ],
        ),
        (
            "Show only selected fields",
            [
                "iam-validator query action --name dynamodb:Query --show-condition-keys",
                'iam-validator query action --name "s3:Get*" --show-resource-types --output text',
                "iam-validator query action --name iam:CreateRole --show-access-level --show-data-plane",
                "iam-validator query action --service s3 --show-service-name --output text",
            ],
        ),
    ],
    "arn": [
        ("ARN formats for a service", ["iam-validator query arn --service s3"]),
        (
            "One resource type (two equivalent forms)",
            ["iam-validator query arn --service s3 --name bucket", "iam-validator query arn --name s3:bucket"],
        ),
        (
            "Filter and select fields",
            [
                "iam-validator query arn --service s3 --has-condition-key s3:ResourceAccount",
                "iam-validator query arn --service s3 --show-arn-format --show-condition-keys",
            ],
        ),
    ],
    "condition": [
        ("Condition keys for a service", ["iam-validator query condition --service s3"]),
        (
            "One condition key (two equivalent forms)",
            [
                "iam-validator query condition --service s3 --name prefix",
                "iam-validator query condition --name s3:prefix",
            ],
        ),
        ("Show only selected fields", ["iam-validator query condition --service s3 --show-types --output text"]),
    ],
    "global-condition": [
        ("All global condition keys", ["iam-validator query global-condition --output text"]),
        ("Filter by value type", ["iam-validator query global-condition --type IPAddress"]),
        (
            "One key (tag keys resolve to their ${TagKey} template)",
            [
                "iam-validator query global-condition --name aws:SourceIp",
                "iam-validator query global-condition --name aws:ResourceTag",
            ],
        ),
        ("Show only selected fields", ["iam-validator query global-condition --show-types --output text"]),
    ],
    "output": [
        (
            "Text output for piping",
            [
                "iam-validator query action --service s3 --output text | grep Delete",
                "iam-validator query action --service iam --access-level write --output text",
            ],
        ),
        (
            "JSON piped to jq",
            [
                "iam-validator query action --service s3 --data-plane | jq -r '.[].action'",
                "iam-validator query action --service s3 | jq 'group_by(.access_level) | map({(.[0].access_level): length}) | add'",
                "iam-validator query action --service s3 | jq -r '.[] | select(.condition_keys | index(\"s3:TlsVersion\")) | .action'",
                "iam-validator query global-condition --type Bool | jq -r '.[] | \"\\(.condition_key)\\t\\(.doc_url)\"'",
            ],
        ),
        (
            "YAML piped to yq",
            [
                "iam-validator query action --service iam --access-level permissions-management --output yaml | yq '.[].action'",
                "iam-validator query condition --service s3 --output yaml | yq '.[] | select(.types | contains([\"Numeric\"])) | .condition_key'",
            ],
        ),
    ],
}


class QueryCommand(Command):
    """Query AWS service definitions."""

    @property
    def name(self) -> str:
        """Command name."""
        return "query"

    @property
    def help(self) -> str:
        """Command help text."""
        return "Query AWS service definitions (actions, ARNs, condition keys, global condition keys)"

    @property
    def epilog(self) -> str:
        """Command epilog pointing at the examples."""
        return "Run 'iam-validator query --examples' or 'iam-validator query examples [TOPIC]' for usage examples."

    @property
    def examples(self) -> ExampleSections:
        return [section for sections in QUERY_EXAMPLES.values() for section in sections]

    def print_examples(self) -> None:
        self._print_examples(None)

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
            epilog="Run 'iam-validator query examples action' for usage examples.",
        )
        action_parser.add_argument(
            "--service",
            help="AWS service prefix (e.g., s3, iam, ec2). Optional if --name includes service prefix.",
        )
        action_parser.add_argument(
            "--name",
            nargs="*",
            help="Action name(s) - can specify multiple (e.g., GetObject PutObject or s3:GetObject dynamodb:Query). "
            "Supports wildcards (e.g., 's3:Get*'). If service prefix included, --service is optional.",
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
            "--has-condition-key",
            "--condition",
            dest="has_condition_key",
            help="Filter actions that support a specific condition key (e.g., s3:ResourceAccount)",
        )
        plane_group = action_parser.add_mutually_exclusive_group()
        plane_group.add_argument(
            "--data-plane",
            dest="data_plane",
            action="store_const",
            const=True,
            default=None,
            help="Only actions AWS classifies as data-plane (IsDataPlane)",
        )
        plane_group.add_argument(
            "--control-plane",
            dest="data_plane",
            action="store_const",
            const=False,
            help="Only actions AWS explicitly classifies as control-plane (unclassified actions excluded)",
        )
        action_parser.add_argument(
            "--output",
            choices=["json", "yaml", "text"],
            default="json",
            help="Output format (default: json)",
        )

        # Output field filters - when specified, only show these fields
        action_parser.add_argument(
            "--show-condition-keys",
            action="store_true",
            help="Show only condition keys for each action",
        )
        action_parser.add_argument(
            "--show-resource-types",
            action="store_true",
            help="Show only resource types for each action",
        )
        action_parser.add_argument(
            "--show-access-level",
            action="store_true",
            help="Show only access level for each action",
        )
        action_parser.add_argument(
            "--show-data-plane",
            action="store_true",
            help="Show only the data-plane classification for each action",
        )
        action_parser.add_argument(
            "--show-service-name",
            action="store_true",
            help="Show only the AWS service name (ServiceName) for each action",
        )

        # ARN query
        arn_parser = subparsers.add_parser(
            "arn",
            help="Query ARN formats",
            epilog="Run 'iam-validator query examples arn' for usage examples.",
        )
        arn_parser.add_argument(
            "--service",
            help="AWS service prefix (e.g., s3, iam, ec2). Optional if --name includes service prefix.",
        )
        arn_parser.add_argument(
            "--name",
            help="ARN resource type (e.g., bucket or s3:bucket). If service prefix included, --service is optional.",
        )
        arn_parser.add_argument(
            "--has-condition-key",
            help="Filter ARN types that support a specific condition key (e.g., s3:ResourceAccount)",
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

        # Output field filters for ARN queries
        arn_parser.add_argument(
            "--show-condition-keys",
            action="store_true",
            help="Show condition keys for each resource type",
        )
        arn_parser.add_argument(
            "--show-arn-format",
            action="store_true",
            help="Show ARN format patterns for each resource type",
        )
        arn_parser.add_argument(
            "--show-resource-type",
            action="store_true",
            help="Show resource type name",
        )

        # Condition query
        condition_parser = subparsers.add_parser(
            "condition",
            help="Query condition keys",
            epilog="Run 'iam-validator query examples condition' for usage examples.",
        )
        condition_parser.add_argument(
            "--service",
            help="AWS service prefix (e.g., s3, iam, ec2). Optional if --name includes service prefix.",
        )
        condition_parser.add_argument(
            "--name",
            help="Condition key (e.g., prefix or s3:prefix). If service prefix included, --service is optional.",
        )
        condition_parser.add_argument(
            "--output",
            choices=["json", "yaml", "text"],
            default="json",
            help="Output format (default: json)",
        )
        condition_parser.add_argument(
            "--show-types", action="store_true", help="Show only the value types for each key"
        )

        # Global condition key query
        global_condition_parser = subparsers.add_parser(
            "global-condition",
            help="Query global condition keys (aws:SourceIp, aws:PrincipalTag/${TagKey}, ...)",
            epilog="Run 'iam-validator query examples global-condition' for usage examples.",
        )
        global_condition_parser.add_argument(
            "--name",
            help="Global condition key (e.g., aws:SourceIp or aws:ResourceTag)",
        )
        global_condition_parser.add_argument(
            "--type",
            dest="key_type",
            help="Filter by condition key type (e.g., String, ArrayOfString, Bool, ARN, Date, Numeric, IPAddress)",
        )
        global_condition_parser.add_argument(
            "--output",
            choices=["json", "yaml", "text"],
            default="json",
            help="Output format (default: json)",
        )
        global_condition_parser.add_argument(
            "--show-types", action="store_true", help="Show only the value types for each key"
        )
        global_condition_parser.add_argument(
            "--show-description", action="store_true", help="Show only the description for each key"
        )
        global_condition_parser.add_argument(
            "--show-doc-url",
            action="store_true",
            help="Show only the AWS documentation link for each key",
        )

        examples_parser = subparsers.add_parser("examples", help="Show usage examples")
        examples_parser.add_argument(
            "topic",
            nargs="?",
            choices=list(QUERY_EXAMPLES),
            help="Only show examples for this topic",
        )

    @staticmethod
    def _print_examples(topic: str | None) -> None:
        """Print usage examples, optionally for one topic."""
        for name, sections in QUERY_EXAMPLES.items():
            if not topic or name == topic:
                print_examples(sections, heading=name)

    def _parse_service_and_name(self, args: argparse.Namespace, query_type: str) -> tuple[str, str | None]:
        """Parse service and name from arguments (single name - for ARN/condition queries).

        Extracts service from --name if it contains a colon (e.g., 's3:GetObject').
        If --name has a service prefix, it overrides --service.

        Args:
            args: Parsed arguments with optional service and name attributes.
            query_type: Type of query ('action', 'arn', 'condition') for error messages.

        Returns:
            Tuple of (service, name) where name may be None.

        Raises:
            ValueError: If neither --service nor service prefix in --name is provided.
        """
        service = getattr(args, "service", None)
        raw_name = getattr(args, "name", None)

        # Handle list from nargs='*' - take first element for non-action queries
        if isinstance(raw_name, list):
            name = raw_name[0] if raw_name else None
        else:
            name = raw_name

        # If name contains a colon, extract service from it
        if name and ":" in name:
            parts = name.split(":", 1)
            extracted_service = parts[0]
            extracted_name = parts[1] if len(parts) > 1 else None

            # Use extracted service if --service wasn't provided
            if not service:
                service = extracted_service
            # If both provided, prefer the one in --name for consistency
            elif service != extracted_service:
                logger.warning(
                    f"Service from --name '{extracted_service}' differs from --service '{service}'. "
                    f"Using '{extracted_service}' from --name."
                )
                service = extracted_service

            name = extracted_name

        # Validate that we have a service
        if not service:
            raise ValueError(
                f"--service is required when --name doesn't include service prefix. "
                f"Use '--service <service>' or '--name <service>:<{query_type}>'"
            )

        return service, name

    def _parse_action_names(self, args: argparse.Namespace) -> list[tuple[str, str | None, bool]]:
        """Parse multiple action names from arguments.

        Handles the --name argument which can contain multiple action names,
        each optionally with a service prefix. Detects wildcard patterns.

        Args:
            args: Parsed arguments with optional service and name attributes.

        Returns:
            List of (service, action_name, is_wildcard) tuples.
            action_name is None when listing all actions for a service.

        Raises:
            ValueError: If service cannot be determined for an action.
        """
        default_service = getattr(args, "service", None)
        raw_names = getattr(args, "name", None)

        # Normalize names to a list (handles both string and list inputs)
        if raw_names is None:
            names: list[str] = []
        elif isinstance(raw_names, str):
            # Single string (backwards compatibility with tests)
            names = [raw_names]
        else:
            # List from nargs='*'
            names = list(raw_names)

        # If no names provided, return service with None name (list all)
        if not names:
            if not default_service:
                raise ValueError(
                    "--service is required when --name is not provided. Use '--service <service>' to list all actions."
                )
            return [(default_service, None, False)]

        results: list[tuple[str, str | None, bool]] = []
        for name in names:
            service = default_service
            action_name: str | None = name

            # If name contains a colon, extract service from it
            if ":" in name:
                parts = name.split(":", 1)
                service = parts[0]
                action_name = parts[1] if parts[1] else None

            # Validate that we have a service
            if not service:
                raise ValueError(
                    f"--service is required for '{name}' (no service prefix). "
                    f"Use '--service <service>' or '<service>:{name}'"
                )

            # Detect if this is a wildcard pattern
            is_wildcard = action_name is not None and ("*" in action_name or "?" in action_name)

            results.append((service, action_name, is_wildcard))

        return results

    async def execute(self, args: argparse.Namespace) -> int:
        """Execute query command."""
        if args.query_type == "examples":
            self._print_examples(args.topic)
            return 0
        try:
            async with AWSServiceFetcher(prefetch_common=False) as fetcher:
                result: dict[str, Any] | list[dict[str, Any]] | list[str]
                if args.query_type == "action":
                    # Use new multi-action parsing for action queries
                    result = await self._query_action_table(fetcher, args)
                elif args.query_type == "arn":
                    # Parse service and name for ARN queries (single name)
                    service, name = self._parse_service_and_name(args, args.query_type)
                    args.service = service
                    args.name = name
                    result = await self._query_arn_table(fetcher, args)
                elif args.query_type == "condition":
                    # Parse service and name for condition queries (single name)
                    service, name = self._parse_service_and_name(args, args.query_type)
                    args.service = service
                    args.name = name
                    result = await self._query_condition_table(fetcher, args)
                elif args.query_type == "global-condition":
                    if args.name:
                        result = dict(await query_global_condition_key(fetcher, args.name))
                    else:
                        result = [dict(k) for k in await query_global_condition_keys(fetcher, args.key_type)]
                    result = self._select_key_fields(result, args)
                else:
                    logger.error(f"Unknown query type: {args.query_type}")
                    return 1

                # Output result
                self._print_result(result, args.output, show_fields=self._has_key_field_filters(args))
                return 0

        except ValueError as e:
            logger.error(f"Query failed: {e}")
            return 1
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"Unexpected error during query: {e}", exc_info=True)
            return 1

    @staticmethod
    def _matches_condition_key(condition_keys: list[str], filter_value: str) -> bool:
        """Check if any condition key matches the filter using prefix matching.

        Condition keys can contain template parameters (e.g., ``s3:BucketTag/${TagKey}``).
        A filter of ``s3:BucketTag`` should match ``s3:BucketTag/${TagKey}``.
        Exact matches are also supported.

        Args:
            condition_keys: List of condition keys from an action or resource type.
            filter_value: The condition key filter to match against.

        Returns:
            True if any condition key matches the filter.
        """
        filter_lower = filter_value.lower()
        for key in condition_keys:
            key_lower = key.lower()
            if key_lower == filter_lower or key_lower.startswith(filter_lower + "/"):
                return True
        return False

    @staticmethod
    def _matches_filters(action_detail: Any, args: argparse.Namespace) -> bool:
        """Apply the --access-level, --resource-type, --has-condition-key and plane filters."""
        access_level = getattr(args, "access_level", None)
        if access_level and action_detail.access_level != access_level:
            return False
        resource_type = getattr(args, "resource_type", None)
        if resource_type:
            resource_names = [r.get("Name", "") for r in action_detail.resources or []]
            if resource_names if resource_type == "*" else resource_type not in resource_names:
                return False
        condition_key_filter = getattr(args, "has_condition_key", None)
        if condition_key_filter and not QueryCommand._matches_condition_key(
            action_detail.action_condition_keys or [], condition_key_filter
        ):
            return False
        data_plane = getattr(args, "data_plane", None)
        return data_plane is None or action_detail.is_data_plane is data_plane

    @staticmethod
    def _has_key_field_filters(args: argparse.Namespace) -> bool:
        return any(getattr(args, f, False) for f in ("show_types", "show_description", "show_doc_url"))

    @classmethod
    def _select_key_fields(cls, result: Any, args: argparse.Namespace) -> Any:
        """Reduce condition key results to ``condition_key`` plus the requested --show-* fields."""
        if not cls._has_key_field_filters(args):
            return result
        keep = {"condition_key"}
        keep.update(
            field
            for flag, field in (
                ("show_types", "types"),
                ("show_description", "description"),
                ("show_doc_url", "doc_url"),
            )
            if getattr(args, flag, False)
        )
        if isinstance(result, dict):
            return {k: v for k, v in result.items() if k in keep}
        return [{k: v for k, v in item.items() if k in keep} for item in result]

    def _get_field_filters(self, args: argparse.Namespace) -> set[str] | None:
        """Extract field filters from arguments.

        Returns:
            Set of fields to include, or None if no filters specified (show all).
            Valid fields: 'condition_keys', 'resource_types', 'access_level', 'data_plane', 'service_name'
        """
        fields: set[str] = set()

        if getattr(args, "show_condition_keys", False):
            fields.add("condition_keys")
        if getattr(args, "show_resource_types", False):
            fields.add("resource_types")
        if getattr(args, "show_access_level", False):
            fields.add("access_level")
        if getattr(args, "show_data_plane", False):
            fields.add("data_plane")
        if getattr(args, "show_service_name", False):
            fields.add("service_name")

        return fields if fields else None

    def _get_arn_field_filters(self, args: argparse.Namespace) -> set[str] | None:
        """Extract ARN field filters from arguments.

        Returns:
            Set of fields to include, or None if no filters specified (show all).
            Valid fields: 'condition_keys', 'arn_formats', 'resource_type'
        """
        fields: set[str] = set()

        if getattr(args, "show_condition_keys", False):
            fields.add("condition_keys")
        if getattr(args, "show_arn_format", False):
            fields.add("arn_formats")
        if getattr(args, "show_resource_type", False):
            fields.add("resource_type")

        return fields if fields else None

    @staticmethod
    def _format_arn_detail(
        resource_type: Any,
        fields: set[str] | None = None,
    ) -> dict[str, Any]:
        """Format ARN resource type detail for output.

        Args:
            resource_type: Resource type from service definition.
            fields: Set of fields to include. If None, include all fields.

        Returns:
            Formatted resource type dictionary. ``resource_type`` (name) is always included.
        """
        if fields:
            result: dict[str, Any] = {"resource_type": resource_type.name}
            if "arn_formats" in fields:
                result["arn_formats"] = resource_type.arn_formats or []
            if "condition_keys" in fields:
                result["condition_keys"] = resource_type.condition_keys or []
            return result

        # Full output
        return {
            "resource_type": resource_type.name,
            "arn_formats": resource_type.arn_formats or [],
            "condition_keys": resource_type.condition_keys or [],
        }

    async def _query_action_table(
        self, fetcher: AWSServiceFetcher, args: argparse.Namespace
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Query action table with support for multiple actions and wildcards.

        Optimized for speed by:
        - Grouping actions by service to minimize API calls
        - Fetching service definitions in parallel
        - Expanding wildcards in parallel
        - Pre-building lowercase lookup dicts for O(1) case-insensitive matching
        """
        # Parse all action names
        parsed_actions = self._parse_action_names(args)

        # Get field filters if any
        fields = self._get_field_filters(args)

        # Check if this is a "list all" query (single service, no name)
        if len(parsed_actions) == 1 and parsed_actions[0][1] is None:
            service = parsed_actions[0][0]
            return await self._query_all_actions_for_service(fetcher, service, args)

        # Group actions by service for efficient batching
        service_actions: dict[str, list[tuple[str | None, bool]]] = defaultdict(list)
        for service, action_name, is_wildcard in parsed_actions:
            service_actions[service].append((action_name, is_wildcard))

        # Fetch all service definitions in parallel
        services = list(service_actions.keys())
        service_details = await asyncio.gather(
            *[fetcher.fetch_service_by_name(s) for s in services],
            return_exceptions=True,
        )

        # Build service -> detail mapping with lowercase lookup dicts for O(1) matching
        service_detail_map: dict[str, Any] = {}
        service_lowercase_map: dict[str, dict[str, str]] = {}  # lowercase -> original key
        for service, detail in zip(services, service_details):
            if isinstance(detail, BaseException):
                raise ValueError(f"Failed to fetch service '{service}': {detail}")
            # detail is now narrowed to ServiceDetail
            service_detail_map[service] = detail
            # Pre-build lowercase lookup for O(1) case-insensitive matching
            service_lowercase_map[service] = {k.lower(): k for k in detail.actions.keys()}

        # Determine if this is a single exact action query (for backwards compatibility)
        is_single_exact_query = (
            len(parsed_actions) == 1 and not parsed_actions[0][2]  # Not a wildcard
        )

        # Collect all wildcard patterns for parallel expansion
        wildcard_patterns: list[tuple[str, str, str]] = []  # (service, action_name, pattern)
        exact_actions: list[tuple[str, str]] = []  # (service, action_name)

        for service, actions_list in service_actions.items():
            for action_name, is_wildcard in actions_list:
                if action_name is None:
                    continue
                if is_wildcard:
                    wildcard_patterns.append((service, action_name, f"{service}:{action_name}"))
                else:
                    exact_actions.append((service, action_name))

        # Expand all wildcards in parallel
        wildcard_results: dict[str, list[str]] = {}
        errors: list[str] = []

        if wildcard_patterns:
            expansions = await asyncio.gather(
                *[fetcher.expand_wildcard_action(p[2]) for p in wildcard_patterns],
                return_exceptions=True,
            )
            for (_svc, _action, pattern), expansion in zip(wildcard_patterns, expansions):
                if isinstance(expansion, BaseException):
                    errors.append(f"Failed to expand '{pattern}': {expansion}")
                    continue
                # expansion is now narrowed to list[str]
                wildcard_results[pattern] = sorted(expansion)

        # Process results with deduplication
        results: list[dict[str, Any]] = []
        seen_actions: set[str] = set()  # Track seen action names to prevent duplicates

        # Process wildcard expansions
        for service, action_name, pattern in wildcard_patterns:
            if pattern not in wildcard_results:
                continue  # Error was logged above
            service_detail = service_detail_map[service]
            for full_action in wildcard_results[pattern]:
                # Skip duplicates (e.g., s3:Get* s3:Get* or overlapping patterns)
                if full_action in seen_actions:
                    continue
                seen_actions.add(full_action)

                action_part = full_action.split(":")[1] if ":" in full_action else full_action
                action_detail = service_detail.actions.get(action_part)
                if action_detail:
                    if not self._matches_filters(action_detail, args):
                        continue
                    results.append(
                        self._format_action_detail(
                            service,
                            action_detail,
                            simple=args.output == "text" and not fields,
                            include_service_prefix=True,  # Always include for wildcards
                            fields=fields,
                            service_name=service_detail.service_name,
                        )
                    )
                else:
                    results.append(
                        {
                            "action": full_action,
                            "access_level": "Unknown",
                            "description": "N/A",
                        }
                    )

        # Process exact actions with O(1) case-insensitive lookup
        for service, action_name in exact_actions:
            service_detail = service_detail_map[service]
            lowercase_map = service_lowercase_map[service]

            # O(1) case-insensitive lookup
            original_key = lowercase_map.get(action_name.lower())
            if original_key:
                # Build full action name for deduplication check
                full_action = f"{service}:{original_key}"
                # Skip if already seen (e.g., s3:GetObject with s3:Get* in same query)
                if full_action in seen_actions:
                    continue
                seen_actions.add(full_action)

                action_detail = service_detail.actions[original_key]
                if not self._matches_filters(action_detail, args):
                    continue
                results.append(
                    self._format_action_detail(
                        service,
                        action_detail,
                        simple=args.output == "text" and not is_single_exact_query and not fields,
                        # Backwards compat: single exact query returns action without service prefix
                        include_service_prefix=not is_single_exact_query,
                        fields=fields,
                        service_name=service_detail.service_name,
                    )
                )
            else:
                errors.append(f"Action '{action_name}' not found in service '{service}'")

        # If there were errors and no results, raise
        if errors and not results:
            raise ValueError("\n".join(errors))

        # If there were some errors but also results, log warnings
        if errors:
            for error in errors:
                logger.warning(error)

        # Return single dict if only one result, otherwise list
        if len(results) == 1:
            return results[0]
        return results

    def _format_action_detail(
        self,
        service: str,
        action_detail: Any,
        simple: bool = False,
        include_service_prefix: bool = True,
        fields: set[str] | None = None,
        service_name: str | None = None,
    ) -> dict[str, Any]:
        """Format action detail for output.

        Args:
            service: Service prefix
            action_detail: Action detail from service definition
            simple: If True, return minimal format (for text output lists)
            include_service_prefix: If True, include service prefix in action name
            fields: Set of fields to include. If None, include all fields.
                    Valid values: 'condition_keys', 'resource_types', 'access_level', 'data_plane',
                    'service_name'
            service_name: Service display name (`ServiceName`)

        Returns:
            Formatted action dictionary
        """
        access_level = action_detail.access_level
        action_name = f"{service}:{action_detail.name}" if include_service_prefix else action_detail.name

        # Simple mode: just action name (for text output of action lists)
        if simple and not fields:
            return {"action": f"{service}:{action_detail.name}"}  # Always full name for text output

        # Field filtering mode: action + only requested fields
        if fields:
            result: dict[str, Any] = {"action": f"{service}:{action_detail.name}"}
            if "condition_keys" in fields:
                result["condition_keys"] = action_detail.action_condition_keys or []
            if "resource_types" in fields:
                result["resource_types"] = [r.get("Name", "*") for r in (action_detail.resources or [])]
            if "access_level" in fields:
                result["access_level"] = access_level
            if "data_plane" in fields:
                result["data_plane"] = action_detail.is_data_plane
            if "service_name" in fields:
                result["service_name"] = service_name
            return result

        # Full output mode
        description = action_detail.annotations.get("Description", "N/A") if action_detail.annotations else "N/A"

        return {
            "service": service,
            "service_name": service_name,
            "action": action_name,
            "description": description,
            "access_level": access_level,
            "data_plane": action_detail.is_data_plane,
            "resource_types": [r.get("Name", "*") for r in (action_detail.resources or [])],
            "condition_keys": action_detail.action_condition_keys or [],
        }

    async def _query_all_actions_for_service(
        self, fetcher: AWSServiceFetcher, service: str, args: argparse.Namespace
    ) -> list[dict[str, Any]]:
        """Query all actions for a service with optional filters."""
        service_detail = await fetcher.fetch_service_by_name(service)

        # Get field filters if any
        fields = self._get_field_filters(args)

        filtered_actions = []
        for action_detail in service_detail.actions.values():
            if not self._matches_filters(action_detail, args):
                continue

            # Add to filtered list using _format_action_detail for consistency
            filtered_actions.append(
                self._format_action_detail(
                    service,
                    action_detail,
                    simple=args.output == "text" and not fields,
                    include_service_prefix=True,
                    fields=fields,
                    service_name=service_detail.service_name,
                )
            )

        return filtered_actions

    async def _query_arn_table(
        self, fetcher: AWSServiceFetcher, args: argparse.Namespace
    ) -> dict[str, Any] | list[dict[str, Any]] | list[str]:
        """Query ARN table."""
        service_detail = await fetcher.fetch_service_by_name(args.service)
        condition_key_filter = getattr(args, "has_condition_key", None)
        arn_fields = self._get_arn_field_filters(args)

        # If specific ARN type requested
        if args.name:
            resource_type = None
            for key, rt in service_detail.resources.items():
                if key.lower() == args.name.lower():
                    resource_type = rt
                    break

            if not resource_type:
                raise ValueError(f"ARN resource type '{args.name}' not found in service '{args.service}'")

            # Apply condition key filter to specific ARN type
            if condition_key_filter:
                if not self._matches_condition_key(resource_type.condition_keys or [], condition_key_filter):
                    return []

            if arn_fields:
                return self._format_arn_detail(resource_type, arn_fields)

            return {
                "service": args.service,
                "service_name": service_detail.service_name,
                "resource_type": resource_type.name,
                "arn_formats": resource_type.arn_formats or [],
                "condition_keys": resource_type.condition_keys or [],
            }

        # Collect matching resource types (filter by condition key if set)
        matching_types = []
        for rt in service_detail.resources.values():
            if condition_key_filter:
                if not self._matches_condition_key(rt.condition_keys or [], condition_key_filter):
                    continue
            matching_types.append(rt)

        # When field filters or --list-arn-types: return structured per-type results
        if arn_fields or args.list_arn_types:
            return [self._format_arn_detail(rt, arn_fields) for rt in matching_types]

        # Default: return flat list of ARN format strings
        all_arns = []
        for rt in matching_types:
            if rt.arn_formats:
                all_arns.extend(rt.arn_formats)
        return list(set(all_arns))  # Remove duplicates

    async def _query_condition_table(
        self, fetcher: AWSServiceFetcher, args: argparse.Namespace
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Query condition table."""
        service_detail = await fetcher.fetch_service_by_name(args.service)

        # If specific condition key requested
        if args.name:
            condition_key = None
            search_name = args.name

            # First try exact match
            for key, ck in service_detail.condition_keys.items():
                if key.lower() == search_name.lower():
                    condition_key = ck
                    break

            # If not found, try with service prefix (condition keys often include it)
            # e.g., searching for "prefix" in s3 should find "s3:prefix"
            if not condition_key and ":" not in search_name:
                full_name = f"{args.service}:{search_name}"
                for key, ck in service_detail.condition_keys.items():
                    if key.lower() == full_name.lower():
                        condition_key = ck
                        break

            if not condition_key:
                raise ValueError(f"Condition key '{args.name}' not found in service '{args.service}'")

            return self._select_key_fields(
                {
                    "service": args.service,
                    "service_name": service_detail.service_name,
                    "condition_key": condition_key.name,
                    "description": condition_key.description or "N/A",
                    "types": condition_key.types or [],
                },
                args,
            )

        return self._select_key_fields(
            [
                {
                    "condition_key": ck.name,
                    "description": ck.description or "N/A",
                    "types": ck.types or [],
                }
                for ck in service_detail.condition_keys.values()
            ],
            args,
        )

    def _print_result(self, result: Any, fmt: str, show_fields: bool = False) -> None:
        """Print query result in specified format.

        ``show_fields`` prints each condition key with its selected fields in text output.
        """
        if fmt == "yaml":
            print(yaml.dump(result, default_flow_style=False, sort_keys=False))
        elif fmt == "text":
            self._print_text_format(result, show_fields)
        else:  # json
            print(json.dumps(result, indent=2))

    def _print_text_format(self, result: Any, show_fields: bool = False) -> None:
        """Print result in simple text format.

        Text format outputs only the essential information:
        - For lists of actions: one action per line (service:action format)
        - For specific action: action name followed by key details
        - For filtered output: action name with only the requested fields
        - For ARNs: one ARN format per line
        - For condition keys: one condition key per line
        """
        if isinstance(result, list):
            # List of items (actions, ARNs, or condition keys)
            if not result:
                return

            first_item = result[0]
            if "action" in first_item:
                # Action list - check if we have filtered fields to show
                has_filtered_fields = any(
                    k in first_item
                    for k in (
                        "condition_keys",
                        "resource_types",
                        "access_level",
                        "data_plane",
                        "service_name",
                    )
                )
                for item in result:
                    if has_filtered_fields:
                        # Print action with filtered fields
                        self._print_action_with_fields(item)
                    else:
                        # Simple list: just action name
                        print(item["action"])
            elif "condition_key" in first_item:
                for item in result:
                    if show_fields:
                        self._print_condition_key(item)
                    else:
                        print(item["condition_key"])
            elif "resource_type" in first_item:
                # ARN type list - check if we have filtered fields to show
                has_filtered_fields = any(
                    k in first_item for k in ("condition_keys", "arn_formats") if k != "resource_type"
                )
                for item in result:
                    if has_filtered_fields:
                        self._print_arn_with_fields(item)
                    else:
                        # Only resource_type name
                        print(item["resource_type"])
            else:
                # Generic list (e.g., plain ARN formats)
                for item in result:
                    print(item)

        elif isinstance(result, dict):
            # Single item details
            if "action" in result:
                self._print_action_with_fields(result)

            elif "resource_type" in result:
                self._print_arn_with_fields(result)

            elif "condition_key" in result:
                self._print_condition_key(result)

    @staticmethod
    def _print_condition_key(item: dict[str, Any]) -> None:
        """Print a condition key with any available fields."""
        print(item["condition_key"])
        if item.get("types"):
            print(f"  Types: {', '.join(item['types'])}")
        if item.get("description") and item["description"] != "N/A":
            print(f"  Description: {item['description']}")
        if item.get("doc_url"):
            print(f"  Documentation: {item['doc_url']}")

    def _print_action_with_fields(self, item: dict[str, Any]) -> None:
        """Print action with any available fields.

        Args:
            item: Action dict with 'action' key and optionally filtered fields.
        """
        print(item["action"])
        if item.get("service_name"):
            print(f"  Service name: {item['service_name']}")
        if item.get("resource_types"):
            print(f"  Resource types: {', '.join(item['resource_types'])}")
        if item.get("condition_keys"):
            print(f"  Condition keys: {', '.join(item['condition_keys'])}")
        if item.get("access_level"):
            print(f"  Access level: {item['access_level']}")
        if "data_plane" in item:
            plane = {True: "data", False: "control", None: "unclassified"}[item["data_plane"]]
            print(f"  Plane: {plane}")

    def _print_arn_with_fields(self, item: dict[str, Any]) -> None:
        """Print ARN resource type with any available fields.

        Args:
            item: ARN dict with 'resource_type' key and optionally filtered fields.
        """
        print(item["resource_type"])
        if item.get("arn_formats"):
            for arn in item["arn_formats"]:
                print(f"  {arn}")
        if item.get("condition_keys"):
            print(f"  Condition keys: {', '.join(item['condition_keys'])}")


# For testing
if __name__ == "__main__":
    cmd = QueryCommand()
    arg_parser = argparse.ArgumentParser()
    cmd.add_arguments(arg_parser)
    parsed_args = arg_parser.parse_args()
    sys.exit(asyncio.run(cmd.execute(parsed_args)))

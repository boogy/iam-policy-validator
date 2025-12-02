"""
Resource-Action Matching check.

This check validates that resources in a policy statement match the required
resource types for the actions. This catches common mistakes like:

- s3:GetObject with bucket ARN (needs object ARN: arn:aws:s3:::bucket/*)
- s3:ListBucket with object ARN (needs bucket ARN: arn:aws:s3:::bucket)
- iam:ListUsers with user ARN (needs wildcard: *)

This is inspired by Parliament's RESOURCE_MISMATCH check.

Example:
    Policy with mismatch:
    {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::mybucket"  # Missing /* for object path!
    }

    This check will report: s3:GetObject requires arn:aws:s3:::mybucket/*
"""

import re
from typing import ClassVar

from iam_validator.checks.utils.action_parser import get_action_case_insensitive, parse_action
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue
from iam_validator.sdk.arn_matching import (
    arn_strictly_valid,
    convert_aws_pattern_to_wildcard,
    has_template_variables,
    normalize_template_variables,
)


class ActionResourceMatchingCheck(PolicyCheck):
    """
    Validates that resources match the required types for actions.

    This check helps identify policies that are syntactically valid but won't
    work as intended because the resource ARNs don't match what the action requires.
    """

    check_id: ClassVar[str] = "action_resource_matching"
    description: ClassVar[str] = "Validates that resources match required types for actions"
    default_severity: ClassVar[str] = "medium"  # Security issue, not IAM validity error

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """
        Execute resource-action matching validation on a statement.

        Args:
            statement: The IAM policy statement to check
            statement_idx: Index of the statement in the policy
            fetcher: AWS service fetcher for action definitions
            config: Configuration for this check

        Returns:
            List of ValidationIssue objects for resource mismatches
        """
        issues = []

        # Check if template variable support is enabled (default: true)
        # Try global settings first, then check-specific config
        allow_template_variables = config.root_config.get("settings", {}).get(
            "allow_template_variables",
            config.config.get("allow_template_variables", True),
        )

        # Get actions and resources
        actions = statement.get_actions()
        resources = statement.get_resources()
        statement_sid = statement.sid
        line_number = statement.line_number

        # Skip if no resources to validate (e.g., trust policies don't have Resource field)
        if not resources:
            return issues

        # Skip if we have a wildcard resource (handled by other checks)
        if "*" in resources:
            return issues

        # Check each action
        for action in actions:
            # Parse and validate action
            parsed = parse_action(action)
            if not parsed:
                continue  # Invalid action format (or "*"), handled by action_validation

            # Skip wildcard actions
            if parsed.has_wildcard:
                continue

            service = parsed.service
            action_name = parsed.action_name

            # Get service definition
            service_detail = await fetcher.fetch_service_by_name(service)
            if not service_detail:
                continue  # Unknown service, handled by action_validation

            # Get action definition (case-insensitive since AWS actions are case-insensitive)
            action_detail = get_action_case_insensitive(service_detail.actions, action_name)
            if not action_detail:
                continue  # Unknown action, handled by action_validation

            # Get required resource types for this action
            required_resources = action_detail.resources or []

            # If action requires no specific resources, it needs Resource: "*"
            if not required_resources:
                # Check if all resources are "*"
                if not all(r == "*" for r in resources):
                    issues.append(
                        self._create_mismatch_issue(
                            action=action,
                            required_format="*",
                            required_type="*",
                            provided_resources=resources,
                            statement_idx=statement_idx,
                            statement_sid=statement_sid,
                            line_number=line_number,
                            config=config,
                            reason=f'Action `{action}` can only use `Resource: "*"`',
                        )
                    )
                continue

            # Check if ANY policy resource matches ANY required resource type
            match_found = False

            for req_resource in required_resources:
                # Get the resource type name from the action's required resources
                resource_name = req_resource.get("Name", "")
                if not resource_name:
                    continue

                # Look up the full resource type definition in the service's resources
                # The action's Resources field only has names like {"Name": "object"}
                # The service's Resources field has full definitions with ARN formats
                resource_type = service_detail.resources.get(resource_name)
                if not resource_type:
                    continue

                # Get the ARN pattern (first format from ARNFormats array)
                arn_pattern = resource_type.arn_pattern
                if not arn_pattern:
                    continue

                # Convert AWS pattern format (${Partition}, ${BucketName}) to wildcards (*)
                # AWS provides patterns like: arn:${Partition}:s3:::${BucketName}/${ObjectName}
                # We need wildcards like: arn:*:s3:::*/*
                wildcard_pattern = convert_aws_pattern_to_wildcard(arn_pattern)

                # Check if any policy resource matches this ARN pattern
                for resource in resources:
                    # Normalize template variables (Terraform/CloudFormation) before matching
                    # This allows policies with ${aws_account_id}, ${AWS::AccountId}, etc.
                    validation_resource = resource
                    if allow_template_variables and has_template_variables(resource):
                        validation_resource = normalize_template_variables(resource)

                    if arn_strictly_valid(wildcard_pattern, validation_resource, resource_name):
                        match_found = True
                        break

                if match_found:
                    break

            # If no match found, create an issue
            if not match_found and required_resources:
                # Build helpful error message with required formats
                # Look up each resource type in the service to get ARN patterns
                required_formats = []
                for req_res in required_resources:
                    res_name = req_res.get("Name", "")
                    if not res_name:
                        continue
                    res_type = service_detail.resources.get(res_name)
                    if res_type and res_type.arn_pattern:
                        required_formats.append(
                            {
                                "type": res_name,
                                "format": res_type.arn_pattern,
                            }
                        )

                issues.append(
                    self._create_mismatch_issue(
                        action=action,
                        required_format=(required_formats[0]["format"] if required_formats else ""),
                        required_type=(required_formats[0]["type"] if required_formats else ""),
                        provided_resources=resources,
                        statement_idx=statement_idx,
                        statement_sid=statement_sid,
                        line_number=line_number,
                        config=config,
                        all_required_formats=required_formats,
                    )
                )

        return issues

    def _create_mismatch_issue(
        self,
        action: str,
        required_format: str,
        required_type: str,
        provided_resources: list[str],
        statement_idx: int,
        statement_sid: str | None,
        line_number: int | None,
        config: CheckConfig,
        all_required_formats: list[dict] | None = None,
        reason: str | None = None,
    ) -> ValidationIssue:
        """Create a validation issue for resource mismatch."""
        # Build helpful message
        if reason:
            message = reason
        elif all_required_formats and len(all_required_formats) > 1:
            types = ", ".join(f"`{f['type']}`" for f in all_required_formats)
            message = (
                f"No resources match for action `{action}`. This action requires one of: {types}"
            )
        else:
            message = (
                f"No resources match for action `{action}`. "
                f"This action requires resource type: `{required_type}`"
            )

        # Build suggestion with examples
        suggestion = self._get_suggestion(
            action=action,
            required_format=required_format,
            provided_resources=provided_resources,
            all_required_formats=all_required_formats,
        )

        return ValidationIssue(
            severity=self.get_severity(config),
            statement_sid=statement_sid,
            statement_index=statement_idx,
            issue_type="resource_mismatch",
            message=message,
            action=action,
            resource=(
                ", ".join(provided_resources)
                if len(provided_resources) <= 3
                else f"{provided_resources[0]}..."
            ),
            suggestion=suggestion,
            line_number=line_number,
            field_name="resource",
        )

    def _get_suggestion(
        self,
        action: str,
        required_format: str,
        provided_resources: list[str],
        all_required_formats: list[dict] | None = None,
    ) -> str:
        """
        Generate helpful suggestion for fixing the mismatch.

        This function is service-agnostic and extracts resource type information
        from the ARN pattern to provide contextual examples.
        """
        if not required_format:
            return "Check AWS documentation for required resource types for this action"

        # Extract action name for contextual hints (e.g., "GetObject" from "s3:GetObject")
        action_name = action.split(":")[1] if ":" in action else action

        # Special case: Wildcard resource
        if required_format == "*":
            return (
                f'Action `{action}` can only use `Resource: "*"` (wildcard).\n'
                f"  This action does not support resource-level permissions.\n"
                f'  Example: `"Resource": "*"`'
            )

        # Build service-specific suggestion with proper markdown formatting
        suggestion_parts = []

        # If multiple resource types are valid, show all of them
        if all_required_formats and len(all_required_formats) > 1:
            resource_types = [fmt["type"] for fmt in all_required_formats]
            suggestion_parts.append(
                f"Action `{action}` requires one of these resource types: {', '.join(f'`{t}`' for t in resource_types)}"
            )
            suggestion_parts.append("")

            # Show format and example for each resource type
            for fmt in all_required_formats:
                resource_type = fmt["type"]
                arn_format = fmt["format"]

                suggestion_parts.append(
                    f"**Option {all_required_formats.index(fmt) + 1}: `{resource_type}` resource**"
                )
                suggestion_parts.append("```")
                suggestion_parts.append(arn_format)
                suggestion_parts.append("```")

                # Add practical example
                example = self._generate_example_arn(arn_format)
                if example:
                    suggestion_parts.append(f"Example: `{example}`")

                suggestion_parts.append("")
        else:
            # Single resource type - show detailed info
            # Extract resource type from ARN pattern
            # Pattern format: arn:${Partition}:service:${Region}:${Account}:resourceType/...
            # Examples:
            #   arn:${Partition}:s3:::${BucketName}/${ObjectName} -> object
            #   arn:${Partition}:iam::${Account}:user/${UserName} -> user
            resource_type = self._extract_resource_type_from_pattern(required_format)

            # Add action description
            suggestion_parts.append(f"Action `{action}` requires `{resource_type}` resource type.")
            suggestion_parts.append("")

            # Add expected format in code block
            suggestion_parts.append("**Expected format:**")
            suggestion_parts.append(f"```\n{required_format}\n```")

            # Add practical example based on the pattern
            example = self._generate_example_arn(required_format)
            if example:
                suggestion_parts.append("**Example:**")
                suggestion_parts.append(f"```\n{example}\n```")

            # Add helpful context for common patterns
            context = self._get_resource_context(action_name, resource_type, required_format)
            if context:
                suggestion_parts.append(f"**Note:** {context}")

        # Add current resources to help user understand the mismatch
        if provided_resources and len(provided_resources) <= 3:
            suggestion_parts.append("**Current resources:**")
            for resource in provided_resources:
                suggestion_parts.append(f"- `{resource}`")

        suggestion = "\n".join(suggestion_parts)
        return suggestion

    def _extract_resource_type_from_pattern(self, pattern: str) -> str:
        """
        Extract the resource type from an ARN pattern.

        Examples:
            arn:${Partition}:s3:::${BucketName}/${ObjectName} -> "object"
            arn:${Partition}:iam::${Account}:user/${UserName} -> "user"
            arn:${Partition}:ec2:${Region}:${Account}:instance/${InstanceId} -> "instance"
        """
        # Split ARN by colons to get resource part
        parts = pattern.split(":")
        if len(parts) < 6:
            return "resource"

        # Resource part is everything after the 5th colon
        resource_part = ":".join(parts[5:])

        # Extract resource type (part before / or entire string)
        if "/" in resource_part:
            resource_type = resource_part.split("/", maxsplit=1)[0]
        elif ":" in resource_part:
            resource_type = resource_part.split(":", maxsplit=1)[0]
        else:
            resource_type = resource_part

        # Remove template variables like ${...}
        resource_type = re.sub(r"\$\{[^}]+\}", "", resource_type)
        return resource_type.strip() or "resource"

    def _generate_example_arn(self, pattern: str) -> str:
        """
        Generate a practical example ARN based on the pattern.

        Converts AWS template variables to realistic examples.
        """
        example = pattern

        # Common substitutions
        substitutions = {
            r"\$\{Partition\}": "aws",
            r"\$\{Region\}": "us-east-1",
            r"\$\{Account\}": "123456789012",
            r"\$\{BucketName\}": "my-bucket",
            r"\$\{ObjectName\}": "*",
            r"\$\{UserName\}": "my-user",
            r"\$\{UserNameWithPath\}": "my-user",
            r"\$\{RoleName\}": "my-role",
            r"\$\{RoleNameWithPath\}": "my-role",
            r"\$\{GroupName\}": "my-group",
            r"\$\{PolicyName\}": "my-policy",
            r"\$\{FunctionName\}": "my-function",
            r"\$\{TableName\}": "MyTable",
            r"\$\{QueueName\}": "MyQueue",
            r"\$\{TopicName\}": "MyTopic",
            r"\$\{InstanceId\}": "i-1234567890abcdef0",
            r"\$\{VolumeId\}": "vol-1234567890abcdef0",
            r"\$\{SnapshotId\}": "snap-1234567890abcdef0",
            r"\$\{KeyId\}": "my-key",
            r"\$\{StreamName\}": "MyStream",
            r"\$\{LayerName\}": "my-layer",
            r"\$\{Token\}": "*",
            r"\$\{[^}]+\}": "*",  # Catch-all for any remaining variables
        }

        for pattern_var, replacement in substitutions.items():
            example = re.sub(pattern_var, replacement, example)

        return example

    def _get_resource_context(self, action_name: str, resource_type: str, pattern: str) -> str:
        """
        Provide helpful context about resource requirements.

        Analyzes the ARN pattern structure and action type to provide
        generic, service-agnostic guidance that works for any AWS service.
        """
        contexts = []

        # Detect path separator patterns (e.g., bucket/object, layer:version)
        if "/" in pattern:
            # Pattern has path separator - resource needs it too
            parts = pattern.split("/")
            if len(parts) > 1 and "${" in parts[-1]:
                # Last part is a variable like ${ObjectName}, ${InstanceId}
                contexts.append("ARN must include path separator (/) with resource identifier")

        # Detect colon-separated resource identifiers
        resource_part = ":".join(pattern.split(":")[5:]) if pattern.count(":") >= 5 else ""
        if resource_part.count(":") > 0 and "${" in resource_part:
            # Resource section uses colons, like function:version or layer:version
            contexts.append("ARN uses colon (:) separators in resource section")

        # Detect List/Describe actions (often need wildcards)
        if (
            action_name.startswith("List")
            or action_name.startswith("Describe")
            or action_name.startswith("Get")
        ):
            # Some Get/List actions require specific resources, others need "*"
            # Only suggest wildcard if pattern is actually "*"
            if pattern == "*":
                contexts.append("This action does not support resource-level permissions")

        # Generic resource type matching hint
        if resource_type and resource_type != "resource":
            # Avoid redundant message if resource type is obvious
            if not any(
                word in resource_type
                for word in ["object", "bucket", "function", "instance", "user", "role"]
            ):
                contexts.append(f"Resource ARN must be of type '{resource_type}'")

        return "Note: " + " | ".join(contexts) if contexts else ""

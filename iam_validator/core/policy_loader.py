"""IAM Policy Loader Module.

This module provides functionality to load and parse IAM policy documents
from various file formats (JSON, YAML) and directories.

The loader supports both eager loading (load all at once) and streaming
(process one file at a time) to optimize memory usage.

Example usage:
    loader = PolicyLoader()

    # Eager loading (loads all files into memory)
    policy = loader.load_from_file("policy.json")
    policies = loader.load_from_directory("./policies/", recursive=True)
    policies = loader.load_from_path("./policies/", recursive=False)

    # Streaming (memory-efficient, processes one file at a time)
    for file_path, policy in loader.stream_from_path("./policies/"):
        # Process each policy immediately
        validate_and_report(file_path, policy)

    # Batch processing (configurable batch size)
    for batch in loader.batch_from_paths(["./policies/"], batch_size=10):
        # Process batch of up to 10 policies
        validate_batch(batch)
"""

import json
import logging
import re
from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, overload

import yaml
from pydantic import ValidationError

from iam_validator.core.models import IAMPolicy


@dataclass
class StatementLineMap:
    """Line numbers for each field in a statement.

    Used for precise line-level PR comments on specific fields
    (e.g., pointing to the exact Action line, not just the statement start).
    """

    statement_start: int  # Opening brace line
    sid: int | None = None
    effect: int | None = None
    action: int | None = None
    not_action: int | None = None
    resource: int | None = None
    not_resource: int | None = None
    condition: int | None = None
    principal: int | None = None
    not_principal: int | None = None

    def get_line_for_field(self, field_name: str) -> int:
        """Get line number for a specific field, fallback to statement start.

        Args:
            field_name: Field name (case-insensitive): action, resource, condition, etc.

        Returns:
            Line number for the field, or statement_start if not found
        """
        field_map = {
            "sid": self.sid,
            "effect": self.effect,
            "action": self.action,
            "notaction": self.not_action,
            "resource": self.resource,
            "notresource": self.not_resource,
            "condition": self.condition,
            "principal": self.principal,
            "notprincipal": self.not_principal,
        }
        line = field_map.get(field_name.lower().replace("_", ""))
        return line if line is not None else self.statement_start


@dataclass
class PolicyLineMap:
    """Line mappings for all statements in a policy file.

    Provides field-level line number lookup for PR comment placement.
    """

    statements: list[StatementLineMap] = field(default_factory=list)

    def get_statement_map(self, index: int) -> StatementLineMap | None:
        """Get line map for a specific statement by index.

        Args:
            index: Statement index (0-based)

        Returns:
            StatementLineMap or None if index out of range
        """
        if 0 <= index < len(self.statements):
            return self.statements[index]
        return None

    def get_line_for_field(self, statement_index: int, field_name: str) -> int | None:
        """Get line number for a field in a specific statement.

        Args:
            statement_index: Statement index (0-based)
            field_name: Field name (action, resource, condition, etc.)

        Returns:
            Line number or None if statement not found
        """
        stmt_map = self.get_statement_map(statement_index)
        if stmt_map:
            return stmt_map.get_line_for_field(field_name)
        return None


logger = logging.getLogger(__name__)


class PolicyValidationLimits:
    """Validation limits for policy loading.

    These limits protect against DoS attacks via maliciously crafted policies
    and ensure reasonable resource usage.
    """

    # Maximum file size in bytes (default: 10MB - AWS limit is 6KB for managed policies)
    MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024
    # Maximum JSON/YAML nesting depth
    MAX_DEPTH: int = 50
    # Maximum number of statements per policy (AWS limit is ~20-30 depending on size)
    MAX_STATEMENTS: int = 100
    # Maximum number of actions per statement
    MAX_ACTIONS_PER_STATEMENT: int = 500
    # Maximum number of resources per statement
    MAX_RESOURCES_PER_STATEMENT: int = 500
    # Maximum string length for any field
    MAX_STRING_LENGTH: int = 10000


class PolicyLoader:
    """Loads and parses IAM policy documents from files.

    Supports both eager loading and streaming for memory efficiency.
    """

    SUPPORTED_EXTENSIONS = {".json", ".yaml", ".yml"}
    # Directories to skip when scanning recursively (cache, build artifacts, etc.)
    SKIP_DIRECTORIES = {".cache", ".git", "node_modules", "__pycache__", ".venv", "venv"}

    def __init__(
        self,
        max_file_size_mb: int = 100,
        enforce_limits: bool = True,
    ) -> None:
        """Initialize the policy loader.

        Args:
            max_file_size_mb: Maximum file size in MB to load (default: 100MB)
            enforce_limits: Whether to enforce validation limits (default: True)
        """
        self.loaded_policies: list[tuple[str, IAMPolicy]] = []
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.enforce_limits = enforce_limits
        # Track parsing/validation errors for reporting
        self.parsing_errors: list[tuple[str, str]] = []  # (file_path, error_message)

    @staticmethod
    def check_json_depth(
        obj: Any, max_depth: int = PolicyValidationLimits.MAX_DEPTH, current_depth: int = 0
    ) -> bool:
        """Check if JSON object exceeds maximum nesting depth.

        Args:
            obj: JSON object to check
            max_depth: Maximum allowed depth
            current_depth: Current recursion depth

        Returns:
            True if within limits, raises ValueError if exceeded
        """
        if current_depth > max_depth:
            raise ValueError(f"JSON nesting depth exceeds maximum of {max_depth}")

        if isinstance(obj, dict):
            for value in obj.values():
                PolicyLoader.check_json_depth(value, max_depth, current_depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                PolicyLoader.check_json_depth(item, max_depth, current_depth + 1)

        return True

    @staticmethod
    def validate_policy_limits(data: dict[str, Any]) -> list[str]:
        """Validate policy data against size limits.

        Args:
            data: Parsed policy dictionary

        Returns:
            List of validation warnings (empty if all limits passed)
        """
        warnings: list[str] = []
        limits = PolicyValidationLimits

        # Check statement count
        statements = data.get("Statement", [])
        if isinstance(statements, list) and len(statements) > limits.MAX_STATEMENTS:
            warnings.append(
                f"Policy has {len(statements)} statements, exceeds recommended max of {limits.MAX_STATEMENTS}"
            )

        # Check each statement
        for i, stmt in enumerate(statements if isinstance(statements, list) else []):
            if not isinstance(stmt, dict):
                continue

            # Check actions
            actions = stmt.get("Action", [])
            if isinstance(actions, list) and len(actions) > limits.MAX_ACTIONS_PER_STATEMENT:
                warnings.append(
                    f"Statement {i} has {len(actions)} actions, exceeds recommended max of {limits.MAX_ACTIONS_PER_STATEMENT}"
                )

            # Check resources
            resources = stmt.get("Resource", [])
            if isinstance(resources, list) and len(resources) > limits.MAX_RESOURCES_PER_STATEMENT:
                warnings.append(
                    f"Statement {i} has {len(resources)} resources, exceeds recommended max of {limits.MAX_RESOURCES_PER_STATEMENT}"
                )

        return warnings

    @staticmethod
    def _find_statement_line_numbers(file_content: str) -> list[int]:
        """Find line numbers for each statement in a JSON policy file.

        Args:
            file_content: Raw content of the policy file

        Returns:
            List of line numbers (1-indexed) for each statement's Sid or opening brace
        """
        lines = file_content.split("\n")
        statement_lines = []
        in_statement_array = False
        brace_depth = 0
        statement_start_line = None
        current_statement_first_field = None

        for line_num, line in enumerate(lines, start=1):
            # Look for "Statement" array
            if '"Statement"' in line or "'Statement'" in line:
                in_statement_array = True
                continue

            if not in_statement_array:
                continue

            # Track opening braces for statement objects
            for char in line:
                if char == "{":
                    if brace_depth == 0 and statement_start_line is None:
                        # Found the start of a statement object
                        statement_start_line = line_num
                        current_statement_first_field = None
                    brace_depth += 1
                elif char == "}":
                    brace_depth -= 1
                    if brace_depth == 0 and statement_start_line is not None:
                        # Completed a statement object
                        # Use first field line if found, otherwise use opening brace
                        statement_lines.append(
                            current_statement_first_field or statement_start_line
                        )
                        statement_start_line = None
                        current_statement_first_field = None
                elif char == "]" and brace_depth == 0:
                    # End of Statement array
                    in_statement_array = False
                    break

            # Track first field in statement (usually Sid, Effect, or Action)
            if (
                in_statement_array
                and brace_depth == 1
                and current_statement_first_field is None
                and statement_start_line is not None
            ):
                stripped = line.strip()
                # Look for first JSON field (e.g., "Sid":, "Effect":, "Action":)
                if (
                    stripped
                    and stripped[0] == '"'
                    and ":" in stripped
                    and not stripped.startswith('"{')
                ):
                    current_statement_first_field = line_num

        return statement_lines

    @staticmethod
    def _find_yaml_statement_line_numbers(file_content: str) -> list[int]:
        """Find line numbers for each statement in a YAML policy file.

        Uses PyYAML's line tracking to find where each statement starts.

        Args:
            file_content: Raw content of the YAML policy file

        Returns:
            List of line numbers (1-indexed) for each statement
        """

        class LineTrackingLoader(yaml.SafeLoader):
            """Custom YAML loader that tracks line numbers for mappings."""

            pass

        def construct_mapping_with_line(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict:
            """Construct a mapping while preserving line number info."""
            mapping = loader.construct_mapping(node)
            # Store line number as a special key (1-indexed)
            mapping["__line__"] = node.start_mark.line + 1
            return mapping

        # Register custom constructor for mappings
        LineTrackingLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
            construct_mapping_with_line,
        )

        try:
            data = yaml.load(file_content, Loader=LineTrackingLoader)  # noqa: S506
        except yaml.YAMLError:
            return []

        if not data or not isinstance(data, dict):
            return []

        # Extract statement line numbers
        statement_line_numbers = []
        statements = data.get("Statement", [])

        if isinstance(statements, list):
            for stmt in statements:
                if isinstance(stmt, dict) and "__line__" in stmt:
                    statement_line_numbers.append(stmt["__line__"])

        return statement_line_numbers

    @staticmethod
    def parse_statement_field_lines(file_content: str) -> PolicyLineMap:
        """Parse JSON to find exact line numbers for each field in each statement.

        This provides field-level line mapping for precise PR comment placement.
        For example, an issue about Action: "*" will point to the Action line,
        not just the statement's opening brace.

        Args:
            file_content: Raw content of the JSON policy file

        Returns:
            PolicyLineMap with field-level line numbers for all statements
        """
        lines = file_content.split("\n")
        policy_map = PolicyLineMap()

        in_statement_array = False
        brace_depth = 0
        current_stmt: StatementLineMap | None = None

        # Field name pattern (case-insensitive for robustness)
        field_pattern = re.compile(
            r'^\s*"(Sid|Effect|Action|NotAction|Resource|NotResource|Condition|Principal|NotPrincipal)"\s*:',
            re.IGNORECASE,
        )

        for line_num, line in enumerate(lines, start=1):
            # Look for "Statement" array
            if '"Statement"' in line or "'Statement'" in line:
                in_statement_array = True
                continue

            if not in_statement_array:
                continue

            # Track braces
            for char in line:
                if char == "{":
                    if brace_depth == 0:
                        # Start of a new statement
                        current_stmt = StatementLineMap(statement_start=line_num)
                    brace_depth += 1
                elif char == "}":
                    brace_depth -= 1
                    if brace_depth == 0 and current_stmt is not None:
                        # End of statement - save it
                        policy_map.statements.append(current_stmt)
                        current_stmt = None
                elif char == "]" and brace_depth == 0:
                    # End of Statement array
                    in_statement_array = False
                    break

            # Parse field names at brace_depth == 1 (direct children of statement)
            if in_statement_array and brace_depth == 1 and current_stmt is not None:
                match = field_pattern.match(line)
                if match:
                    field_name = match.group(1).lower()
                    # Map to dataclass attribute
                    if field_name == "sid":
                        current_stmt.sid = line_num
                    elif field_name == "effect":
                        current_stmt.effect = line_num
                    elif field_name == "action":
                        current_stmt.action = line_num
                    elif field_name == "notaction":
                        current_stmt.not_action = line_num
                    elif field_name == "resource":
                        current_stmt.resource = line_num
                    elif field_name == "notresource":
                        current_stmt.not_resource = line_num
                    elif field_name == "condition":
                        current_stmt.condition = line_num
                    elif field_name == "principal":
                        current_stmt.principal = line_num
                    elif field_name == "notprincipal":
                        current_stmt.not_principal = line_num

        return policy_map

    def _check_file_size(self, path: Path) -> bool:
        """Check if file size is within limits.

        Args:
            path: Path to the file

        Returns:
            True if file size is acceptable, False otherwise
        """
        try:
            file_size = path.stat().st_size
            if file_size > self.max_file_size_bytes:
                logger.warning(
                    f"File {path} exceeds maximum size "
                    f"({file_size / 1024 / 1024:.2f}MB > "
                    f"{self.max_file_size_bytes / 1024 / 1024:.2f}MB). Skipping."
                )
                return False
            return True
        except OSError as e:
            logger.error("Failed to check file size for %s: %s", path, e)
            return False

    @overload
    def load_from_file(self, file_path: str, return_raw_dict: bool = False) -> IAMPolicy | None: ...

    @overload
    def load_from_file(
        self, file_path: str, return_raw_dict: bool = True
    ) -> tuple[IAMPolicy, dict] | None: ...

    def load_from_file(
        self, file_path: str, return_raw_dict: bool = False
    ) -> IAMPolicy | tuple[IAMPolicy, dict] | None:
        """Load a single IAM policy from a file.

        Args:
            file_path: Path to the policy file
            return_raw_dict: If True, return tuple of (policy, raw_dict) for validation

        Returns:
            Parsed IAMPolicy, or tuple of (IAMPolicy, raw_dict) if return_raw_dict=True,
            or None if loading fails
        """
        path = Path(file_path)

        if not path.exists():
            logger.error("File not found: %s", file_path)
            return None

        if not path.is_file():
            logger.error("Not a file: %s", file_path)
            return None

        if path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            logger.warning(
                f"Unsupported file extension: {path.suffix}. "
                f"Supported: {', '.join(self.SUPPORTED_EXTENSIONS)}"
            )
            return None

        # Check file size before loading
        if not self._check_file_size(path):
            return None

        try:
            with open(path, encoding="utf-8") as f:
                file_content = f.read()

            # Parse line numbers based on file type
            statement_line_numbers = []
            if path.suffix.lower() == ".json":
                statement_line_numbers = self._find_statement_line_numbers(file_content)
                data = json.loads(file_content)
            else:  # .yaml or .yml
                statement_line_numbers = self._find_yaml_statement_line_numbers(file_content)
                data = yaml.safe_load(file_content)

            # Validate and parse the policy
            policy = IAMPolicy.model_validate(data)

            # Attach line numbers to statements
            if statement_line_numbers:
                for idx, statement in enumerate(policy.statement or []):
                    if idx < len(statement_line_numbers):
                        statement.line_number = statement_line_numbers[idx]

            logger.info("Successfully loaded policy from %s", file_path)
            return (policy, data) if return_raw_dict else policy

        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON: {e}"
            logger.error("Invalid JSON in %s: %s", file_path, e)
            self.parsing_errors.append((file_path, error_msg))
            return None
        except yaml.YAMLError as e:
            error_msg = f"Invalid YAML: {e}"
            logger.error("Invalid YAML in %s: %s", file_path, e)
            self.parsing_errors.append((file_path, error_msg))
            return None
        except ValidationError as e:
            # Handle Pydantic validation errors with helpful messages
            error_messages = []
            for error in e.errors():
                loc = ".".join(str(x) for x in error["loc"])
                error_type = error["type"]

                # Provide user-friendly messages for common errors
                if error_type == "extra_forbidden":
                    # Extract the field name that has a typo
                    field_name = error["loc"][-1] if error["loc"] else "unknown"
                    error_messages.append(
                        f"Unknown field '{field_name}' at {loc}. "
                        f"This might be a typo. Did you mean 'Condition', 'Action', or 'Resource'?"
                    )
                else:
                    error_messages.append(f"{loc}: {error['msg']}")

            error_summary = "\n  ".join(error_messages)
            logger.error(
                "Policy validation failed for %s:\n  %s",
                file_path,
                error_summary,
            )
            # Track parsing error for GitHub reporting
            self.parsing_errors.append((file_path, error_summary))
            return None
        except Exception as e:
            logger.error("Failed to load policy from %s: %s", file_path, e)
            return None

    def load_from_directory(
        self, directory_path: str, recursive: bool = True
    ) -> list[tuple[str, IAMPolicy]]:
        """Load all IAM policies from a directory.

        Args:
            directory_path: Path to the directory
            recursive: Whether to search subdirectories

        Returns:
            List of tuples (file_path, policy)
        """
        path = Path(directory_path)

        if not path.exists():
            logger.error("Directory not found: %s", directory_path)
            return []

        if not path.is_dir():
            logger.error("Not a directory: %s", directory_path)
            return []

        policies: list[tuple[str, IAMPolicy]] = []
        pattern = "**/*" if recursive else "*"

        for file_path in path.glob(pattern):
            # Skip directories that shouldn't be scanned
            if any(skip_dir in file_path.parts for skip_dir in self.SKIP_DIRECTORIES):
                continue

            if file_path.is_file() and file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                policy = self.load_from_file(str(file_path))
                if policy:
                    policies.append((str(file_path), policy))

        logger.info("Loaded %d policies from %s", len(policies), directory_path)
        return policies

    def load_from_path(self, path: str, recursive: bool = True) -> list[tuple[str, IAMPolicy]]:
        """Load IAM policies from a file or directory.

        Args:
            path: Path to file or directory
            recursive: Whether to search subdirectories (only applies to directories)

        Returns:
            List of tuples (file_path, policy)
        """
        path_obj = Path(path)

        if path_obj.is_file():
            policy = self.load_from_file(path)
            return [(path, policy)] if policy else []
        elif path_obj.is_dir():
            return self.load_from_directory(path, recursive)
        else:
            logger.error("Path not found: %s", path)
            return []

    def load_from_paths(
        self, paths: list[str], recursive: bool = True
    ) -> list[tuple[str, IAMPolicy]]:
        """Load IAM policies from multiple files or directories.

        Args:
            paths: List of paths to files or directories
            recursive: Whether to search subdirectories (only applies to directories)

        Returns:
            List of tuples (file_path, policy) from all paths combined
        """
        all_policies: list[tuple[str, IAMPolicy]] = []

        for path in paths:
            policies = self.load_from_path(path.strip(), recursive)
            all_policies.extend(policies)

        logger.info("Loaded %d total policies from %d path(s)", len(all_policies), len(paths))
        return all_policies

    def _get_policy_files(self, path: str, recursive: bool = True) -> Generator[Path, None, None]:
        """Get all policy files from a path (file or directory).

        This is a generator that yields file paths without loading them,
        enabling memory-efficient iteration.

        Args:
            path: Path to file or directory
            recursive: Whether to search subdirectories

        Yields:
            Path objects for policy files
        """
        path_obj = Path(path)

        if path_obj.is_file():
            if path_obj.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                yield path_obj
        elif path_obj.is_dir():
            pattern = "**/*" if recursive else "*"
            for file_path in path_obj.glob(pattern):
                # Skip directories that shouldn't be scanned
                if any(skip_dir in file_path.parts for skip_dir in self.SKIP_DIRECTORIES):
                    continue

                if file_path.is_file() and file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                    yield file_path
        else:
            logger.error("Path not found: %s", path)

    def stream_from_path(
        self, path: str, recursive: bool = True
    ) -> Generator[tuple[str, IAMPolicy], None, None]:
        """Stream IAM policies from a file or directory one at a time.

        This is a memory-efficient alternative to load_from_path that yields
        policies one at a time instead of loading all into memory.

        Args:
            path: Path to file or directory
            recursive: Whether to search subdirectories

        Yields:
            Tuples of (file_path, policy) for each successfully loaded policy
        """
        for file_path in self._get_policy_files(path, recursive):
            policy = self.load_from_file(str(file_path))
            if policy:
                yield (str(file_path), policy)

    def stream_from_paths(
        self, paths: list[str], recursive: bool = True
    ) -> Generator[tuple[str, IAMPolicy], None, None]:
        """Stream IAM policies from multiple paths one at a time.

        This is a memory-efficient alternative to load_from_paths that yields
        policies one at a time instead of loading all into memory.

        Args:
            paths: List of paths to files or directories
            recursive: Whether to search subdirectories

        Yields:
            Tuples of (file_path, policy) for each successfully loaded policy
        """
        for path in paths:
            yield from self.stream_from_path(path.strip(), recursive)

    def batch_from_paths(
        self, paths: list[str], batch_size: int = 10, recursive: bool = True
    ) -> Generator[list[tuple[str, IAMPolicy]], None, None]:
        """Load policies in batches for balanced memory usage and performance.

        Args:
            paths: List of paths to files or directories
            batch_size: Number of policies per batch (default: 10)
            recursive: Whether to search subdirectories

        Yields:
            Lists of (file_path, policy) tuples, up to batch_size per list
        """
        batch: list[tuple[str, IAMPolicy]] = []

        for file_path, policy in self.stream_from_paths(paths, recursive):
            batch.append((file_path, policy))

            if len(batch) >= batch_size:
                yield batch
                batch = []

        # Yield remaining policies
        if batch:
            yield batch

    @staticmethod
    def parse_policy_string(policy_json: str) -> IAMPolicy | None:
        """Parse an IAM policy from a JSON string.

        Args:
            policy_json: JSON string containing the policy

        Returns:
            Parsed IAMPolicy or None if parsing fails
        """
        try:
            data = json.loads(policy_json)
            policy = IAMPolicy.model_validate(data)
            logger.info("Successfully parsed policy from string")
            return policy
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON: %s", e)
            return None
        except ValidationError as e:
            # Handle Pydantic validation errors with helpful messages
            error_messages = []
            for error in e.errors():
                loc = ".".join(str(x) for x in error["loc"])
                error_type = error["type"]

                # Provide user-friendly messages for common errors
                if error_type == "extra_forbidden":
                    # Extract the field name that has a typo
                    field_name = error["loc"][-1] if error["loc"] else "unknown"
                    error_messages.append(
                        f"Unknown field '{field_name}' at {loc}. "
                        f"This might be a typo. Did you mean 'Condition', 'Action', or 'Resource'?"
                    )
                else:
                    error_messages.append(f"{loc}: {error['msg']}")

            logger.error("Policy validation failed:\n  %s", "\n  ".join(error_messages))
            return None
        except Exception as e:
            logger.error("Failed to parse policy string: %s", e)
            return None

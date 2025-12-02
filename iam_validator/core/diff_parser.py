"""Diff Parser Module.

This module parses GitHub PR diff information to extract changed line numbers.
It supports GitHub's unified diff format and provides utilities for determining
which lines and statements were modified in a PR.
"""

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ParsedDiff:
    """Parsed GitHub PR diff information for a single file.

    Attributes:
        file_path: Relative path to the file from repository root
        changed_lines: Set of all line numbers that were added or modified (new side)
        added_lines: Set of line numbers that were added (new side)
        deleted_lines: Set of line numbers that were deleted (old side)
        status: File status (added, modified, removed, renamed)
    """

    file_path: str
    changed_lines: set[int]
    added_lines: set[int]
    deleted_lines: set[int]
    status: str


@dataclass
class StatementLocation:
    """Location information for a statement in a policy file.

    Attributes:
        statement_index: Zero-based index of the statement
        start_line: First line number of the statement (1-indexed)
        end_line: Last line number of the statement (1-indexed)
        has_changes: True if any line in this range was modified
    """

    statement_index: int
    start_line: int
    end_line: int
    has_changes: bool


class DiffParser:
    """Parser for GitHub PR diff information."""

    @staticmethod
    def parse_pr_files(pr_files: list[dict[str, Any]]) -> dict[str, ParsedDiff]:
        """Parse GitHub PR files response to extract changed line information.

        Args:
            pr_files: List of file dicts from GitHub API's get_pr_files() call.
                     Each dict contains: filename, status, patch, additions, deletions

        Returns:
            Dict mapping file paths to ParsedDiff objects

        Example:
            >>> pr_files = [{
            ...     "filename": "policies/policy.json",
            ...     "status": "modified",
            ...     "patch": "@@ -5,3 +5,4 @@\\n context\\n-old\\n+new\\n+added"
            ... }]
            >>> result = DiffParser.parse_pr_files(pr_files)
            >>> result["policies/policy.json"].changed_lines
            {6, 7}
        """
        parsed: dict[str, ParsedDiff] = {}

        for file_info in pr_files:
            if not isinstance(file_info, dict):
                continue

            filename = file_info.get("filename")
            if not filename or not isinstance(filename, str):
                continue

            status = file_info.get("status", "modified")
            patch = file_info.get("patch")

            # Files without patches (e.g., binary files, very large files)
            # For added/modified files, we use a "no_patch" marker to indicate
            # that we should allow comments on any line (handled in pr_commenter)
            if not patch or not isinstance(patch, str):
                logger.debug(f"No patch available for {filename} (status={status})")
                # Mark as "no_patch" so pr_commenter can handle this specially
                # For added/modified files without patch, we'll allow inline comments
                # on any line since GitHub likely truncated the diff due to size
                parsed[filename] = ParsedDiff(
                    file_path=filename,
                    changed_lines=set(),  # Empty, but status indicates handling
                    added_lines=set(),
                    deleted_lines=set(),
                    status=f"{status}_no_patch",  # Mark as no_patch variant
                )
                continue

            try:
                diff = DiffParser.parse_unified_diff(patch)
                parsed[filename] = ParsedDiff(
                    file_path=filename,
                    changed_lines=diff["changed_lines"],
                    added_lines=diff["added_lines"],
                    deleted_lines=diff["deleted_lines"],
                    status=status,
                )
                logger.debug(
                    f"Parsed diff for {filename}: {len(diff['changed_lines'])} changed lines"
                )
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning(f"Failed to parse diff for {filename}: {e}")
                # Track file with empty change sets on parse error
                parsed[filename] = ParsedDiff(
                    file_path=filename,
                    changed_lines=set(),
                    added_lines=set(),
                    deleted_lines=set(),
                    status=status,
                )

        return parsed

    @staticmethod
    def parse_unified_diff(patch: str) -> dict[str, set[int]]:
        """Parse a unified diff patch to extract changed line numbers.

        Unified diff format uses @@ headers to indicate line ranges:
        @@ -old_start,old_count +new_start,new_count @@

        Lines starting with:
        - '-' are deletions (old side line numbers)
        - '+' are additions (new side line numbers)
        - ' ' are context (both sides)

        Args:
            patch: Unified diff string from GitHub API

        Returns:
            Dict with keys:
            - changed_lines: All added/modified lines (new side)
            - added_lines: Only added lines (new side)
            - deleted_lines: Only deleted lines (old side)

        Example:
            >>> patch = '''@@ -5,3 +5,4 @@
            ...  context line
            ... -deleted line
            ... +added line
            ... +another added line
            ...  context line'''
            >>> result = DiffParser.parse_unified_diff(patch)
            >>> result['added_lines']
            {6, 7}
        """
        changed_lines: set[int] = set()
        added_lines: set[int] = set()
        deleted_lines: set[int] = set()

        # Pattern to match @@ -old_start,old_count +new_start,new_count @@ headers
        # Handles variations: @@ -5,3 +5,4 @@, @@ -5 +5,2 @@, etc.
        hunk_header_pattern = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")

        lines = patch.split("\n")
        current_new_line = 0
        current_old_line = 0

        for line in lines:
            # Check for hunk header
            match = hunk_header_pattern.match(line)
            if match:
                old_start = int(match.group(1))
                new_start = int(match.group(3))
                current_old_line = old_start
                current_new_line = new_start
                continue

            # Process diff lines
            if not line:
                continue

            first_char = line[0]

            if first_char == "+":
                # Addition (new side only)
                added_lines.add(current_new_line)
                changed_lines.add(current_new_line)
                current_new_line += 1
            elif first_char == "-":
                # Deletion (old side only)
                deleted_lines.add(current_old_line)
                current_old_line += 1
            elif first_char == " ":
                # Context line (both sides)
                current_new_line += 1
                current_old_line += 1
            # Ignore lines that don't start with +, -, or space (e.g., \ No newline)

        return {
            "changed_lines": changed_lines,
            "added_lines": added_lines,
            "deleted_lines": deleted_lines,
        }

    @staticmethod
    def get_modified_statements(
        line_mapping: dict[int, int],
        changed_lines: set[int],
        policy_file: str,
    ) -> dict[int, StatementLocation]:
        """Determine which statements were modified based on changed lines.

        A statement is considered modified if ANY line within its range appears
        in the changed_lines set.

        Args:
            line_mapping: Dict mapping statement index to statement start line
                         (from PRCommenter._get_line_mapping())
            changed_lines: Set of line numbers that were changed in the PR
            policy_file: Path to the policy file (to determine statement end lines)

        Returns:
            Dict mapping statement indices to StatementLocation objects
            Only includes statements that were modified.

        Example:
            >>> line_mapping = {0: 3, 1: 10, 2: 20}  # Statement starts
            >>> changed_lines = {5, 6}  # Lines changed in statement 0
            >>> result = get_modified_statements(line_mapping, changed_lines, "policy.json")
            >>> result[0].has_changes
            True
            >>> 1 in result  # Statement 1 not modified
            False
        """
        if not line_mapping or not changed_lines:
            return {}

        # Determine end line for each statement
        statement_ranges: dict[int, tuple[int, int]] = {}
        sorted_indices = sorted(line_mapping.keys())

        for i, stmt_idx in enumerate(sorted_indices):
            start_line = line_mapping[stmt_idx]

            # End line is either:
            # 1. One line before next statement starts, OR
            # 2. EOF for the last statement
            if i < len(sorted_indices) - 1:
                next_start = line_mapping[sorted_indices[i + 1]]
                end_line = next_start - 1
            else:
                # For last statement, try to read file to get actual end
                end_line = DiffParser.get_statement_end_line(policy_file, start_line)

            statement_ranges[stmt_idx] = (start_line, end_line)

        # Check which statements have changes
        modified_statements: dict[int, StatementLocation] = {}

        for stmt_idx, (start_line, end_line) in statement_ranges.items():
            # Check if any line in this statement's range was changed
            statement_lines = set(range(start_line, end_line + 1))
            has_changes = bool(statement_lines & changed_lines)

            if has_changes:
                modified_statements[stmt_idx] = StatementLocation(
                    statement_index=stmt_idx,
                    start_line=start_line,
                    end_line=end_line,
                    has_changes=True,
                )
                logger.debug(f"Statement {stmt_idx} (lines {start_line}-{end_line}) was modified")

        return modified_statements

    @staticmethod
    def get_statement_end_line(policy_file: str, start_line: int) -> int:
        """Find the end line of a statement block starting at start_line.

        Tracks brace depth to find where the statement object closes.

        Args:
            policy_file: Path to policy file
            start_line: Line number where statement starts (1-indexed)

        Returns:
            Line number where statement ends (1-indexed)
        """
        try:
            with open(policy_file, encoding="utf-8") as f:
                lines = f.readlines()

            # Start counting from the statement's opening brace
            brace_depth = 0
            in_statement = False

            for line_num in range(start_line - 1, len(lines)):  # Convert to 0-indexed
                line = lines[line_num]

                # Track braces
                for char in line:
                    if char == "{":
                        brace_depth += 1
                        in_statement = True
                    elif char == "}":
                        brace_depth -= 1

                        # Found the closing brace for this statement
                        if in_statement and brace_depth == 0:
                            return line_num + 1  # Convert back to 1-indexed

            # If we couldn't find the end, return a reasonable default
            # (start_line + 20 or end of file)
            return min(start_line + 20, len(lines))

        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.debug(f"Could not determine statement end line: {e}")
            return start_line + 10  # Reasonable default

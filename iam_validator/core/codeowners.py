"""CODEOWNERS file parser for GitHub repositories.

This module provides functionality to parse GitHub CODEOWNERS files and
determine which users/teams own specific files. Used to authorize users
who can ignore validation findings.

Reference: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import PurePosixPath
from typing import ClassVar


@dataclass(slots=True)
class CodeOwnerRule:
    """A single rule from a CODEOWNERS file.

    Attributes:
        pattern: File pattern (glob-style, GitHub CODEOWNERS format)
        owners: List of @users and/or @org/teams
        compiled_pattern: Pre-compiled regex for fast matching
    """

    pattern: str
    owners: list[str]
    compiled_pattern: re.Pattern[str] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Pre-compile the pattern for efficient matching."""
        self.compiled_pattern = _compile_codeowners_pattern(self.pattern)


@lru_cache(maxsize=256)
def _compile_codeowners_pattern(pattern: str) -> re.Pattern[str]:
    """Compile a CODEOWNERS pattern to regex with caching.

    CODEOWNERS patterns follow these rules:
    - Patterns starting with / are relative to repo root
    - Patterns without / match any path containing that component
    - * matches anything except /
    - ** matches anything including /
    - Trailing / matches directories

    Args:
        pattern: CODEOWNERS glob pattern

    Returns:
        Compiled regex pattern
    """
    # Normalize the pattern
    original_pattern = pattern
    pattern = pattern.strip()

    # Handle leading slash (anchored to root)
    anchored = pattern.startswith("/")
    if anchored:
        pattern = pattern[1:]

    # Handle trailing slash (directory match)
    is_dir = pattern.endswith("/")
    if is_dir:
        pattern = pattern[:-1]

    # Escape special regex characters except * and ?
    pattern = re.escape(pattern)

    # Convert glob patterns to regex
    # ** matches any number of directories
    pattern = pattern.replace(r"\*\*", "<<<DOUBLE_STAR>>>")
    # * matches anything except /
    pattern = pattern.replace(r"\*", "[^/]*")
    # ** -> match anything
    pattern = pattern.replace("<<<DOUBLE_STAR>>>", ".*")
    # ? matches single character except /
    pattern = pattern.replace(r"\?", "[^/]")

    # Build final regex
    if anchored:
        # Anchored patterns match from repo root
        regex = f"^{pattern}"
    elif "/" in original_pattern.lstrip("/"):
        # Patterns with / in them are implicitly anchored
        regex = f"^{pattern}"
    else:
        # Patterns without / can match anywhere in path
        regex = f"(^|/){pattern}"

    if is_dir:
        # Directory patterns match the directory and anything under it
        regex += "(/|$)"
    else:
        # File patterns match exactly or as prefix for directories
        regex += "($|/)"

    return re.compile(regex)


class CodeOwnersParser:
    """Parser for GitHub CODEOWNERS file format.

    Parses CODEOWNERS content and provides file-to-owner mapping.
    Uses last-matching-pattern semantics as per GitHub's behavior.

    Example:
        >>> content = '''
        ... # Default owners
        ... * @default-team
        ... # IAM policies owned by security
        ... /policies/**/*.json @security-team @security-lead
        ... '''
        >>> parser = CodeOwnersParser(content)
        >>> parser.get_owners_for_file("policies/admin/admin.json")
        ['@security-team', '@security-lead']
    """

    CODEOWNERS_PATHS: ClassVar[list[str]] = [
        "CODEOWNERS",
        ".github/CODEOWNERS",
        "docs/CODEOWNERS",
    ]

    def __init__(self, content: str) -> None:
        """Initialize parser with CODEOWNERS content.

        Args:
            content: Raw content of CODEOWNERS file
        """
        self.rules: list[CodeOwnerRule] = []
        self._parse(content)

    def _parse(self, content: str) -> None:
        """Parse CODEOWNERS file content.

        Args:
            content: Raw CODEOWNERS file content
        """
        for line in content.splitlines():
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Split into pattern and owners
            parts = line.split()
            if len(parts) >= 2:
                pattern = parts[0]
                owners = parts[1:]
                self.rules.append(CodeOwnerRule(pattern=pattern, owners=owners))
            elif len(parts) == 1:
                # Pattern with no owners (unsets ownership)
                self.rules.append(CodeOwnerRule(pattern=parts[0], owners=[]))

    def get_owners_for_file(self, file_path: str) -> list[str]:
        """Get owners for a specific file path.

        Uses last-matching-pattern semantics as per GitHub's behavior.
        If multiple patterns match, the last one in the file wins.

        Args:
            file_path: Path to the file (relative to repo root)

        Returns:
            List of owners for the file, or empty list if no match
        """
        # Normalize path (remove leading ./ or /)
        file_path = file_path.lstrip("./")

        # Find all matching rules, last one wins
        owners: list[str] = []
        for rule in self.rules:
            if rule.compiled_pattern and rule.compiled_pattern.search(file_path):
                owners = rule.owners

        return owners

    def is_owner(self, username: str, file_path: str) -> bool:
        """Check if a user is an owner of a file.

        Note: This only checks direct username matches. For team membership,
        use GitHubIntegration.is_user_codeowner() which resolves teams.

        Args:
            username: GitHub username (with or without @)
            file_path: Path to the file

        Returns:
            True if user is directly listed as owner
        """
        # Normalize username
        username = username.lstrip("@").lower()

        owners = self.get_owners_for_file(file_path)
        for owner in owners:
            owner = owner.lstrip("@").lower()
            # Direct username match (not team)
            if "/" not in owner and owner == username:
                return True

        return False

    def get_teams_for_file(self, file_path: str) -> list[tuple[str, str]]:
        """Get team owners for a file as (org, team_slug) tuples.

        Args:
            file_path: Path to the file

        Returns:
            List of (org, team_slug) tuples
        """
        owners = self.get_owners_for_file(file_path)
        teams: list[tuple[str, str]] = []

        for owner in owners:
            owner = owner.lstrip("@")
            if "/" in owner:
                parts = owner.split("/", 1)
                if len(parts) == 2:
                    teams.append((parts[0], parts[1]))

        return teams


def normalize_path(path: str) -> str:
    """Normalize a file path for CODEOWNERS matching.

    Args:
        path: File path (may be absolute or relative)

    Returns:
        Normalized relative path
    """
    # Convert to posix-style path
    path = str(PurePosixPath(path))
    # Remove leading ./
    if path.startswith("./"):
        path = path[2:]
    # Remove leading /
    path = path.lstrip("/")
    return path

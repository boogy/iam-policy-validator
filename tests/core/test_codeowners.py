"""Tests for CODEOWNERS file parser."""

from iam_validator.core.codeowners import (
    CodeOwnerRule,
    CodeOwnersParser,
    normalize_path,
)


class TestCodeOwnersParser:
    """Tests for CodeOwnersParser class."""

    def test_parse_simple_codeowners(self):
        """Test parsing simple CODEOWNERS file."""
        content = """
# Default owners
* @default-owner

# IAM policies
/policies/ @security-team
"""
        parser = CodeOwnersParser(content)

        assert len(parser.rules) == 2
        assert parser.rules[0].pattern == "*"
        assert parser.rules[0].owners == ["@default-owner"]
        assert parser.rules[1].pattern == "/policies/"
        assert parser.rules[1].owners == ["@security-team"]

    def test_parse_multiple_owners(self):
        """Test parsing CODEOWNERS with multiple owners."""
        content = """
*.json @security-team @platform-lead @reviewer
"""
        parser = CodeOwnersParser(content)

        assert len(parser.rules) == 1
        assert parser.rules[0].owners == ["@security-team", "@platform-lead", "@reviewer"]

    def test_parse_team_owners(self):
        """Test parsing CODEOWNERS with team owners."""
        content = """
/policies/ @org/security-team
/config/ @org/platform-team @admin-user
"""
        parser = CodeOwnersParser(content)

        assert len(parser.rules) == 2
        assert parser.rules[0].owners == ["@org/security-team"]
        assert parser.rules[1].owners == ["@org/platform-team", "@admin-user"]

    def test_parse_with_comments(self):
        """Test parsing CODEOWNERS ignores comments."""
        content = """
# This is a comment
* @default-owner
# Another comment with @user
/policies/ @security-team
"""
        parser = CodeOwnersParser(content)

        assert len(parser.rules) == 2

    def test_parse_empty_lines(self):
        """Test parsing CODEOWNERS ignores empty lines."""
        content = """
* @default-owner


/policies/ @security-team

"""
        parser = CodeOwnersParser(content)

        assert len(parser.rules) == 2

    def test_parse_pattern_without_owners(self):
        """Test parsing pattern that unsets ownership."""
        content = """
* @default-owner
/ignored/
"""
        parser = CodeOwnersParser(content)

        assert len(parser.rules) == 2
        assert parser.rules[1].pattern == "/ignored/"
        assert parser.rules[1].owners == []


class TestCodeOwnersMatching:
    """Tests for file path matching."""

    def test_wildcard_pattern(self):
        """Test wildcard (*) pattern matches all files."""
        content = "* @default-owner"
        parser = CodeOwnersParser(content)

        assert parser.get_owners_for_file("any/file.json") == ["@default-owner"]
        assert parser.get_owners_for_file("deeply/nested/path/file.py") == ["@default-owner"]

    def test_directory_pattern(self):
        """Test directory pattern matches files in directory."""
        content = "/policies/ @security-team"
        parser = CodeOwnersParser(content)

        assert parser.get_owners_for_file("policies/admin.json") == ["@security-team"]
        assert parser.get_owners_for_file("policies/sub/nested.json") == ["@security-team"]
        assert parser.get_owners_for_file("other/admin.json") == []

    def test_extension_pattern(self):
        """Test extension pattern matches files with extension."""
        content = "*.json @security-team"
        parser = CodeOwnersParser(content)

        assert parser.get_owners_for_file("policy.json") == ["@security-team"]
        assert parser.get_owners_for_file("nested/policy.json") == ["@security-team"]
        assert parser.get_owners_for_file("policy.yaml") == []

    def test_specific_file_pattern(self):
        """Test specific file pattern."""
        content = "config/settings.json @admin"
        parser = CodeOwnersParser(content)

        assert parser.get_owners_for_file("config/settings.json") == ["@admin"]
        assert parser.get_owners_for_file("config/other.json") == []

    def test_last_matching_pattern_wins(self):
        """Test that last matching pattern wins."""
        content = """
* @default-owner
/policies/ @security-team
/policies/admin/ @admin-team
"""
        parser = CodeOwnersParser(content)

        # Most specific pattern should win
        assert parser.get_owners_for_file("policies/admin/admin.json") == ["@admin-team"]
        assert parser.get_owners_for_file("policies/user.json") == ["@security-team"]
        assert parser.get_owners_for_file("other/file.json") == ["@default-owner"]

    def test_glob_pattern_doublestar(self):
        """Test ** glob pattern."""
        content = "/docs/ @docs-team"
        parser = CodeOwnersParser(content)

        # Directory pattern matches all files under docs/
        assert parser.get_owners_for_file("docs/readme.md") == ["@docs-team"]
        assert parser.get_owners_for_file("docs/api/endpoints.md") == ["@docs-team"]

    def test_unset_ownership(self):
        """Test unsetting ownership with empty owner."""
        content = """
* @default-owner
/test/
"""
        parser = CodeOwnersParser(content)

        # /test/ has no owners (empty list)
        assert parser.get_owners_for_file("test/file.json") == []
        # Other files still have default owner
        assert parser.get_owners_for_file("src/file.json") == ["@default-owner"]


class TestCodeOwnersOwnerChecks:
    """Tests for owner checking methods."""

    def test_is_owner_direct_match(self):
        """Test direct user ownership check."""
        content = """
* @default-owner
/policies/ @security-team @admin-user
"""
        parser = CodeOwnersParser(content)

        assert parser.is_owner("admin-user", "policies/test.json")
        assert parser.is_owner("@admin-user", "policies/test.json")
        assert parser.is_owner("default-owner", "other/file.json")
        assert not parser.is_owner("unknown-user", "policies/test.json")

    def test_is_owner_case_insensitive(self):
        """Test owner matching is case insensitive."""
        content = "/policies/ @Admin-User"
        parser = CodeOwnersParser(content)

        assert parser.is_owner("admin-user", "policies/test.json")
        assert parser.is_owner("ADMIN-USER", "policies/test.json")
        assert parser.is_owner("Admin-User", "policies/test.json")

    def test_is_owner_ignores_teams(self):
        """Test is_owner only checks direct users, not teams."""
        content = "/policies/ @org/security-team"
        parser = CodeOwnersParser(content)

        # Team owner should not match as direct user
        assert not parser.is_owner("security-team", "policies/test.json")
        assert not parser.is_owner("org", "policies/test.json")

    def test_get_teams_for_file(self):
        """Test getting teams for a file."""
        content = """
* @default-user
/policies/ @org/security-team @other-org/platform
"""
        parser = CodeOwnersParser(content)

        teams = parser.get_teams_for_file("policies/test.json")
        assert ("org", "security-team") in teams
        assert ("other-org", "platform") in teams
        assert len(teams) == 2

        # Non-team owners shouldn't appear
        teams = parser.get_teams_for_file("other/file.json")
        assert teams == []


class TestNormalizePath:
    """Tests for path normalization."""

    def test_normalize_relative_path(self):
        """Test normalizing relative paths."""
        assert normalize_path("policies/admin.json") == "policies/admin.json"
        assert normalize_path("./policies/admin.json") == "policies/admin.json"

    def test_normalize_leading_slash(self):
        """Test normalizing paths with leading slash."""
        assert normalize_path("/policies/admin.json") == "policies/admin.json"

    def test_normalize_mixed(self):
        """Test normalizing mixed path format."""
        assert normalize_path("./policies/../policies/admin.json") == "policies/../policies/admin.json"


class TestCodeOwnerRule:
    """Tests for CodeOwnerRule dataclass."""

    def test_rule_creation(self):
        """Test creating a rule."""
        rule = CodeOwnerRule(pattern="*.json", owners=["@user"])

        assert rule.pattern == "*.json"
        assert rule.owners == ["@user"]
        assert rule.compiled_pattern is not None

    def test_rule_pattern_compilation(self):
        """Test that patterns are compiled on creation."""
        rule = CodeOwnerRule(pattern="*.json", owners=["@user"])

        # Pattern should be compiled as regex
        assert rule.compiled_pattern is not None
        assert rule.compiled_pattern.search("file.json") is not None
        assert rule.compiled_pattern.search("file.yaml") is None

"""Tests for the DiffParser module."""

import tempfile
from pathlib import Path

import pytest

from iam_validator.core.diff_parser import DiffParser


class TestDiffParser:
    """Test suite for DiffParser functionality."""

    def test_parse_simple_addition(self):
        """Test parsing a simple addition in unified diff."""
        pr_files = [
            {
                "filename": "policy.json",
                "status": "modified",
                "patch": """@@ -5,3 +5,4 @@
 context line
 another context
+added line
 more context""",
            }
        ]

        result = DiffParser.parse_pr_files(pr_files)

        assert "policy.json" in result
        diff = result["policy.json"]
        assert 7 in diff.added_lines
        assert 7 in diff.changed_lines
        assert len(diff.deleted_lines) == 0

    def test_parse_simple_deletion(self):
        """Test parsing a simple deletion in unified diff."""
        pr_files = [
            {
                "filename": "policy.json",
                "status": "modified",
                "patch": """@@ -5,4 +5,3 @@
 context line
-deleted line
 another context
 more context""",
            }
        ]

        result = DiffParser.parse_pr_files(pr_files)

        assert "policy.json" in result
        diff = result["policy.json"]
        assert 6 in diff.deleted_lines
        assert len(diff.added_lines) == 0
        assert len(diff.changed_lines) == 0

    def test_parse_modification(self):
        """Test parsing a line modification (deletion + addition)."""
        pr_files = [
            {
                "filename": "policy.json",
                "status": "modified",
                "patch": """@@ -5,3 +5,3 @@
 context line
-old line
+new line
 more context""",
            }
        ]

        result = DiffParser.parse_pr_files(pr_files)

        assert "policy.json" in result
        diff = result["policy.json"]
        assert 6 in diff.deleted_lines  # Old side
        assert 6 in diff.added_lines  # New side
        assert 6 in diff.changed_lines

    def test_parse_multiple_hunks(self):
        """Test parsing multiple hunks in a single file."""
        pr_files = [
            {
                "filename": "policy.json",
                "status": "modified",
                "patch": """@@ -5,3 +5,4 @@
 context
+added line 1
 context
 context
@@ -20,2 +21,3 @@
 context
+added line 2
 context""",
            }
        ]

        result = DiffParser.parse_pr_files(pr_files)

        assert "policy.json" in result
        diff = result["policy.json"]
        assert 6 in diff.added_lines  # First hunk
        assert 22 in diff.added_lines  # Second hunk
        assert len(diff.added_lines) == 2

    def test_parse_multiple_files(self):
        """Test parsing diffs for multiple files."""
        pr_files = [
            {
                "filename": "policy1.json",
                "status": "modified",
                "patch": "@@ -5,2 +5,3 @@\n context\n+added\n context",
            },
            {
                "filename": "policy2.json",
                "status": "modified",
                "patch": "@@ -10,3 +10,2 @@\n context\n-deleted\n context",
            },
        ]

        result = DiffParser.parse_pr_files(pr_files)

        assert len(result) == 2
        assert "policy1.json" in result
        assert "policy2.json" in result
        assert 6 in result["policy1.json"].added_lines
        assert 11 in result["policy2.json"].deleted_lines

    def test_parse_no_patch(self):
        """Test handling files without patch (binary, large files)."""
        pr_files = [
            {
                "filename": "image.png",
                "status": "added",
                # No patch field
            }
        ]

        result = DiffParser.parse_pr_files(pr_files)

        assert "image.png" in result
        diff = result["image.png"]
        assert len(diff.changed_lines) == 0
        assert len(diff.added_lines) == 0
        # Files without patch get "_no_patch" suffix to allow special handling
        assert diff.status == "added_no_patch"

    def test_parse_invalid_hunk_header(self):
        """Test graceful handling of malformed diff."""
        pr_files = [
            {
                "filename": "policy.json",
                "status": "modified",
                "patch": "Not a valid unified diff format",
            }
        ]

        # Should not raise exception, but return empty change sets
        result = DiffParser.parse_pr_files(pr_files)
        assert "policy.json" in result
        assert len(result["policy.json"].changed_lines) == 0

    def test_parse_complex_iam_policy_diff(self):
        """Test parsing a realistic IAM policy diff."""
        pr_files = [
            {
                "filename": "policies/s3-policy.json",
                "status": "modified",
                "patch": """@@ -3,7 +3,10 @@
   "Statement": [
     {
       "Effect": "Allow",
-      "Action": "s3:GetObject",
+      "Action": [
+        "s3:GetObject",
+        "s3:PutObject"
+      ],
       "Resource": "*"
     }
   ]""",
            }
        ]

        result = DiffParser.parse_pr_files(pr_files)

        assert "policies/s3-policy.json" in result
        diff = result["policies/s3-policy.json"]

        # Deletions: line 6 (old "Action": "s3:GetObject")
        assert 6 in diff.deleted_lines

        # Additions: lines 6-9 (new Action array)
        assert 6 in diff.added_lines
        assert 7 in diff.added_lines
        assert 8 in diff.added_lines
        assert 9 in diff.added_lines

        # Changed lines (new side)
        assert 6 in diff.changed_lines
        assert 7 in diff.changed_lines
        assert 8 in diff.changed_lines
        assert 9 in diff.changed_lines

    def test_get_modified_statements_single_statement(self):
        """Test identifying a single modified statement."""
        # Create a temporary policy file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(
                """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    }
  ]
}"""
            )
            policy_file = f.name

        try:
            line_mapping = {0: 4}  # Statement 0 starts at line 4
            changed_lines = {6}  # Line 6 (Action) was changed

            result = DiffParser.get_modified_statements(line_mapping, changed_lines, policy_file)

            assert 0 in result
            assert result[0].statement_index == 0
            assert result[0].has_changes
            assert result[0].start_line == 4
        finally:
            Path(policy_file).unlink()

    def test_get_modified_statements_multiple_statements(self):
        """Test identifying modified statements when multiple exist."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(
                """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Statement0",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::bucket/*"
    },
    {
      "Sid": "Statement1",
      "Effect": "Allow",
      "Action": "dynamodb:Query",
      "Resource": "*"
    }
  ]
}"""
            )
            policy_file = f.name

        try:
            line_mapping = {0: 4, 1: 10}  # Statement 0 at line 4, Statement 1 at line 10
            changed_lines = {7, 14}  # Lines in both statements

            result = DiffParser.get_modified_statements(line_mapping, changed_lines, policy_file)

            assert len(result) == 2
            assert 0 in result
            assert 1 in result
            assert result[0].has_changes
            assert result[1].has_changes
        finally:
            Path(policy_file).unlink()

    def test_get_modified_statements_only_first_modified(self):
        """Test that only the first statement is identified when it's the only one changed."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(
                """{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": "iam:*",
      "Resource": "*"
    }
  ]
}"""
            )
            policy_file = f.name

        try:
            line_mapping = {0: 3, 1: 8}
            changed_lines = {5}  # Only line 5 (in statement 0) changed

            result = DiffParser.get_modified_statements(line_mapping, changed_lines, policy_file)

            assert len(result) == 1
            assert 0 in result
            assert 1 not in result
        finally:
            Path(policy_file).unlink()

    def test_get_modified_statements_empty_inputs(self):
        """Test handling of empty inputs."""
        result = DiffParser.get_modified_statements({}, set(), "dummy.json")
        assert len(result) == 0

        result = DiffParser.get_modified_statements({0: 5}, set(), "dummy.json")
        assert len(result) == 0

    def test_parse_unified_diff_edge_cases(self):
        """Test edge cases in unified diff parsing."""
        # Empty patch
        result = DiffParser.parse_unified_diff("")
        assert len(result["changed_lines"]) == 0

        # Only context lines
        patch = "@@ -5,3 +5,3 @@\n context\n context\n context"
        result = DiffParser.parse_unified_diff(patch)
        assert len(result["changed_lines"]) == 0

        # Lines with no newline at end marker
        patch = "@@ -5,2 +5,2 @@\n context\n+added\n\\ No newline at end of file"
        result = DiffParser.parse_unified_diff(patch)
        assert 6 in result["added_lines"]

    def test_statement_end_line_detection(self):
        """Test accurate detection of statement end lines."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(
                """{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::bucket/*"
    },
    {
      "Effect": "Deny",
      "Action": "iam:*"
    }
  ]
}"""
            )
            policy_file = f.name

        try:
            # Statement 0 starts at line 3, should end at line 7 (before statement 1)
            end_line = DiffParser.get_statement_end_line(policy_file, 3)
            assert end_line == 7

            # Statement 1 starts at line 8, should end around line 11
            end_line = DiffParser.get_statement_end_line(policy_file, 8)
            assert end_line >= 10  # Should detect closing brace
        finally:
            Path(policy_file).unlink()

    def test_hunk_header_variations(self):
        """Test parsing various hunk header formats."""
        # Format: @@ -start +start @@  (no count, implies 1 line)
        patch1 = "@@ -5 +5 @@\n-old\n+new"
        result = DiffParser.parse_unified_diff(patch1)
        assert 5 in result["added_lines"]

        # Format: @@ -start,count +start @@ (no new count)
        patch2 = "@@ -5,2 +5 @@\n-deleted\n-deleted\n context"
        result = DiffParser.parse_unified_diff(patch2)
        assert 5 in result["deleted_lines"]
        assert 6 in result["deleted_lines"]

    def test_real_world_github_diff(self):
        """Test with a real-world GitHub diff format."""
        pr_files = [
            {
                "filename": "iam-policies/prod-s3-access.json",
                "status": "modified",
                "additions": 5,
                "deletions": 1,
                "changes": 6,
                "patch": """@@ -8,7 +8,11 @@
     {
       "Sid": "AllowS3Access",
       "Effect": "Allow",
-      "Action": "s3:GetObject",
+      "Action": [
+        "s3:GetObject",
+        "s3:ListBucket",
+        "s3:PutObject"
+      ],
       "Resource": [
         "arn:aws:s3:::my-bucket",
         "arn:aws:s3:::my-bucket/*"
""",
            }
        ]

        result = DiffParser.parse_pr_files(pr_files)

        assert "iam-policies/prod-s3-access.json" in result
        diff = result["iam-policies/prod-s3-access.json"]

        # Check that we correctly identified the changed lines
        assert 11 in diff.deleted_lines  # Old Action line
        assert 11 in diff.added_lines  # New Action array start
        assert 12 in diff.added_lines  # s3:GetObject
        assert 13 in diff.added_lines  # s3:ListBucket
        assert 14 in diff.added_lines  # s3:PutObject
        assert 15 in diff.added_lines  # Closing bracket

        # Verify metadata
        assert diff.status == "modified"
        assert diff.file_path == "iam-policies/prod-s3-access.json"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

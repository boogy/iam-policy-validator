"""Unit tests for Policy Loader module."""

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from iam_validator.core.models import IAMPolicy
from iam_validator.core.policy_loader import PolicyLoader


class TestPolicyLoader:
    """Test the PolicyLoader class."""

    @pytest.fixture
    def loader(self):
        """Create a PolicyLoader instance."""
        return PolicyLoader()

    @pytest.fixture
    def valid_policy_dict(self):
        """Return a valid IAM policy dictionary."""
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowS3Read",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket"],
                }
            ],
        }

    @pytest.fixture
    def valid_policy_json(self, valid_policy_dict):
        """Return a valid IAM policy as JSON string."""
        return json.dumps(valid_policy_dict, indent=2)

    @pytest.fixture
    def valid_policy_yaml(self, valid_policy_dict):
        """Return a valid IAM policy as YAML string."""
        return yaml.dump(valid_policy_dict)

    def test_initialization(self, loader):
        """Test that PolicyLoader initializes correctly."""
        assert loader.loaded_policies == []
        assert PolicyLoader.SUPPORTED_EXTENSIONS == {".json", ".yaml", ".yml"}

    def test_parse_policy_string_valid_json(self, loader, valid_policy_json):
        """Test parsing a valid JSON policy string."""
        policy = loader.parse_policy_string(valid_policy_json)

        assert policy is not None
        assert isinstance(policy, IAMPolicy)
        assert policy.version == "2012-10-17"
        assert len(policy.statement) == 1
        assert policy.statement[0].sid == "AllowS3Read"
        assert policy.statement[0].effect == "Allow"

    def test_parse_policy_string_invalid_json(self, loader):
        """Test parsing an invalid JSON string."""
        invalid_json = '{"Version": "2012-10-17", "Statement": ['
        policy = loader.parse_policy_string(invalid_json)

        assert policy is None

    def test_parse_policy_string_minimal_structure(self, loader):
        """Test parsing JSON with minimal policy structure."""
        minimal_policy = json.dumps({"Version": "2012-10-17"})  # Missing Statement (optional)
        policy = loader.parse_policy_string(minimal_policy)

        # Statement is optional in the model, so this parses successfully
        assert policy is not None
        assert policy.version == "2012-10-17"
        assert policy.statement is None

    def test_load_from_file_json(self, loader, valid_policy_dict):
        """Test loading a valid JSON policy file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(valid_policy_dict, f, indent=2)
            temp_path = f.name

        try:
            policy = loader.load_from_file(temp_path)

            assert policy is not None
            assert isinstance(policy, IAMPolicy)
            assert policy.version == "2012-10-17"
            assert len(policy.statement) == 1
        finally:
            Path(temp_path).unlink()

    def test_load_from_file_yaml(self, loader, valid_policy_dict):
        """Test loading a valid YAML policy file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(valid_policy_dict, f)
            temp_path = f.name

        try:
            policy = loader.load_from_file(temp_path)

            assert policy is not None
            assert isinstance(policy, IAMPolicy)
            assert policy.version == "2012-10-17"
            assert len(policy.statement) == 1
        finally:
            Path(temp_path).unlink()

    def test_load_from_file_yml_extension(self, loader, valid_policy_dict):
        """Test loading a .yml file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(valid_policy_dict, f)
            temp_path = f.name

        try:
            policy = loader.load_from_file(temp_path)

            assert policy is not None
            assert isinstance(policy, IAMPolicy)
        finally:
            Path(temp_path).unlink()

    def test_load_from_file_not_found(self, loader):
        """Test loading from a non-existent file."""
        policy = loader.load_from_file("/path/to/nonexistent/file.json")
        assert policy is None

    def test_load_from_file_unsupported_extension(self, loader, valid_policy_dict):
        """Test loading a file with unsupported extension."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            json.dump(valid_policy_dict, f)
            temp_path = f.name

        try:
            policy = loader.load_from_file(temp_path)
            assert policy is None
        finally:
            Path(temp_path).unlink()

    def test_load_from_file_invalid_json_content(self, loader):
        """Test loading a JSON file with invalid content."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json content")
            temp_path = f.name

        try:
            policy = loader.load_from_file(temp_path)
            assert policy is None
        finally:
            Path(temp_path).unlink()

    def test_load_from_file_invalid_yaml_content(self, loader):
        """Test loading a YAML file with invalid content."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: content: [unclosed")
            temp_path = f.name

        try:
            policy = loader.load_from_file(temp_path)
            assert policy is None
        finally:
            Path(temp_path).unlink()

    def test_load_from_directory_recursive(self, loader, valid_policy_dict):
        """Test loading policies from a directory recursively."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create multiple policy files in different subdirectories
            (temp_path / "subdir").mkdir()
            policy1_path = temp_path / "policy1.json"
            policy2_path = temp_path / "subdir" / "policy2.yaml"

            with open(policy1_path, "w") as f:
                json.dump(valid_policy_dict, f)

            with open(policy2_path, "w") as f:
                yaml.dump(valid_policy_dict, f)

            # Load recursively
            policies = loader.load_from_directory(str(temp_path), recursive=True)

            assert len(policies) == 2
            assert all(isinstance(p[1], IAMPolicy) for p in policies)

    def test_load_from_directory_non_recursive(self, loader, valid_policy_dict):
        """Test loading policies from a directory non-recursively."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create files in root and subdirectory
            (temp_path / "subdir").mkdir()
            policy1_path = temp_path / "policy1.json"
            policy2_path = temp_path / "subdir" / "policy2.json"

            with open(policy1_path, "w") as f:
                json.dump(valid_policy_dict, f)

            with open(policy2_path, "w") as f:
                json.dump(valid_policy_dict, f)

            # Load non-recursively (should only get policy1)
            policies = loader.load_from_directory(str(temp_path), recursive=False)

            assert len(policies) == 1
            assert str(policy1_path) in [p[0] for p in policies]

    def test_load_from_directory_not_found(self, loader):
        """Test loading from a non-existent directory."""
        policies = loader.load_from_directory("/path/to/nonexistent/directory")
        assert policies == []

    def test_load_from_directory_is_file(self, loader, valid_policy_dict):
        """Test load_from_directory when path is a file, not a directory."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(valid_policy_dict, f)
            temp_path = f.name

        try:
            policies = loader.load_from_directory(temp_path)
            assert policies == []
        finally:
            Path(temp_path).unlink()

    def test_load_from_path_file(self, loader, valid_policy_dict):
        """Test load_from_path with a file path."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(valid_policy_dict, f)
            temp_path = f.name

        try:
            policies = loader.load_from_path(temp_path)

            assert len(policies) == 1
            assert isinstance(policies[0][1], IAMPolicy)
        finally:
            Path(temp_path).unlink()

    def test_load_from_path_directory(self, loader, valid_policy_dict):
        """Test load_from_path with a directory path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            policy_path = temp_path / "policy.json"

            with open(policy_path, "w") as f:
                json.dump(valid_policy_dict, f)

            policies = loader.load_from_path(str(temp_path))

            assert len(policies) == 1
            assert isinstance(policies[0][1], IAMPolicy)

    def test_load_from_path_not_found(self, loader):
        """Test load_from_path with non-existent path."""
        policies = loader.load_from_path("/path/to/nonexistent")
        assert policies == []

    def test_find_statement_line_numbers_json(self, loader):
        """Test finding line numbers for statements in JSON policy."""
        policy_json = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FirstStatement",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    },
    {
      "Sid": "SecondStatement",
      "Effect": "Deny",
      "Action": "iam:*",
      "Resource": "*"
    }
  ]
}"""
        line_numbers = loader._find_statement_line_numbers(policy_json)

        assert len(line_numbers) == 2
        # Line numbers should point to the Sid lines (1-indexed)
        assert all(isinstance(num, int) and num > 0 for num in line_numbers)

    def test_policy_with_line_numbers(self, loader):
        """Test that loaded JSON policies have line numbers attached to statements."""
        policy_dict = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "FirstStatement",
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                },
                {
                    "Sid": "SecondStatement",
                    "Effect": "Allow",
                    "Action": "s3:PutObject",
                    "Resource": "*",
                },
            ],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(policy_dict, f, indent=2)
            temp_path = f.name

        try:
            policy = loader.load_from_file(temp_path)

            assert policy is not None
            assert len(policy.statement) == 2
            # Each statement should have a line number
            assert policy.statement[0].line_number is not None
            assert policy.statement[1].line_number is not None
            assert policy.statement[0].line_number > 0
            assert policy.statement[1].line_number > policy.statement[0].line_number
        finally:
            Path(temp_path).unlink()

    def test_statement_with_string_action(self, loader):
        """Test loading a policy with Action as a string (not list)."""
        policy_dict = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(policy_dict, f)
            temp_path = f.name

        try:
            policy = loader.load_from_file(temp_path)

            assert policy is not None
            assert policy.statement[0].action == "s3:GetObject"
        finally:
            Path(temp_path).unlink()

    def test_statement_with_string_resource(self, loader):
        """Test loading a policy with Resource as a string (not list)."""
        policy_dict = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(policy_dict, f)
            temp_path = f.name

        try:
            policy = loader.load_from_file(temp_path)

            assert policy is not None
            assert policy.statement[0].resource == "*"
        finally:
            Path(temp_path).unlink()

    def test_mixed_valid_and_invalid_files_in_directory(self, loader, valid_policy_dict):
        """Test that invalid files are skipped when loading from directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create valid policy
            valid_path = temp_path / "valid.json"
            with open(valid_path, "w") as f:
                json.dump(valid_policy_dict, f)

            # Create invalid policy
            invalid_path = temp_path / "invalid.json"
            with open(invalid_path, "w") as f:
                f.write("{invalid json")

            # Create unsupported file
            unsupported_path = temp_path / "readme.txt"
            with open(unsupported_path, "w") as f:
                f.write("This is not a policy")

            policies = loader.load_from_directory(str(temp_path))

            # Should only load the valid policy
            assert len(policies) == 1
            assert isinstance(policies[0][1], IAMPolicy)

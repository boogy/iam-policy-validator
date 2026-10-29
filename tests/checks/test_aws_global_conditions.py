"""Unit tests for AWS Global Conditions module."""

import pytest

from iam_validator.core.config.aws_global_conditions import (
    AWS_GLOBAL_CONDITION_KEYS,
    AWSGlobalConditions,
    get_global_conditions,
)


class TestAWSGlobalConditions:
    """Test the AWSGlobalConditions class."""

    @pytest.fixture
    def conditions(self):
        """Create a fresh AWSGlobalConditions instance."""
        return AWSGlobalConditions()

    def test_initialization(self, conditions):
        assert conditions.source == "bundled"
        assert len(conditions.get_all_keys()) > 0
        assert len(conditions.get_patterns()) == 3

    def test_valid_explicit_global_key(self, conditions):
        """Test validation of explicit global condition keys."""
        assert conditions.is_valid_global_key("aws:SourceIp") is True
        assert conditions.is_valid_global_key("aws:PrincipalArn") is True
        assert conditions.is_valid_global_key("aws:CurrentTime") is True
        assert conditions.is_valid_global_key("aws:SecureTransport") is True
        assert conditions.is_valid_global_key("aws:MultiFactorAuthPresent") is True

    def test_invalid_global_key(self, conditions):
        """Test validation of invalid condition keys."""
        assert conditions.is_valid_global_key("aws:InvalidKey") is False
        assert conditions.is_valid_global_key("custom:MyKey") is False
        assert conditions.is_valid_global_key("s3:BucketName") is False
        assert conditions.is_valid_global_key("") is False

    def test_request_tag_pattern(self, conditions):
        """aws:RequestTag/* is global (AWS lists it in global-condition-keys.json)."""
        assert conditions.is_valid_global_key("aws:RequestTag/Environment") is True
        assert conditions.is_valid_global_key("aws:RequestTag/Owner") is True
        assert conditions.is_valid_global_key("aws:RequestTag/CostCenter") is True
        assert conditions.is_valid_global_key("aws:RequestTag/Team-Name") is True
        assert conditions.is_valid_global_key("aws:RequestTag/app.example.com/role") is True

    def test_resource_tag_pattern(self, conditions):
        """aws:ResourceTag/* is global (AWS lists it in global-condition-keys.json)."""
        assert conditions.is_valid_global_key("aws:ResourceTag/Environment") is True
        assert conditions.is_valid_global_key("aws:ResourceTag/Owner") is True
        assert conditions.is_valid_global_key("aws:ResourceTag/Project") is True
        assert conditions.is_valid_global_key("aws:ResourceTag/app:component") is True

    def test_principal_tag_pattern(self, conditions):
        """Test validation of aws:PrincipalTag/* patterns."""
        assert conditions.is_valid_global_key("aws:PrincipalTag/Department") is True
        assert conditions.is_valid_global_key("aws:PrincipalTag/Role") is True
        assert conditions.is_valid_global_key("aws:PrincipalTag/Access-Level") is True

    def test_invalid_tag_patterns(self, conditions):
        """Test that invalid tag patterns are rejected."""
        # Missing tag name
        assert conditions.is_valid_global_key("aws:RequestTag/") is False
        assert conditions.is_valid_global_key("aws:ResourceTag/") is False
        assert conditions.is_valid_global_key("aws:PrincipalTag/") is False

        # Wrong prefix
        assert conditions.is_valid_global_key("s3:RequestTag/Environment") is False
        assert conditions.is_valid_global_key("ec2:ResourceTag/Name") is False

    def test_get_all_keys(self, conditions):
        """Test getting all explicit global condition keys with types."""
        keys = conditions.get_all_keys()
        assert isinstance(keys, dict)
        assert len(keys) > 0
        assert "aws:SourceIp" in keys
        assert "aws:PrincipalArn" in keys
        # Check that types are present
        assert keys["aws:SourceIp"] == "IPAddress"
        assert keys["aws:PrincipalArn"] == "ARN"
        keys["test:key"] = "String"
        assert "test:key" not in conditions.get_all_keys()

    def test_get_key_type(self, conditions):
        """Test getting the type for a global condition key."""
        # Exact matches
        assert conditions.get_key_type("aws:SourceIp") == "IPAddress"
        assert conditions.get_key_type("aws:PrincipalArn") == "ARN"
        assert conditions.get_key_type("aws:CurrentTime") == "Date"
        assert conditions.get_key_type("aws:SecureTransport") == "Bool"
        assert conditions.get_key_type("aws:MultiFactorAuthAge") == "Numeric"
        assert conditions.get_key_type("aws:username") == "String"

        assert conditions.get_key_type("aws:PrincipalTag/Department") == "String"
        assert conditions.get_key_type("aws:RequestTag/Environment") == "String"
        assert conditions.get_key_type("aws:ResourceTag/Name") == "String"
        assert conditions.get_key_types("aws:RequestTag/Environment") == ["String", "Numeric"]

        # Invalid keys
        assert conditions.get_key_type("invalid:key") is None
        assert conditions.get_key_type("s3:prefix") is None

    def test_get_patterns(self, conditions):
        """Test getting all condition key patterns."""
        patterns = conditions.get_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) == 3

        # Verify pattern structure
        for pattern_config in patterns:
            assert "pattern" in pattern_config
            assert "description" in pattern_config

        patterns.append({"pattern": "test", "description": "test"})
        assert len(conditions.get_patterns()) == 3

    def test_singleton_get_global_conditions(self):
        """Test the singleton factory function."""
        instance1 = get_global_conditions()
        instance2 = get_global_conditions()

        # Should return the same instance
        assert instance1 is instance2
        assert isinstance(instance1, AWSGlobalConditions)

    def test_all_predefined_keys_are_valid(self, conditions):
        """Test that all predefined keys in AWS_GLOBAL_CONDITION_KEYS are valid."""
        for key in AWS_GLOBAL_CONDITION_KEYS:
            assert conditions.is_valid_global_key(key) is True, f"{key} should be valid"

    def test_case_insensitivity(self, conditions):
        """AWS: condition key names are not case-sensitive."""
        assert conditions.is_valid_global_key("aws:SourceIp") is True
        assert conditions.is_valid_global_key("aws:sourceip") is True
        assert conditions.is_valid_global_key("AWS:SourceIp") is True
        assert conditions.is_valid_global_key("aws:SOURCEIP") is True
        assert conditions.get_key_type("aws:sourceip") == "IPAddress"
        assert conditions.get_key_type("AWS:PRINCIPALTAG/team") == "String"

        assert conditions.is_valid_global_key("aws:NotARealKey") is False

    def test_recently_documented_global_keys_are_recognized(self, conditions):
        expected = {
            "aws:CalledViaAWSMCP": "String",
            "aws:IsMcpServiceAction": "Bool",
            "aws:ViaAWSMCPService": "Bool",
            "aws:ViaCustomerDomain": "String",
            "aws:SignInSessionArn": "ARN",
            "aws:SourceVpcArn": "ARN",
        }
        for key, key_type in expected.items():
            assert conditions.is_valid_global_key(key) is True, key
            assert conditions.get_key_type(key) == key_type, key

    def test_multivalued_keys_typed_arrayofstring(self, conditions):
        """The seven keys AWS documents as Value type - Multivalued carry ArrayOfString."""
        multivalued = [
            "aws:TagKeys",
            "aws:PrincipalOrgPaths",
            "aws:PrincipalServiceNamesList",
            "aws:ResourceOrgPaths",
            "aws:SourceOrgPaths",
            "aws:VpceOrgPaths",
            "aws:CalledVia",
        ]
        for key in multivalued:
            assert conditions.get_key_type(key) == "ArrayOfString", key

        assert conditions.get_key_type("aws:CalledViaFirst") == "String"
        assert conditions.get_key_type("aws:CalledViaLast") == "String"

    def test_arrayofstring_table_agrees_with_is_multivalued_context_key(self):
        """The type table and the set-operator authority must not contradict."""
        from iam_validator.core.condition_validators import is_multivalued_context_key

        for key, key_type in AWS_GLOBAL_CONDITION_KEYS.items():
            assert is_multivalued_context_key(key) is (key_type == "ArrayOfString"), key

    def test_tag_with_special_characters(self, conditions):
        """Test tag patterns with allowed special characters."""
        assert conditions.is_valid_global_key("aws:PrincipalTag/my-tag") is True
        assert conditions.is_valid_global_key("aws:PrincipalTag/my_tag") is True
        assert conditions.is_valid_global_key("aws:PrincipalTag/my.tag") is True
        assert conditions.is_valid_global_key("aws:PrincipalTag/my:tag") is True
        assert conditions.is_valid_global_key("aws:PrincipalTag/my/tag") is True
        assert conditions.is_valid_global_key("aws:PrincipalTag/my@tag") is True
        assert conditions.is_valid_global_key("aws:PrincipalTag/my+tag") is True
        assert conditions.is_valid_global_key("aws:PrincipalTag/my=tag") is True
        assert conditions.is_valid_global_key("aws:RequestTag/my-tag") is True

    def test_known_service_specific_keys_are_invalid(self, conditions):
        """Test that service-specific condition keys are not treated as global."""
        # S3-specific keys
        assert conditions.is_valid_global_key("s3:x-amz-acl") is False
        assert conditions.is_valid_global_key("s3:prefix") is False

        # EC2-specific keys
        assert conditions.is_valid_global_key("ec2:InstanceType") is False
        assert conditions.is_valid_global_key("ec2:Region") is False

        # IAM-specific keys
        assert conditions.is_valid_global_key("iam:PassedToService") is False


class TestFromApi:
    PAYLOAD = [
        {
            "Name": "aws:EpochTime",
            "Description": "Request time",
            "DocPage": "/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-epochtime",
            "Types": ["Numeric", "Date"],
        },
        {"Name": "aws:SourceIp", "Types": ["IpAddress"]},
        {"Name": "aws:RequestTag/${TagKey}", "Types": ["String", "Numeric"]},
        {"Name": "aws:Unknown", "Types": [], "Extra": "ignored"},
        {"Types": ["String"]},
        "not-an-object",
    ]

    @pytest.fixture
    def conditions(self):
        result = AWSGlobalConditions.from_api(self.PAYLOAD)
        assert result is not None
        return result

    def test_source_is_aws_api(self, conditions):
        assert conditions.source == "aws-api"

    def test_multi_types_are_kept_in_order(self, conditions):
        assert conditions.get_key_types("aws:EpochTime") == ["Numeric", "Date"]
        assert conditions.get_key_type("aws:EpochTime") == "Numeric"

    def test_doc_page_becomes_absolute_url(self, conditions):
        info = conditions.get_key_info("aws:EpochTime")
        assert info is not None
        assert info.doc_url.startswith("https://docs.aws.amazon.com/IAM/latest/UserGuide/")
        assert info.description == "Request time"

    def test_templated_name_becomes_pattern(self, conditions):
        assert conditions.is_valid_global_key("aws:RequestTag/team/owner") is True
        assert conditions.is_valid_global_key("aws:RequestTag/") is False
        assert conditions.get_key_types("aws:requesttag/team") == ["String", "Numeric"]
        assert conditions.is_valid_global_key("aws:PrincipalTag/team") is False

    def test_entry_without_types_defaults_to_string(self, conditions):
        assert conditions.get_key_types("aws:Unknown") == ["String"]

    def test_malformed_entries_are_skipped(self, conditions):
        names = {info.name for info in conditions.list_keys()}
        assert "aws:EpochTime" in names
        assert all(isinstance(name, str) and name for name in names)

    def test_supplemental_keys_are_merged(self, conditions):
        assert conditions.is_valid_global_key("ec2:RoleDelivery") is True
        assert conditions.is_valid_global_key("aws:ViaCustomerDomain") is True

    @pytest.mark.parametrize("data", [None, {}, [], [{"Types": ["String"]}], "text"])
    def test_unusable_payload_returns_none(self, data):
        assert AWSGlobalConditions.from_api(data) is None

    def test_lookups_are_case_insensitive(self, conditions):
        assert conditions.get_key_types("AWS:EPOCHTIME") == ["Numeric", "Date"]

"""Unit tests for Pydantic models."""

import pytest
from pydantic import ValidationError

from iam_validator.core.models import (
    ActionDetail,
    ConditionKey,
    IAMPolicy,
    PolicyValidationResult,
    ResourceType,
    ServiceDetail,
    ServiceInfo,
    Statement,
    ValidationIssue,
    ValidationReport,
)


class TestServiceInfo:
    """Test the ServiceInfo model."""

    def test_valid_service_info(self):
        """Test creating a valid ServiceInfo."""
        service = ServiceInfo(service="s3", url="https://example.com/s3")
        assert service.service == "s3"
        assert service.url == "https://example.com/s3"

    def test_service_info_missing_fields(self):
        """Test that missing required fields raise validation error."""
        with pytest.raises(ValidationError):
            ServiceInfo(service="s3")  # Missing url
        with pytest.raises(ValidationError):
            ServiceInfo(url="https://example.com")  # Missing service


class TestActionDetail:
    """Test the ActionDetail model."""

    def test_action_detail_with_alias_and_defaults(self):
        """Test ActionDetail with aliases and default values."""
        # Using alias
        action = ActionDetail(
            Name="s3:GetObject",
            ActionConditionKeys=["s3:prefix", "aws:SourceIp"],
            Resources=[{"Name": "bucket"}],
        )
        assert action.name == "s3:GetObject"
        assert action.action_condition_keys == ["s3:prefix", "aws:SourceIp"]
        assert len(action.resources) == 1

        # Using field name
        action2 = ActionDetail(name="s3:PutObject")
        assert action2.name == "s3:PutObject"
        assert action2.action_condition_keys == []  # Default
        assert action2.resources == []  # Default


class TestResourceType:
    """Test the ResourceType model."""

    def test_resource_type(self):
        """Test ResourceType with values and defaults."""
        resource = ResourceType(
            Name="bucket",
            ARNFormats=["arn:aws:s3:::${BucketName}"],
            ConditionKeys=["s3:prefix"],
        )
        assert resource.name == "bucket"
        assert resource.arn_pattern == "arn:aws:s3:::${BucketName}"

        # Test defaults
        resource2 = ResourceType(Name="bucket")
        assert resource2.arn_pattern is None


class TestConditionKey:
    """Test the ConditionKey model."""

    def test_condition_key(self):
        """Test ConditionKey with values and defaults."""
        key = ConditionKey(
            Name="aws:SourceIp",
            Description="IP address of the requester",
            Types=["IpAddress"],
        )
        assert key.name == "aws:SourceIp"
        assert key.description == "IP address of the requester"

        # Test defaults
        key2 = ConditionKey(Name="aws:SourceIp")
        assert key2.description is None
        assert key2.types == []


class TestServiceDetail:
    """Test the ServiceDetail model."""

    def test_service_detail_conversion(self):
        """Test ServiceDetail list-to-dict conversion and defaults."""
        service = ServiceDetail(
            Name="Amazon S3",
            Actions=[
                ActionDetail(Name="s3:GetObject"),
                ActionDetail(Name="s3:PutObject"),
            ],
            Resources=[ResourceType(Name="bucket")],
            ConditionKeys=[ConditionKey(Name="s3:prefix")],
            Version="2023-01-01",
        )
        # Lists should be converted to dicts
        assert isinstance(service.actions, dict)
        assert "s3:GetObject" in service.actions
        assert "bucket" in service.resources

        # Test defaults
        service2 = ServiceDetail(Name="S3")
        assert service2.actions == {}


class TestStatement:
    """Test the Statement model."""

    def test_statement_basic(self):
        """Test basic statement creation."""
        stmt = Statement(
            Sid="AllowS3Read",
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource="*",
            Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
        )
        assert stmt.sid == "AllowS3Read"
        assert stmt.effect == "Allow"
        assert stmt.condition is not None

    @pytest.mark.parametrize(
        "action,resource,expected_actions,expected_resources",
        [
            (["s3:GetObject", "s3:PutObject"], "*", ["s3:GetObject", "s3:PutObject"], ["*"]),
            ("s3:GetObject", ["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2/*"], ["s3:GetObject"], ["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2/*"]),
            (None, "*", [], ["*"]),  # NotAction case
        ],
    )
    def test_statement_get_methods(self, action, resource, expected_actions, expected_resources):
        """Test get_actions() and get_resources() methods."""
        stmt = Statement(Effect="Allow", Action=action, Resource=resource, NotAction=["s3:*"] if action is None else None)
        assert stmt.get_actions() == expected_actions
        assert stmt.get_resources() == expected_resources

    def test_statement_line_number(self):
        """Test line_number excluded from serialization."""
        stmt = Statement(Effect="Allow", Action=["s3:GetObject"], Resource="*")
        stmt.line_number = 42
        assert stmt.line_number == 42
        assert "line_number" not in stmt.model_dump()


class TestIAMPolicy:
    """Test the IAMPolicy model."""

    def test_policy_creation(self):
        """Test policy creation with various configurations."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Id="MyPolicyId",
            Statement=[
                Statement(Effect="Allow", Action=["s3:GetObject"], Resource="*"),
                Statement(Effect="Deny", Action=["iam:*"], Resource="*"),
            ],
        )
        assert policy.version == "2012-10-17"
        assert policy.id == "MyPolicyId"
        assert len(policy.statement) == 2

    def test_policy_optional_fields(self):
        """Test that Version and Statement are optional."""
        policy1 = IAMPolicy(Statement=[])
        assert policy1.version is None

        policy2 = IAMPolicy(Version="2012-10-17")
        assert policy2.statement is None


class TestValidationIssue:
    """Test the ValidationIssue model."""

    def test_validation_issue(self):
        """Test ValidationIssue with all fields."""
        issue = ValidationIssue(
            severity="warning",
            statement_sid="MyStatement",
            statement_index=1,
            issue_type="missing_condition",
            message="Condition key missing",
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/*",
            suggestion="Add condition",
            line_number=42,
        )
        assert issue.severity == "warning"
        assert issue.statement_sid == "MyStatement"
        assert issue.suggestion == "Add condition"

    @pytest.mark.parametrize(
        "severity,expected_icon,expected_label",
        [
            ("error", "❌", "ERROR"),
            ("warning", "⚠️", "WARNING"),
            ("info", "ℹ️", "INFO"),
        ],
    )
    def test_to_pr_comment(self, severity, expected_icon, expected_label):
        """Test to_pr_comment formatting."""
        issue = ValidationIssue(
            severity=severity,
            statement_index=0,
            issue_type="test",
            message="Test message",
        )
        comment = issue.to_pr_comment()
        assert expected_icon in comment
        assert expected_label in comment


class TestPolicyValidationResult:
    """Test the PolicyValidationResult model."""

    def test_validation_result(self):
        """Test creating validation result with and without issues."""
        result_valid = PolicyValidationResult(
            policy_file="policy.json",
            is_valid=True,
            actions_checked=10,
        )
        assert result_valid.is_valid
        assert result_valid.issues == []

        result_invalid = PolicyValidationResult(
            policy_file="policy.json",
            is_valid=False,
            issues=[ValidationIssue(severity="error", statement_index=0, issue_type="test", message="Test")],
        )
        assert not result_invalid.is_valid
        assert len(result_invalid.issues) == 1


class TestValidationReport:
    """Test the ValidationReport model."""

    def test_validation_report(self):
        """Test report creation and summary."""
        report = ValidationReport(
            total_policies=25,
            valid_policies=20,
            invalid_policies=5,
            total_issues=42,
        )
        assert report.total_policies == 25

        summary = report.get_summary()
        assert "25 policies" in summary
        assert "20 valid" in summary

    def test_report_with_results(self):
        """Test report with validation results."""
        results = [
            PolicyValidationResult(policy_file="policy1.json", is_valid=True, issues=[]),
            PolicyValidationResult(policy_file="policy2.json", is_valid=False, issues=[
                ValidationIssue(severity="error", statement_index=0, issue_type="test", message="Test")
            ]),
        ]
        report = ValidationReport(
            total_policies=2, valid_policies=1, invalid_policies=1, total_issues=1, results=results
        )
        assert len(report.results) == 2

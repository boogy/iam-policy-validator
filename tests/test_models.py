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

    def test_valid_action_detail(self):
        """Test creating a valid ActionDetail with alias."""
        action = ActionDetail(
            Name="s3:GetObject",
            ActionConditionKeys=["s3:prefix", "aws:SourceIp"],
            Resources=[{"Name": "bucket"}],
        )

        assert action.name == "s3:GetObject"
        assert action.action_condition_keys == ["s3:prefix", "aws:SourceIp"]
        assert len(action.resources) == 1

    def test_action_detail_populate_by_name(self):
        """Test that both alias and field name work."""
        # Using field name
        action1 = ActionDetail(name="s3:GetObject")
        assert action1.name == "s3:GetObject"

        # Using alias
        action2 = ActionDetail(Name="s3:GetObject")
        assert action2.name == "s3:GetObject"

    def test_action_detail_defaults(self):
        """Test default values for optional fields."""
        action = ActionDetail(Name="s3:GetObject")

        assert action.action_condition_keys == []
        assert action.resources == []
        assert action.annotations is None
        assert action.supported_by is None


class TestResourceType:
    """Test the ResourceType model."""

    def test_valid_resource_type(self):
        """Test creating a valid ResourceType."""
        resource = ResourceType(
            Name="bucket",
            ARNPattern="arn:aws:s3:::${BucketName}",
            ConditionKeys=["s3:prefix"],
        )

        assert resource.name == "bucket"
        assert resource.arn_pattern == "arn:aws:s3:::${BucketName}"
        assert resource.condition_keys == ["s3:prefix"]

    def test_resource_type_defaults(self):
        """Test default values."""
        resource = ResourceType(Name="bucket")

        assert resource.arn_pattern is None
        assert resource.condition_keys == []


class TestConditionKey:
    """Test the ConditionKey model."""

    def test_valid_condition_key(self):
        """Test creating a valid ConditionKey."""
        key = ConditionKey(
            Name="aws:SourceIp",
            Description="IP address of the requester",
            Types=["IpAddress"],
        )

        assert key.name == "aws:SourceIp"
        assert key.description == "IP address of the requester"
        assert key.types == ["IpAddress"]

    def test_condition_key_defaults(self):
        """Test default values."""
        key = ConditionKey(Name="aws:SourceIp")

        assert key.description is None
        assert key.types == []


class TestServiceDetail:
    """Test the ServiceDetail model."""

    def test_valid_service_detail(self):
        """Test creating a valid ServiceDetail."""
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

        assert service.name == "Amazon S3"
        assert service.version == "2023-01-01"
        # Lists should be converted to dicts in post_init
        assert len(service.actions) == 2
        assert "s3:GetObject" in service.actions
        assert "s3:PutObject" in service.actions
        assert "bucket" in service.resources
        assert "s3:prefix" in service.condition_keys

    def test_service_detail_post_init_conversion(self):
        """Test that model_post_init converts lists to dicts."""
        service = ServiceDetail(
            Name="S3",
            Actions=[
                ActionDetail(Name="s3:GetObject"),
                ActionDetail(Name="s3:PutObject"),
            ],
            Resources=[ResourceType(Name="bucket")],
            ConditionKeys=[ConditionKey(Name="s3:prefix")],
        )

        # Verify dict conversion
        assert isinstance(service.actions, dict)
        assert isinstance(service.resources, dict)
        assert isinstance(service.condition_keys, dict)

        # Verify lookups work
        assert service.actions["s3:GetObject"].name == "s3:GetObject"
        assert service.resources["bucket"].name == "bucket"
        assert service.condition_keys["s3:prefix"].name == "s3:prefix"

    def test_service_detail_defaults(self):
        """Test default values."""
        service = ServiceDetail(Name="S3")

        assert service.prefix is None
        assert service.version is None
        assert service.actions == {}
        assert service.resources == {}
        assert service.condition_keys == {}


class TestStatement:
    """Test the Statement model."""

    def test_valid_statement_basic(self):
        """Test creating a basic valid statement."""
        stmt = Statement(Effect="Allow", Action=["s3:GetObject"], Resource="*")

        assert stmt.effect == "Allow"
        assert stmt.action == ["s3:GetObject"]
        assert stmt.resource == "*"
        assert stmt.sid is None

    def test_statement_with_sid(self):
        """Test statement with SID."""
        stmt = Statement(Sid="AllowS3Read", Effect="Allow", Action=["s3:GetObject"], Resource="*")

        assert stmt.sid == "AllowS3Read"

    def test_statement_with_condition(self):
        """Test statement with condition."""
        stmt = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource="*",
            Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
        )

        assert stmt.condition is not None
        assert "IpAddress" in stmt.condition

    def test_statement_get_actions_list(self):
        """Test get_actions() with action as list."""
        stmt = Statement(Effect="Allow", Action=["s3:GetObject", "s3:PutObject"], Resource="*")

        actions = stmt.get_actions()
        assert actions == ["s3:GetObject", "s3:PutObject"]

    def test_statement_get_actions_string(self):
        """Test get_actions() with action as string."""
        stmt = Statement(Effect="Allow", Action="s3:GetObject", Resource="*")

        actions = stmt.get_actions()
        assert actions == ["s3:GetObject"]

    def test_statement_get_actions_none(self):
        """Test get_actions() when action is None."""
        stmt = Statement(Effect="Allow", NotAction=["s3:*"], Resource="*")

        actions = stmt.get_actions()
        assert actions == []

    def test_statement_get_resources_list(self):
        """Test get_resources() with resource as list."""
        stmt = Statement(
            Effect="Allow",
            Action=["s3:GetObject"],
            Resource=["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2/*"],
        )

        resources = stmt.get_resources()
        assert resources == ["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2/*"]

    def test_statement_get_resources_string(self):
        """Test get_resources() with resource as string."""
        stmt = Statement(Effect="Allow", Action=["s3:GetObject"], Resource="*")

        resources = stmt.get_resources()
        assert resources == ["*"]

    def test_statement_get_resources_none(self):
        """Test get_resources() when resource is None."""
        stmt = Statement(Effect="Allow", Action=["s3:GetObject"], NotResource=["*"])

        resources = stmt.get_resources()
        assert resources == []

    def test_statement_with_principal(self):
        """Test statement with Principal."""
        stmt = Statement(
            Effect="Allow",
            Principal={"AWS": "arn:aws:iam::123456789012:user/test"},
            Action=["s3:GetObject"],
            Resource="*",
        )

        assert stmt.principal is not None
        assert "AWS" in stmt.principal

    def test_statement_line_number(self):
        """Test that line_number can be set and is excluded from serialization."""
        stmt = Statement(Effect="Allow", Action=["s3:GetObject"], Resource="*")
        stmt.line_number = 42

        assert stmt.line_number == 42

        # line_number should be excluded from dict representation
        stmt_dict = stmt.model_dump()
        assert "line_number" not in stmt_dict


class TestIAMPolicy:
    """Test the IAMPolicy model."""

    def test_valid_policy(self):
        """Test creating a valid IAM policy."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Allow", Action=["s3:GetObject"], Resource="*")],
        )

        assert policy.version == "2012-10-17"
        assert len(policy.statement) == 1
        assert policy.id is None

    def test_policy_with_id(self):
        """Test policy with Id field."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Id="MyPolicyId",
            Statement=[Statement(Effect="Allow", Action=["s3:GetObject"], Resource="*")],
        )

        assert policy.id == "MyPolicyId"

    def test_policy_multiple_statements(self):
        """Test policy with multiple statements."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(Effect="Allow", Action=["s3:GetObject"], Resource="*"),
                Statement(Effect="Deny", Action=["iam:*"], Resource="*"),
            ],
        )

        assert len(policy.statement) == 2
        assert policy.statement[0].effect == "Allow"
        assert policy.statement[1].effect == "Deny"

    def test_policy_missing_required_fields(self):
        """Test that missing required fields raise validation error."""
        with pytest.raises(ValidationError):
            IAMPolicy(Statement=[])  # Missing Version

        with pytest.raises(ValidationError):
            IAMPolicy(Version="2012-10-17")  # Missing Statement


class TestValidationIssue:
    """Test the ValidationIssue model."""

    def test_valid_issue(self):
        """Test creating a valid ValidationIssue."""
        issue = ValidationIssue(
            severity="error",
            statement_index=0,
            issue_type="invalid_action",
            message="Invalid action detected",
        )

        assert issue.severity == "error"
        assert issue.statement_index == 0
        assert issue.issue_type == "invalid_action"
        assert issue.message == "Invalid action detected"

    def test_issue_with_all_fields(self):
        """Test issue with all optional fields."""
        issue = ValidationIssue(
            severity="warning",
            statement_sid="MyStatement",
            statement_index=1,
            issue_type="missing_condition",
            message="Condition key missing",
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/*",
            condition_key="aws:SourceIp",
            suggestion="Add aws:SourceIp condition",
            line_number=42,
        )

        assert issue.statement_sid == "MyStatement"
        assert issue.action == "s3:GetObject"
        assert issue.resource == "arn:aws:s3:::bucket/*"
        assert issue.condition_key == "aws:SourceIp"
        assert issue.suggestion == "Add aws:SourceIp condition"
        assert issue.line_number == 42

    def test_to_pr_comment_error(self):
        """Test formatting as PR comment for error."""
        issue = ValidationIssue(
            severity="error",
            statement_index=0,
            issue_type="invalid_action",
            message="Action does not exist",
            action="s3:InvalidAction",
        )

        comment = issue.to_pr_comment()
        assert "❌" in comment
        assert "ERROR" in comment
        assert "Action does not exist" in comment
        assert "s3:InvalidAction" in comment

    def test_to_pr_comment_warning(self):
        """Test formatting as PR comment for warning."""
        issue = ValidationIssue(
            severity="warning",
            statement_index=0,
            issue_type="missing_condition",
            message="Missing recommended condition",
            condition_key="aws:SecureTransport",
            suggestion="Add SecureTransport condition",
        )

        comment = issue.to_pr_comment()
        assert "⚠️" in comment
        assert "WARNING" in comment
        assert "Missing recommended condition" in comment
        assert "aws:SecureTransport" in comment
        assert "Add SecureTransport condition" in comment

    def test_to_pr_comment_info(self):
        """Test formatting as PR comment for info."""
        issue = ValidationIssue(
            severity="info",
            statement_index=0,
            issue_type="best_practice",
            message="Consider using more specific resources",
            resource="*",
        )

        comment = issue.to_pr_comment()
        assert "ℹ️" in comment
        assert "INFO" in comment


class TestPolicyValidationResult:
    """Test the PolicyValidationResult model."""

    def test_valid_result_no_issues(self):
        """Test creating a validation result with no issues."""
        result = PolicyValidationResult(
            policy_file="policy.json",
            is_valid=True,
            actions_checked=10,
            condition_keys_checked=5,
            resources_checked=3,
        )

        assert result.policy_file == "policy.json"
        assert result.is_valid is True
        assert result.issues == []
        assert result.actions_checked == 10

    def test_valid_result_with_issues(self):
        """Test creating a validation result with issues."""
        issues = [
            ValidationIssue(
                severity="error",
                statement_index=0,
                issue_type="invalid_action",
                message="Invalid action",
            ),
            ValidationIssue(
                severity="warning",
                statement_index=1,
                issue_type="missing_condition",
                message="Missing condition",
            ),
        ]

        result = PolicyValidationResult(
            policy_file="policy.json",
            is_valid=False,
            issues=issues,
            actions_checked=10,
        )

        assert result.is_valid is False
        assert len(result.issues) == 2


class TestValidationReport:
    """Test the ValidationReport model."""

    def test_valid_report(self):
        """Test creating a valid validation report."""
        report = ValidationReport(
            total_policies=10,
            valid_policies=8,
            invalid_policies=2,
            total_issues=15,
        )

        assert report.total_policies == 10
        assert report.valid_policies == 8
        assert report.invalid_policies == 2
        assert report.total_issues == 15

    def test_report_with_results(self):
        """Test report with validation results."""
        results = [
            PolicyValidationResult(policy_file="policy1.json", is_valid=True, issues=[]),
            PolicyValidationResult(
                policy_file="policy2.json",
                is_valid=False,
                issues=[
                    ValidationIssue(
                        severity="error",
                        statement_index=0,
                        issue_type="invalid_action",
                        message="Invalid",
                    )
                ],
            ),
        ]

        report = ValidationReport(
            total_policies=2,
            valid_policies=1,
            invalid_policies=1,
            total_issues=1,
            results=results,
        )

        assert len(report.results) == 2

    def test_get_summary(self):
        """Test get_summary method."""
        report = ValidationReport(
            total_policies=25,
            valid_policies=20,
            invalid_policies=5,
            total_issues=42,
        )

        summary = report.get_summary()
        assert "25 policies" in summary
        assert "20 valid" in summary
        assert "5 invalid" in summary
        assert "42 total issues" in summary

    def test_get_summary_no_issues(self):
        """Test get_summary with no issues."""
        report = ValidationReport(
            total_policies=10, valid_policies=10, invalid_policies=0, total_issues=0
        )

        summary = report.get_summary()
        assert "10 policies" in summary
        assert "10 valid" in summary
        assert "0 invalid" in summary
        assert "0 total issues" in summary

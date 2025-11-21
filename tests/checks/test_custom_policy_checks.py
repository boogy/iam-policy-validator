"""Tests for custom policy checks using AWS IAM Access Analyzer."""

from unittest.mock import MagicMock, patch

import pytest

from iam_validator.core.access_analyzer import (
    AccessAnalyzerValidator,
    CheckResultType,
    CustomCheckResult,
    PolicyType,
    ReasonSummary,
    ResourceType,
)


@pytest.fixture
def validator():
    """Create an AccessAnalyzerValidator instance with mocked client."""
    with patch("boto3.Session") as mock_session:
        mock_client = MagicMock()
        mock_session.return_value.client.return_value = mock_client

        validator = AccessAnalyzerValidator(
            region="us-east-1", policy_type=PolicyType.IDENTITY_POLICY
        )
        validator.client = mock_client
        yield validator


@pytest.fixture
def sample_policy():
    """Sample IAM policy for testing."""
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


class TestCheckAccessNotGranted:
    """Tests for check_access_not_granted method."""

    def test_check_access_not_granted_pass(self, validator, sample_policy):
        """Test when policy does not grant specified access."""
        validator.client.check_access_not_granted.return_value = {
            "result": "PASS",
            "message": "The policy does not grant the specified access",
            "reasons": [],
        }

        result = validator.check_access_not_granted(sample_policy, actions=["s3:DeleteBucket"])

        assert isinstance(result, CustomCheckResult)
        assert result.check_type == "AccessNotGranted"
        assert result.result == CheckResultType.PASS
        assert result.passed is True
        assert len(result.reasons) == 0

        # Verify API was called correctly
        validator.client.check_access_not_granted.assert_called_once()
        call_args = validator.client.check_access_not_granted.call_args
        assert call_args.kwargs["policyType"] == "IDENTITY_POLICY"
        assert call_args.kwargs["access"][0]["actions"] == ["s3:DeleteBucket"]

    def test_check_access_not_granted_fail(self, validator, sample_policy):
        """Test when policy grants access that should not be granted."""
        validator.client.check_access_not_granted.return_value = {
            "result": "FAIL",
            "message": "The policy grants access that should not be granted",
            "reasons": [
                {
                    "description": "Statement allows the specified actions",
                    "statementId": "AllowS3Read",
                    "statementIndex": 0,
                }
            ],
        }

        result = validator.check_access_not_granted(sample_policy, actions=["s3:GetObject"])

        assert result.result == CheckResultType.FAIL
        assert result.passed is False
        assert len(result.reasons) == 1
        assert result.reasons[0].description == "Statement allows the specified actions"
        assert result.reasons[0].statement_id == "AllowS3Read"
        assert result.reasons[0].statement_index == 0

    def test_check_access_not_granted_with_resources(self, validator, sample_policy):
        """Test check with specific resources."""
        validator.client.check_access_not_granted.return_value = {
            "result": "PASS",
            "message": "Access not granted",
            "reasons": [],
        }

        result = validator.check_access_not_granted(
            sample_policy,
            actions=["s3:DeleteObject"],
            resources=["arn:aws:s3:::production-bucket/*"],
        )

        assert result.passed is True

        # Verify resources were passed to API
        call_args = validator.client.check_access_not_granted.call_args
        assert call_args.kwargs["access"][0]["resources"] == ["arn:aws:s3:::production-bucket/*"]


class TestCheckNoNewAccess:
    """Tests for check_no_new_access method."""

    def test_check_no_new_access_pass(self, validator, sample_policy):
        """Test when new policy doesn't grant new access."""
        validator.client.check_no_new_access.return_value = {
            "result": "PASS",
            "message": "The updated policy does not grant new access",
            "reasons": [],
        }

        existing_policy = sample_policy.copy()
        new_policy = sample_policy.copy()

        result = validator.check_no_new_access(new_policy, existing_policy)

        assert isinstance(result, CustomCheckResult)
        assert result.check_type == "NoNewAccess"
        assert result.result == CheckResultType.PASS
        assert result.passed is True

    def test_check_no_new_access_fail(self, validator, sample_policy):
        """Test when new policy grants additional access."""
        validator.client.check_no_new_access.return_value = {
            "result": "FAIL",
            "message": "The updated policy grants new access",
            "reasons": [
                {
                    "description": "New statement grants additional permissions",
                    "statementId": "NewS3Write",
                    "statementIndex": 1,
                }
            ],
        }

        existing_policy = sample_policy.copy()
        new_policy = {
            "Version": "2012-10-17",
            "Statement": [
                sample_policy["Statement"][0],
                {
                    "Sid": "NewS3Write",
                    "Effect": "Allow",
                    "Action": "s3:PutObject",
                    "Resource": "*",
                },
            ],
        }

        result = validator.check_no_new_access(new_policy, existing_policy)

        assert result.result == CheckResultType.FAIL
        assert result.passed is False
        assert len(result.reasons) == 1
        assert result.reasons[0].statement_id == "NewS3Write"


class TestCheckNoPublicAccess:
    """Tests for check_no_public_access method."""

    def test_check_no_public_access_pass(self, validator):
        """Test when resource policy doesn't allow public access."""
        # Change to resource policy type
        validator.policy_type = PolicyType.RESOURCE_POLICY

        validator.client.check_no_public_access.return_value = {
            "result": "PASS",
            "message": "The policy does not allow public access",
            "reasons": [],
        }

        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }

        result = validator.check_no_public_access(bucket_policy, ResourceType.AWS_S3_BUCKET)

        assert result.result == CheckResultType.PASS
        assert result.passed is True

    def test_check_no_public_access_fail(self, validator):
        """Test when resource policy allows public access."""
        validator.policy_type = PolicyType.RESOURCE_POLICY

        validator.client.check_no_public_access.return_value = {
            "result": "FAIL",
            "message": "The policy allows public access",
            "reasons": [
                {
                    "description": "Statement allows access from the internet",
                    "statementId": "PublicRead",
                    "statementIndex": 0,
                }
            ],
        }

        public_bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicRead",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }

        result = validator.check_no_public_access(public_bucket_policy, ResourceType.AWS_S3_BUCKET)

        assert result.result == CheckResultType.FAIL
        assert result.passed is False
        assert result.reasons[0].statement_id == "PublicRead"

    def test_check_no_public_access_different_resource_types(self, validator):
        """Test with different resource types."""
        validator.policy_type = PolicyType.RESOURCE_POLICY

        validator.client.check_no_public_access.return_value = {
            "result": "PASS",
            "message": "No public access",
            "reasons": [],
        }

        policy = {"Version": "2012-10-17", "Statement": []}

        # Test with S3 Access Point
        result = validator.check_no_public_access(policy, ResourceType.AWS_S3_ACCESS_POINT)
        assert result.passed is True

        # Verify correct resource type was passed
        call_args = validator.client.check_no_public_access.call_args
        assert call_args.kwargs["resourceType"] == "AWS::S3::AccessPoint"


class TestCustomCheckResult:
    """Tests for CustomCheckResult dataclass."""

    def test_custom_check_result_passed_property(self):
        """Test the passed property."""
        pass_result = CustomCheckResult(
            check_type="AccessNotGranted",
            result=CheckResultType.PASS,
            message="OK",
            reasons=[],
        )
        assert pass_result.passed is True

        fail_result = CustomCheckResult(
            check_type="AccessNotGranted",
            result=CheckResultType.FAIL,
            message="Failed",
            reasons=[],
        )
        assert fail_result.passed is False

    def test_reason_summary(self):
        """Test ReasonSummary dataclass."""
        reason = ReasonSummary(
            description="Test description",
            statement_id="TestSid",
            statement_index=5,
        )

        assert reason.description == "Test description"
        assert reason.statement_id == "TestSid"
        assert reason.statement_index == 5

    def test_reason_summary_optional_fields(self):
        """Test ReasonSummary with optional fields."""
        reason = ReasonSummary(description="Test description")

        assert reason.description == "Test description"
        assert reason.statement_id is None
        assert reason.statement_index is None


class TestValidatePoliciesWithCustomChecks:
    """Tests for validate_policies with custom checks."""

    def test_validate_policies_with_access_not_granted(self, validator, sample_policy):
        """Test validate_policies with access not granted check."""
        validator.client.validate_policy.return_value = {"findings": []}
        validator.client.check_access_not_granted.return_value = {
            "result": "PASS",
            "message": "OK",
            "reasons": [],
        }

        custom_checks = {
            "access_not_granted": {
                "actions": ["s3:DeleteBucket"],
                "resources": None,
            }
        }

        results = validator.validate_policies(
            [("test-policy.json", sample_policy)], custom_checks=custom_checks
        )

        assert len(results) == 1
        result = results[0]
        assert result.policy_file == "test-policy.json"
        assert result.custom_checks is not None
        assert len(result.custom_checks) == 1
        assert result.custom_checks[0].check_type == "AccessNotGranted"
        assert result.custom_checks[0].passed is True

    def test_validate_policies_with_no_public_access(self, validator, sample_policy):
        """Test validate_policies with no public access check."""
        validator.client.validate_policy.return_value = {"findings": []}
        validator.client.check_no_public_access.return_value = {
            "result": "FAIL",
            "message": "Public access detected",
            "reasons": [{"description": "Public access", "statementIndex": 0}],
        }

        custom_checks = {"no_public_access": {"resource_types": [ResourceType.AWS_S3_BUCKET]}}

        results = validator.validate_policies(
            [("bucket-policy.json", sample_policy)], custom_checks=custom_checks
        )

        assert len(results) == 1
        result = results[0]
        assert result.custom_checks is not None
        assert result.custom_checks[0].check_type == "NoPublicAccess (AWS::S3::Bucket)"
        assert result.custom_checks[0].passed is False

    def test_validate_policies_without_custom_checks(self, validator, sample_policy):
        """Test validate_policies without custom checks."""
        validator.client.validate_policy.return_value = {"findings": []}

        results = validator.validate_policies([("test-policy.json", sample_policy)])

        assert len(results) == 1
        assert results[0].custom_checks is None

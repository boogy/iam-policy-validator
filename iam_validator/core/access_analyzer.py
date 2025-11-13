"""AWS IAM Access Analyzer integration for policy validation.

This module provides integration with AWS IAM Access Analyzer ValidatePolicy API
to validate IAM policies for syntax errors, security warnings, and best practices.
"""

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from iam_validator.core.policy_loader import PolicyLoader


class PolicyType(str, Enum):
    """IAM Access Analyzer policy types."""

    IDENTITY_POLICY = "IDENTITY_POLICY"
    RESOURCE_POLICY = "RESOURCE_POLICY"
    SERVICE_CONTROL_POLICY = "SERVICE_CONTROL_POLICY"


class FindingType(str, Enum):
    """Access Analyzer finding types."""

    ERROR = "ERROR"
    SECURITY_WARNING = "SECURITY_WARNING"
    SUGGESTION = "SUGGESTION"
    WARNING = "WARNING"


class CheckResultType(str, Enum):
    """Custom policy check result types."""

    PASS = "PASS"
    FAIL = "FAIL"


class ResourceType(str, Enum):
    """Resource types for public access checks.

    See: https://docs.aws.amazon.com/cli/latest/reference/accessanalyzer/check-no-public-access.html
    """

    # Storage
    AWS_S3_BUCKET = "AWS::S3::Bucket"
    AWS_S3_ACCESS_POINT = "AWS::S3::AccessPoint"
    AWS_S3_MULTI_REGION_ACCESS_POINT = "AWS::S3::MultiRegionAccessPoint"
    AWS_S3_EXPRESS_DIRECTORY_BUCKET = "AWS::S3Express::DirectoryBucket"
    AWS_S3_EXPRESS_ACCESS_POINT = "AWS::S3Express::AccessPoint"
    AWS_S3_GLACIER = "AWS::S3::Glacier"
    AWS_S3_OUTPOSTS_BUCKET = "AWS::S3Outposts::Bucket"
    AWS_S3_OUTPOSTS_ACCESS_POINT = "AWS::S3Outposts::AccessPoint"
    AWS_S3_TABLES_TABLE_BUCKET = "AWS::S3Tables::TableBucket"
    AWS_S3_TABLES_TABLE = "AWS::S3Tables::Table"
    AWS_EFS_FILE_SYSTEM = "AWS::EFS::FileSystem"

    # Database
    AWS_DYNAMODB_TABLE = "AWS::DynamoDB::Table"
    AWS_DYNAMODB_STREAM = "AWS::DynamoDB::Stream"
    AWS_OPENSEARCH_DOMAIN = "AWS::OpenSearchService::Domain"

    # Messaging & Streaming
    AWS_KINESIS_STREAM = "AWS::Kinesis::Stream"
    AWS_KINESIS_STREAM_CONSUMER = "AWS::Kinesis::StreamConsumer"
    AWS_SNS_TOPIC = "AWS::SNS::Topic"
    AWS_SQS_QUEUE = "AWS::SQS::Queue"

    # Security & Secrets
    AWS_KMS_KEY = "AWS::KMS::Key"
    AWS_SECRETS_MANAGER_SECRET = "AWS::SecretsManager::Secret"
    AWS_IAM_ASSUME_ROLE_POLICY = "AWS::IAM::AssumeRolePolicyDocument"

    # Compute
    AWS_LAMBDA_FUNCTION = "AWS::Lambda::Function"

    # API & Integration
    AWS_API_GATEWAY_REST_API = "AWS::ApiGateway::RestApi"

    # DevOps & Management
    AWS_CODE_ARTIFACT_DOMAIN = "AWS::CodeArtifact::Domain"
    AWS_BACKUP_VAULT = "AWS::Backup::BackupVault"
    AWS_CLOUDTRAIL_DASHBOARD = "AWS::CloudTrail::Dashboard"
    AWS_CLOUDTRAIL_EVENT_DATA_STORE = "AWS::CloudTrail::EventDataStore"


@dataclass
class ReasonSummary:
    """Represents a reason from custom policy checks."""

    description: str
    statement_index: int | None = None
    statement_id: str | None = None


@dataclass
class CustomCheckResult:
    """Result from a custom policy check (CheckAccessNotGranted, CheckNoNewAccess, etc.)."""

    check_type: str  # "AccessNotGranted", "NoNewAccess", "NoPublicAccess"
    result: CheckResultType
    message: str
    reasons: list[ReasonSummary]
    policy_file: str | None = None

    @property
    def passed(self) -> bool:
        """Check if the validation passed."""
        return self.result == CheckResultType.PASS


@dataclass
class AccessAnalyzerFinding:
    """Represents a finding from IAM Access Analyzer."""

    finding_type: FindingType
    issue_code: str
    message: str
    learn_more_link: str
    locations: list[dict[str, Any]]

    @property
    def severity(self) -> str:
        """Map finding type to severity level."""
        mapping = {
            FindingType.ERROR: "error",
            FindingType.SECURITY_WARNING: "warning",
            FindingType.WARNING: "warning",
            FindingType.SUGGESTION: "info",
        }
        return mapping.get(self.finding_type, "info")


@dataclass
class AccessAnalyzerResult:
    """Results from validating a policy with Access Analyzer."""

    policy_file: str
    is_valid: bool
    findings: list[AccessAnalyzerFinding]
    custom_checks: list[CustomCheckResult] | None = None
    error: str | None = None

    @property
    def error_count(self) -> int:
        """Count of ERROR findings."""
        return sum(1 for f in self.findings if f.finding_type == FindingType.ERROR)

    @property
    def warning_count(self) -> int:
        """Count of WARNING and SECURITY_WARNING findings."""
        return sum(
            1
            for f in self.findings
            if f.finding_type in (FindingType.WARNING, FindingType.SECURITY_WARNING)
        )

    @property
    def suggestion_count(self) -> int:
        """Count of SUGGESTION findings."""
        return sum(1 for f in self.findings if f.finding_type == FindingType.SUGGESTION)

    @property
    def failed_custom_checks(self) -> int:
        """Count of failed custom checks."""
        if not self.custom_checks:
            return 0
        return sum(1 for c in self.custom_checks if not c.passed)


@dataclass
class AccessAnalyzerReport:
    """Aggregated report from Access Analyzer validation."""

    total_policies: int
    valid_policies: int
    invalid_policies: int
    total_findings: int
    results: list[AccessAnalyzerResult]

    @property
    def total_errors(self) -> int:
        """Total number of errors across all policies."""
        return sum(r.error_count for r in self.results)

    @property
    def total_warnings(self) -> int:
        """Total number of warnings across all policies."""
        return sum(r.warning_count for r in self.results)

    @property
    def total_suggestions(self) -> int:
        """Total number of suggestions across all policies."""
        return sum(r.suggestion_count for r in self.results)

    @property
    def policies_with_findings(self) -> int:
        """Number of policies that have at least one finding."""
        return sum(1 for r in self.results if r.findings)


class AccessAnalyzerValidator:
    """Validates IAM policies using AWS IAM Access Analyzer."""

    def __init__(
        self,
        region: str = "us-east-1",
        policy_type: PolicyType = PolicyType.IDENTITY_POLICY,
        profile: str | None = None,
    ):
        """Initialize the Access Analyzer validator.

        Args:
            region: AWS region to use for Access Analyzer API calls
            policy_type: Type of policy to validate
            profile: AWS profile name to use (optional)
        """
        self.region = region
        self.policy_type = policy_type
        self.profile = profile
        self.logger = logging.getLogger(__name__)

        try:
            session_kwargs: dict[str, Any] = {"region_name": region}
            if profile:
                session_kwargs["profile_name"] = profile

            session = boto3.Session(**session_kwargs)
            self.client = session.client("accessanalyzer")
            self.logger.info(f"Initialized Access Analyzer client in region {region}")
        except NoCredentialsError:
            self.logger.error(
                "AWS credentials not found. Please configure credentials using "
                "AWS CLI, environment variables, or IAM role."
            )
            raise
        except Exception as e:
            self.logger.error(f"Failed to initialize Access Analyzer client: {e}")
            raise

    def validate_policy(self, policy_document: dict[str, Any]) -> list[AccessAnalyzerFinding]:
        """Validate a single policy document using Access Analyzer.

        Args:
            policy_document: IAM policy document as a dictionary

        Returns:
            List of findings from Access Analyzer

        Raises:
            ClientError: If the API call fails
        """
        try:
            policy_json = json.dumps(policy_document)

            response = self.client.validate_policy(
                policyDocument=policy_json,
                policyType=self.policy_type.value,
            )

            findings = []
            for finding_data in response.get("findings", []):
                finding = AccessAnalyzerFinding(
                    finding_type=FindingType(finding_data["findingType"]),
                    issue_code=finding_data["issueCode"],
                    message=finding_data["findingDetails"],
                    learn_more_link=finding_data["learnMoreLink"],
                    locations=finding_data.get("locations", []),
                )
                findings.append(finding)

            self.logger.debug(f"Validated policy, found {len(findings)} findings")
            return findings

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            self.logger.error(f"Access Analyzer API error ({error_code}): {error_msg}")
            raise
        except BotoCoreError as e:
            self.logger.error(f"AWS SDK error: {e}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to serialize policy document: {e}")
            raise

    def check_access_not_granted(
        self,
        policy_document: dict[str, Any],
        actions: list[str],
        resources: list[str] | None = None,
    ) -> CustomCheckResult:
        """Check that a policy does NOT grant specific access.

        Args:
            policy_document: IAM policy document as a dictionary
            actions: List of actions that should NOT be granted (e.g., ["s3:DeleteBucket"])
            resources: Optional list of resources to check (e.g., ["arn:aws:s3:::my-bucket/*"])

        Returns:
            CustomCheckResult with PASS/FAIL and reasons

        Raises:
            ClientError: If the API call fails
        """
        try:
            policy_json = json.dumps(policy_document)

            # Build access specification
            access_spec: dict[str, Any] = {"actions": actions}
            if resources:
                access_spec["resources"] = resources

            response = self.client.check_access_not_granted(
                policyDocument=policy_json,
                access=[access_spec],
                policyType=self.policy_type.value,
            )

            # Parse response
            result = CheckResultType(response["result"])
            message = response.get("message", "")

            reasons = []
            for reason_data in response.get("reasons", []):
                reason = ReasonSummary(
                    description=reason_data.get("description", ""),
                    statement_index=reason_data.get("statementIndex"),
                    statement_id=reason_data.get("statementId"),
                )
                reasons.append(reason)

            check_result = CustomCheckResult(
                check_type="AccessNotGranted",
                result=result,
                message=message,
                reasons=reasons,
            )

            self.logger.debug(f"CheckAccessNotGranted: {result.value} - {len(reasons)} reasons")
            return check_result

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            self.logger.error(f"CheckAccessNotGranted API error ({error_code}): {error_msg}")
            raise
        except BotoCoreError as e:
            self.logger.error(f"AWS SDK error: {e}")
            raise

    def check_no_new_access(
        self,
        new_policy_document: dict[str, Any],
        existing_policy_document: dict[str, Any],
    ) -> CustomCheckResult:
        """Check that a new policy doesn't grant new access compared to existing policy.

        Args:
            new_policy_document: New/updated IAM policy document
            existing_policy_document: Existing/reference IAM policy document

        Returns:
            CustomCheckResult with PASS/FAIL and reasons

        Raises:
            ClientError: If the API call fails
        """
        try:
            new_policy_json = json.dumps(new_policy_document)
            existing_policy_json = json.dumps(existing_policy_document)

            response = self.client.check_no_new_access(
                newPolicyDocument=new_policy_json,
                existingPolicyDocument=existing_policy_json,
                policyType=self.policy_type.value,
            )

            # Parse response
            result = CheckResultType(response["result"])
            message = response.get("message", "")

            reasons = []
            for reason_data in response.get("reasons", []):
                reason = ReasonSummary(
                    description=reason_data.get("description", ""),
                    statement_index=reason_data.get("statementIndex"),
                    statement_id=reason_data.get("statementId"),
                )
                reasons.append(reason)

            check_result = CustomCheckResult(
                check_type="NoNewAccess",
                result=result,
                message=message,
                reasons=reasons,
            )

            self.logger.debug(f"CheckNoNewAccess: {result.value} - {len(reasons)} reasons")
            return check_result

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            self.logger.error(f"CheckNoNewAccess API error ({error_code}): {error_msg}")
            raise
        except BotoCoreError as e:
            self.logger.error(f"AWS SDK error: {e}")
            raise

    def check_no_public_access(
        self,
        policy_document: dict[str, Any],
        resource_type: ResourceType,
    ) -> CustomCheckResult:
        """Check that a resource policy doesn't allow public access.

        Args:
            policy_document: Resource policy document (e.g., S3 bucket policy)
            resource_type: Type of AWS resource

        Returns:
            CustomCheckResult with PASS/FAIL and reasons

        Raises:
            ClientError: If the API call fails
        """
        try:
            policy_json = json.dumps(policy_document)

            response = self.client.check_no_public_access(
                policyDocument=policy_json,
                resourceType=resource_type.value,
            )

            # Parse response
            result = CheckResultType(response["result"])
            message = response.get("message", "")

            reasons = []
            for reason_data in response.get("reasons", []):
                reason = ReasonSummary(
                    description=reason_data.get("description", ""),
                    statement_index=reason_data.get("statementIndex"),
                    statement_id=reason_data.get("statementId"),
                )
                reasons.append(reason)

            check_result = CustomCheckResult(
                check_type=f"NoPublicAccess ({resource_type.value})",
                result=result,
                message=message,
                reasons=reasons,
            )

            self.logger.debug(f"CheckNoPublicAccess: {result.value} - {len(reasons)} reasons")
            return check_result

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            self.logger.error(f"CheckNoPublicAccess API error ({error_code}): {error_msg}")
            raise
        except BotoCoreError as e:
            self.logger.error(f"AWS SDK error: {e}")
            raise

    def validate_policies(
        self,
        policies: list[tuple[str, dict[str, Any]]],
        custom_checks: dict[str, Any] | None = None,
    ) -> list[AccessAnalyzerResult]:
        """Validate multiple policies.

        Args:
            policies: List of tuples containing (file_path, policy_document)
            custom_checks: Optional dictionary with custom check configurations:
                - 'access_not_granted': {'actions': [...], 'resources': [...]}
                - 'no_new_access': {'existing_policies': {policy_file: policy_doc}}
                - 'no_public_access': {'resource_types': [ResourceType, ...]}

        Returns:
            List of validation results
        """
        results = []

        for policy_file, policy_doc in policies:
            self.logger.info(f"Validating policy: {policy_file}")

            try:
                findings = self.validate_policy(policy_doc)
                has_errors = any(f.finding_type == FindingType.ERROR for f in findings)

                # Run custom checks if specified
                custom_check_results = []
                if custom_checks:
                    # Check access not granted
                    if "access_not_granted" in custom_checks:
                        config = custom_checks["access_not_granted"]

                        # Validate configuration structure
                        if not isinstance(config, dict):
                            self.logger.warning(
                                f"Invalid access_not_granted configuration for {policy_file}: "
                                "expected dict, skipping check"
                            )
                        elif "actions" not in config:
                            self.logger.warning(
                                f"access_not_granted configuration missing 'actions' "
                                f"for {policy_file}, skipping check"
                            )
                        else:
                            check_result = self.check_access_not_granted(
                                policy_doc,
                                actions=config["actions"],
                                resources=config.get("resources"),
                            )
                            check_result.policy_file = policy_file
                            custom_check_results.append(check_result)

                    # Check no new access
                    if "no_new_access" in custom_checks:
                        no_new_access_config = custom_checks["no_new_access"]

                        # Validate configuration structure
                        if not isinstance(no_new_access_config, dict):
                            self.logger.warning(
                                f"Invalid no_new_access configuration for {policy_file}: "
                                "expected dict, skipping check"
                            )
                        else:
                            existing_policies = no_new_access_config.get("existing_policies", {})
                            if policy_file in existing_policies:
                                check_result = self.check_no_new_access(
                                    policy_doc, existing_policies[policy_file]
                                )
                                check_result.policy_file = policy_file
                                custom_check_results.append(check_result)

                    # Check no public access (supports multiple resource types)
                    if "no_public_access" in custom_checks:
                        no_public_config = custom_checks["no_public_access"]

                        # Validate configuration structure
                        if not isinstance(no_public_config, dict):
                            self.logger.warning(
                                f"Invalid no_public_access configuration for {policy_file}: "
                                "expected dict, skipping check"
                            )
                        elif "resource_types" not in no_public_config:
                            self.logger.warning(
                                f"no_public_access configuration missing 'resource_types' "
                                f"for {policy_file}, skipping check"
                            )
                        else:
                            resource_types = no_public_config["resource_types"]
                            # Support both single ResourceType and list
                            if not isinstance(resource_types, list):
                                resource_types = [resource_types]

                            for resource_type in resource_types:
                                check_result = self.check_no_public_access(
                                    policy_doc, resource_type
                                )
                                check_result.policy_file = policy_file
                                custom_check_results.append(check_result)

                result = AccessAnalyzerResult(
                    policy_file=policy_file,
                    is_valid=not has_errors,
                    findings=findings,
                    custom_checks=(custom_check_results if custom_check_results else None),
                )
                results.append(result)

            except Exception as e:  # pylint: disable=broad-exception-caught
                self.logger.error(f"Failed to validate {policy_file}: {e}")
                result = AccessAnalyzerResult(
                    policy_file=policy_file,
                    is_valid=False,
                    findings=[],
                    error=str(e),
                )
                results.append(result)

        return results

    def generate_report(self, results: list[AccessAnalyzerResult]) -> AccessAnalyzerReport:
        """Generate a summary report from validation results.

        Args:
            results: List of validation results

        Returns:
            Aggregated report
        """
        total_policies = len(results)
        valid_policies = sum(1 for r in results if r.is_valid and not r.error)
        invalid_policies = total_policies - valid_policies
        total_findings = sum(len(r.findings) for r in results)

        return AccessAnalyzerReport(
            total_policies=total_policies,
            valid_policies=valid_policies,
            invalid_policies=invalid_policies,
            total_findings=total_findings,
            results=results,
        )


def validate_policies_with_analyzer(
    path: str | list[str],
    region: str = "us-east-1",
    policy_type: PolicyType = PolicyType.IDENTITY_POLICY,
    profile: str | None = None,
    recursive: bool = True,
    custom_checks: dict[str, Any] | None = None,
) -> AccessAnalyzerReport:
    """Validate IAM policies from file(s) or director(ies) using Access Analyzer.

    Args:
        path: Path to policy file/directory, or list of paths
        region: AWS region for Access Analyzer
        policy_type: Type of policy to validate
        profile: AWS profile name (optional)
        recursive: Whether to search directories recursively
        custom_checks: Optional custom check configurations

    Returns:
        Validation report

    Raises:
        ValueError: If no policies found
        ClientError: If AWS API calls fail
    """
    # Load policies
    loader = PolicyLoader()
    if isinstance(path, list):
        loaded_policies = loader.load_from_paths(path, recursive=recursive)
        path_description = ", ".join(path)
    else:
        loaded_policies = loader.load_from_path(path, recursive=recursive)
        path_description = path

    if not loaded_policies:
        raise ValueError(f"No valid IAM policies found in {path_description}")

    logging.info(f"Loaded {len(loaded_policies)} policies for Access Analyzer validation")

    # Convert IAMPolicy models to dicts for Access Analyzer
    # Use by_alias=True to export with capitalized field names (Version, Statement, etc.)
    policy_dicts: list[tuple[str, dict[str, Any]]] = [
        (file_path, policy.model_dump(by_alias=True, exclude_none=True))
        for file_path, policy in loaded_policies
    ]

    # Validate with Access Analyzer
    validator = AccessAnalyzerValidator(
        region=region,
        policy_type=policy_type,
        profile=profile,
    )

    results = validator.validate_policies(policy_dicts, custom_checks=custom_checks)
    report = validator.generate_report(results)

    return report

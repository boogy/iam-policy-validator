"""
Sensitive actions catalog for IAM Policy Validator.

This module defines a curated list of sensitive AWS actions that should
typically have IAM conditions to limit when they can be used.

Using Python instead of YAML/JSON provides:
- Zero parsing overhead (compiled to .pyc)
- Better PyPI packaging (no data files)
- Type hints and IDE autocomplete
- Easy to extend and maintain

The list is a frozenset for O(1) lookup performance.
"""

from typing import Final

# ============================================================================
# Sensitive Actions List
# ============================================================================
# These actions are considered sensitive and should typically have IAM
# conditions to limit when they can be used. Examples include:
# - IAM identity and access management changes
# - Secrets and credential operations
# - Destructive operations (deletions)
# - Security configuration changes
# - Network and firewall modifications
# - Logging and audit trail changes
# ============================================================================

DEFAULT_SENSITIVE_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        # IAM & Identity Management
        "iam:AddClientIDToOpenIDConnectProvider",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey",
        "iam:CreateOpenIDConnectProvider",
        "iam:CreatePolicyVersion",
        "iam:CreateRole",
        "iam:CreateSAMLProvider",
        "iam:CreateUser",
        "iam:DeleteAccessKey",
        "iam:DeleteLoginProfile",
        "iam:DeleteOpenIDConnectProvider",
        "iam:DeleteRole",
        "iam:DeleteRolePolicy",
        "iam:DeleteSAMLProvider",
        "iam:DeleteUser",
        "iam:DeleteUserPolicy",
        "iam:DetachRolePolicy",
        "iam:DetachUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy",
        "iam:SetDefaultPolicyVersion",
        "iam:UpdateAccessKey",
        "iam:UpdateAssumeRolePolicy",
        # Secrets & Credentials
        "kms:DisableKey",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "secretsmanager:DeleteSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "ssm:DeleteParameter",
        "ssm:PutParameter",
        # Compute & Containers
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeleteVpc",
        "ec2:ModifyInstanceAttribute",
        "ec2:TerminateInstances",
        "ecr:DeleteRepository",
        "ecs:DeleteCluster",
        "ecs:DeleteService",
        "eks:DeleteCluster",
        "lambda:DeleteFunction",
        "lambda:DeleteFunctionConcurrency",
        "lambda:PutFunctionConcurrency",
        # Database & Storage
        "dynamodb:DeleteTable",
        "efs:DeleteFileSystem",
        "elasticache:DeleteCacheCluster",
        "fsx:DeleteFileSystem",
        "rds:DeleteDBCluster",
        "rds:DeleteDBInstance",
        "redshift:DeleteCluster",
        # S3 & Backup
        "backup:DeleteBackupVault",
        "glacier:DeleteArchive",
        "s3:DeleteBucket",
        "s3:DeleteBucketPolicy",
        "s3:DeleteObject",
        "s3:PutBucketPolicy",
        "s3:PutLifecycleConfiguration",
        # Network & Security
        "ec2:ApplySecurityGroupsToClientVpnTargetNetwork",
        "ec2:AssociateClientVpnTargetNetwork",
        "ec2:AssociateSecurityGroupVpc",
        "ec2:AttachVpnGateway",
        "ec2:AuthorizeClientVpnIngress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateClientVpnRoute",
        "ec2:CreateVpnConnection",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteVpnConnection",
        "ec2:DisassociateRouteTable",
        "ec2:RevokeSecurityGroupEgress",
        # Access & Logging
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudwatch:DeleteLogGroup",
        "config:DeleteConfigurationRecorder",
        "guardduty:DeleteDetector",
        # Account & Organization
        "account:CloseAccount",
        "account:CreateAccount",
        "account:DeleteAccount",
        "organizations:DeleteOrganization",
        "organizations:LeaveOrganization",
        "organizations:RemoveAccountFromOrganization",
    }
)


def get_sensitive_actions() -> frozenset[str]:
    """
    Get all sensitive actions.

    Returns:
        Frozenset of all sensitive actions for O(1) membership testing
    """
    return DEFAULT_SENSITIVE_ACTIONS

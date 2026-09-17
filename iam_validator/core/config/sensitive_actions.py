"""
Sensitive actions catalog for IAM Policy Validator.

This module defines categorized lists of sensitive AWS actions that should
typically have IAM conditions to limit when they can be used.

Actions are organized into four security risk categories:
- CredentialExposure (46 actions):  Actions that expose credentials, secrets, or tokens
- DataAccess (109 actions):         Actions that retrieve sensitive data
- PrivEsc (27 actions):             Actions that enable privilege escalation
- ResourceExposure (321 actions):   Actions that modify resource policies or permissions

Total: 490 sensitive actions across all categories

Source: https://github.com/primeharbor/sensitive_iam_actions
"""

from typing import Any, Final

# ============================================================================
# Category: CredentialExposure (46 actions)
# ============================================================================
# Actions that expose credentials, secrets, API keys, or authentication tokens.
# These actions should be tightly controlled as they can lead to credential theft.
# ============================================================================

CREDENTIAL_EXPOSURE_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "appsync:GetDataSource",
        "appsync:GetFunction",
        "appsync:ListApiKeys",
        "chime:CreateApiKey",
        "chime:DeleteVoiceConnectorTerminationCredentials",
        "chime:PutVoiceConnectorTerminationCredentials",
        "cloud9:CreateEnvironmentSSH",
        "cloud9:CreateEnvironmentToken",
        "codeartifact:GetAuthorizationToken",
        "codebuild:DeleteSourceCredentials",
        "codebuild:ImportSourceCredentials",
        "cognito-identity:GetCredentialsForIdentity",
        "cognito-identity:GetId",
        "cognito-identity:GetOpenIdToken",
        "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
        "connect:GetFederationToken",
        "connect:ListSecurityKeys",
        "ec2-instance-connect:SendSSHPublicKey",
        "ec2:GetPasswordData",
        "ecr-public:GetAuthorizationToken",
        "ecr:GetAuthorizationToken",
        "gamelift:GetComputeAuthToken",
        "gamelift:RequestUploadCredentials",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:CreateServiceSpecificCredential",
        "iam:GetServiceLinkedRoleDeletionStatus",
        "iam:ResetServiceSpecificCredential",
        "iam:UpdateAccessKey",
        "lightsail:DownloadDefaultKeyPair",
        "lightsail:GetBucketAccessKeys",
        "lightsail:GetKeyPair",
        "lightsail:GetKeyPairs",
        "lightsail:GetRelationalDatabaseMasterUserPassword",
        "mediapackage:RotateChannelCredentials",
        "mediapackage:RotateIngestEndpointCredentials",
        "rds-db:connect",
        "redshift:CreateClusterUser",
        "redshift:GetClusterCredentials",
        "secretsmanager:GetSecretValue",
        "snowball:GetJobUnlockCode",
        "sts:AssumeRole",
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity",
        "sts:GetFederationToken",
        "sts:GetSessionToken",
    }
)

# ============================================================================
# Category: DataAccess (109 actions)
# ============================================================================
# Actions that retrieve sensitive data, query databases, or access stored content.
# These actions can expose confidential business or customer data.
# ============================================================================

DATA_ACCESS_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "aoss:APIAccessAll",
        "aoss:DashboardsAccessAll",
        "athena:GetQueryExecution",
        "athena:GetQueryResults",
        "athena:GetQueryResultsStream",
        "athena:GetSession",
        "cassandra:Select",
        "chatbot:DescribeSlackChannels",
        "chatbot:DescribeSlackUserIdentities",
        "chatbot:GetMicrosoftTeamsOauthParameters",
        "chatbot:GetSlackOauthParameters",
        "chatbot:ListMicrosoftTeamsConfiguredTeams",
        "chatbot:ListMicrosoftTeamsUserIdentities",
        "chime:GetAttendee",
        "chime:GetChannelMessage",
        "chime:GetMeeting",
        "chime:GetMeetingDetail",
        "chime:GetRoom",
        "chime:GetUser",
        "chime:GetUserActivityReportData",
        "chime:GetUserByEmail",
        "chime:GetUserSettings",
        "chime:ListAttendees",
        "chime:ListMeetingEvents",
        "chime:ListMeetings",
        "chime:ListUsers",
        "cleanrooms:GetProtectedQuery",
        "cloudformation:GetTemplate",
        "cloudfront:GetFunction",
        "codeartifact:GetPackageVersionAsset",
        "codeartifact:GetPackageVersionReadme",
        "codeartifact:ReadFromRepository",
        "cognito-identity:LookupDeveloperIdentity",
        "cognito-idp:AdminGetDevice",
        "cognito-idp:AdminGetUser",
        "cognito-idp:AdminListDevices",
        "cognito-idp:AdminListGroupsForUser",
        "cognito-idp:AdminListUserAuthEvents",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:GetDevice",
        "cognito-idp:GetGroup",
        "cognito-idp:GetUser",
        "cognito-idp:GetUserAttributeVerificationCode",
        "cognito-idp:ListDevices",
        "cognito-idp:ListGroups",
        "cognito-idp:ListUsers",
        "cognito-sync:ListRecords",
        "cognito-sync:QueryRecords",
        "connect:ListUsers",
        "datapipeline:QueryObjects",
        "dax:BatchGetItem",
        "dax:GetItem",
        "dax:Query",
        "dax:Scan",
        "dynamodb:BatchGetItem",
        "dynamodb:GetItem",
        "dynamodb:GetRecords",
        "dynamodb:Query",
        "dynamodb:Scan",
        "ecr:GetDownloadUrlForLayer",
        "gamelift:GetGameSessionLogUrl",
        "gamelift:GetInstanceAccess",
        "healthlake:ReadResource",
        "healthlake:SearchWithGet",
        "healthlake:SearchWithPost",
        "kendra:Query",
        "kinesis:GetRecords",
        "kinesisvideo:GetImages",
        "kinesisvideo:GetMedia",
        "lambda:GetFunction",
        "lambda:GetLayerVersion",
        "lightsail:GetContainerImages",
        "logs:GetLogEvents",
        "logs:GetLogRecord",
        "logs:GetQueryResults",
        "logs:Unmask",
        "macie2:GetFindings",
        "mediastore:GetObject",
        "qldb:GetBlock",
        "rds:DownloadCompleteDBLogFile",
        "rds:DownloadDBLogFilePortion",
        "robomaker:GetWorldTemplateBody",
        "s3-object-lambda:GetObject",
        "s3-object-lambda:GetObjectVersion",
        "s3-object-lambda:ListBucket",
        "s3:GetDataAccess",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "sagemaker:Search",
        "sdb:Select",
        "serverlessrepo:GetApplication",
        "serverlessrepo:GetCloudFormationTemplate",
        "sqs:ReceiveMessage",
        "ssm:GetDocument",
        "ssm:GetParameter",
        "ssm:GetParameterHistory",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "sso-directory:DescribeGroup",
        "sso-directory:DescribeUser",
        "sso-directory:ListBearerTokens",
        "sso-directory:SearchGroups",
        "sso-directory:SearchUsers",
        "sso:SearchGroups",
        "sso:SearchUsers",
        "storagegateway:DescribeChapCredentials",
        "workdocs:GetDocument",
        "workdocs:GetDocumentPath",
        "workdocs:GetDocumentVersion",
    }
)

# ============================================================================
# Category: PrivEsc (27 actions)
# ============================================================================
# Actions that enable privilege escalation by creating or modifying IAM identities,
# roles, policies, or permission boundaries. These are critical security controls.
# ============================================================================

PRIV_ESC_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "codestar:AssociateTeamMember",
        "codestar:CreateProject",
        "ec2-instance-connect:SendSSHPublicKey",
        "glue:UpdateDevEndpoint",
        "iam:AddUserToGroup",
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:CreatePolicyVersion",
        "iam:CreateServiceLinkedRole",
        "iam:CreateVirtualMFADevice",
        "iam:DeleteRolePermissionsBoundary",
        "iam:DeleteUserPermissionsBoundary",
        "iam:EnableMFADevice",
        "iam:PassRole",
        "iam:PutGroupPolicy",
        "iam:PutRolePermissionsBoundary",
        "iam:PutRolePolicy",
        "iam:PutUserPermissionsBoundary",
        "iam:PutUserPolicy",
        "iam:ResyncMFADevice",
        "iam:SetDefaultPolicyVersion",
        "iam:UpdateAssumeRolePolicy",
        "iam:UpdateLoginProfile",
        "kms:CreateGrant",
    }
)

# ============================================================================
# Category: ResourceExposure (321 actions)
# ============================================================================
# Actions that modify resource policies, access policies, sharing settings,
# or permissions that could expose resources to unauthorized access.
# ============================================================================

RESOURCE_EXPOSURE_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "account:CloseAccount",
        "account:CreateAccount",
        "account:DeleteAccount",
        "acm-pca:CreatePermission",
        "acm-pca:DeletePermission",
        "acm-pca:DeletePolicy",
        "acm-pca:PutPolicy",
        "apigateway:UpdateRestApiPolicy",
        "backup:DeleteBackupVault",
        "backup:DeleteBackupVaultAccessPolicy",
        "backup:PutBackupVaultAccessPolicy",
        "cloudformation:SetStackPolicy",
        "cloudsearch:UpdateServiceAccessPolicies",
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudwatch:DeleteLogGroup",
        "codeartifact:DeleteDomainPermissionsPolicy",
        "codeartifact:DeleteRepositoryPermissionsPolicy",
        "codebuild:DeleteResourcePolicy",
        "codebuild:PutResourcePolicy",
        "codeguru-profiler:PutPermission",
        "codeguru-profiler:RemovePermission",
        "codestar:AssociateTeamMember",
        "codestar:CreateProject",
        "codestar:DeleteProject",
        "codestar:DisassociateTeamMember",
        "codestar:UpdateTeamMember",
        "cognito-identity:CreateIdentityPool",
        "cognito-identity:DeleteIdentities",
        "cognito-identity:DeleteIdentityPool",
        "cognito-identity:MergeDeveloperIdentities",
        "cognito-identity:SetIdentityPoolRoles",
        "cognito-identity:UnlinkDeveloperIdentity",
        "cognito-identity:UnlinkIdentity",
        "cognito-identity:UpdateIdentityPool",
        "config:DeleteConfigurationRecorder",
        "deeplens:AssociateServiceRoleToAccount",
        "ds:CreateConditionalForwarder",
        "ds:CreateDirectory",
        "ds:CreateMicrosoftAD",
        "ds:CreateTrust",
        "ds:ShareDirectory",
        "dynamodb:DeleteTable",
        "ec2:ApplySecurityGroupsToClientVpnTargetNetwork",
        "ec2:AssociateClientVpnTargetNetwork",
        "ec2:AssociateSecurityGroupVpc",
        "ec2:AttachVpnGateway",
        "ec2:AuthorizeClientVpnIngress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateClientVpnRoute",
        "ec2:CreateNetworkInterfacePermission",
        "ec2:CreateVpnConnection",
        "ec2:DeleteNetworkInterfacePermission",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeleteVpc",
        "ec2:DeleteVpnConnection",
        "ec2:DisableImageBlockPublicAccess",
        "ec2:DisassociateRouteTable",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:ModifyVpcEndpointServicePermissions",
        "ec2:ResetSnapshotAttribute",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:TerminateInstances",
        "ecr:DeleteRepository",
        "ecr:DeleteRepositoryPolicy",
        "ecr:SetRepositoryPolicy",
        "ecs:DeleteCluster",
        "ecs:DeleteService",
        "efs:DeleteFileSystem",
        "eks:DeleteCluster",
        "elasticache:DeleteCacheCluster",
        "elasticfilesystem:DeleteFileSystemPolicy",
        "elasticfilesystem:PutFileSystemPolicy",
        "elasticmapreduce:PutBlockPublicAccessConfiguration",
        "es:CreateElasticsearchDomain",
        "es:ESHttpDelete",
        "es:ESHttpPatch",
        "es:ESHttpPost",
        "es:ESHttpPut",
        "es:UpdateElasticsearchDomainConfig",
        "fsx:DeleteFileSystem",
        "glacier:AbortVaultLock",
        "glacier:CompleteVaultLock",
        "glacier:DeleteArchive",
        "glacier:DeleteVaultAccessPolicy",
        "glacier:InitiateVaultLock",
        "glacier:SetDataRetrievalPolicy",
        "glacier:SetVaultAccessPolicy",
        "glue:DeleteResourcePolicy",
        "glue:PutResourcePolicy",
        "glue:UpdateDevEndpoint",
        "greengrass:AssociateServiceRoleToAccount",
        "guardduty:DeleteDetector",
        "health:DisableHealthServiceAccessForOrganization",
        "health:EnableHealthServiceAccessForOrganization",
        "iam:AddClientIDToOpenIDConnectProvider",
        "iam:AddRoleToInstanceProfile",
        "iam:ChangePassword",
        "iam:CreateAccountAlias",
        "iam:CreateInstanceProfile",
        "iam:CreateOpenIDConnectProvider",
        "iam:CreateSAMLProvider",
        "iam:CreateServiceLinkedRole",
        "iam:CreateVirtualMFADevice",
        "iam:DeactivateMFADevice",
        "iam:DeleteAccessKey",
        "iam:DeleteAccountAlias",
        "iam:DeleteAccountPasswordPolicy",
        "iam:DeleteGroup",
        "iam:DeleteGroupPolicy",
        "iam:DeleteInstanceProfile",
        "iam:DeleteLoginProfile",
        "iam:DeleteOpenIDConnectProvider",
        "iam:DeletePolicy",
        "iam:DeletePolicyVersion",
        "iam:DeleteRole",
        "iam:DeleteRolePermissionsBoundary",
        "iam:DeleteRolePolicy",
        "iam:DeleteSAMLProvider",
        "iam:DeleteSSHPublicKey",
        "iam:DeleteServerCertificate",
        "iam:DeleteServiceLinkedRole",
        "iam:DeleteServiceSpecificCredential",
        "iam:DeleteSigningCertificate",
        "iam:DeleteUser",
        "iam:DeleteUserPolicy",
        "iam:DeleteVirtualMFADevice",
        "iam:DetachGroupPolicy",
        "iam:DetachRolePolicy",
        "iam:DetachUserPolicy",
        "iam:EnableMFADevice",
        "iam:RemoveClientIDFromOpenIDConnectProvider",
        "iam:RemoveRoleFromInstanceProfile",
        "iam:RemoveUserFromGroup",
        "iam:ResyncMFADevice",
        "iam:SetSecurityTokenServicePreferences",
        "iam:UpdateAccountPasswordPolicy",
        "iam:UpdateGroup",
        "iam:UpdateLoginProfile",
        "iam:UpdateOpenIDConnectProviderThumbprint",
        "iam:UpdateRole",
        "iam:UpdateRoleDescription",
        "iam:UpdateSAMLProvider",
        "iam:UpdateSSHPublicKey",
        "iam:UpdateServerCertificate",
        "iam:UpdateServiceSpecificCredential",
        "iam:UpdateSigningCertificate",
        "iam:UploadServerCertificate",
        "iam:UploadSigningCertificate",
        "imagebuilder:PutComponentPolicy",
        "imagebuilder:PutImagePolicy",
        "imagebuilder:PutImageRecipePolicy",
        "iot:AttachPolicy",
        "iot:AttachPrincipalPolicy",
        "iot:DetachPolicy",
        "iot:DetachPrincipalPolicy",
        "iot:SetDefaultAuthorizer",
        "iot:SetDefaultPolicyVersion",
        "iotsitewise:CreateAccessPolicy",
        "iotsitewise:DeleteAccessPolicy",
        "iotsitewise:UpdateAccessPolicy",
        "kms:CreateGrant",
        "kms:DisableKey",
        "kms:PutKeyPolicy",
        "kms:RetireGrant",
        "kms:RevokeGrant",
        "kms:ScheduleKeyDeletion",
        "lakeformation:BatchGrantPermissions",
        "lakeformation:BatchRevokePermissions",
        "lakeformation:GrantPermissions",
        "lakeformation:PutDataLakeSettings",
        "lakeformation:RevokePermissions",
        "lambda:AddLayerVersionPermission",
        "lambda:AddPermission",
        "lambda:DeleteFunction",
        "lambda:DeleteFunctionConcurrency",
        "lambda:DisableReplication",
        "lambda:EnableReplication",
        "lambda:PutFunctionConcurrency",
        "lambda:RemoveLayerVersionPermission",
        "lambda:RemovePermission",
        "license-manager:UpdateServiceSettings",
        "logs:DeleteResourcePolicy",
        "logs:PutResourcePolicy",
        "mediastore:DeleteContainerPolicy",
        "mediastore:PutContainerPolicy",
        "opsworks:SetPermission",
        "opsworks:UpdateUserProfile",
        "organizations:DeleteOrganization",
        "organizations:LeaveOrganization",
        "organizations:RemoveAccountFromOrganization",
        "quicksight:CreateAdmin",
        "quicksight:CreateGroup",
        "quicksight:CreateGroupMembership",
        "quicksight:CreateIAMPolicyAssignment",
        "quicksight:CreateUser",
        "quicksight:DeleteGroup",
        "quicksight:DeleteGroupMembership",
        "quicksight:DeleteIAMPolicyAssignment",
        "quicksight:DeleteUser",
        "quicksight:DeleteUserByPrincipalId",
        "quicksight:RegisterUser",
        "quicksight:UpdateDashboardPermissions",
        "quicksight:UpdateGroup",
        "quicksight:UpdateIAMPolicyAssignment",
        "quicksight:UpdateTemplatePermissions",
        "quicksight:UpdateUser",
        "ram:AcceptResourceShareInvitation",
        "ram:AssociateResourceShare",
        "ram:CreateResourceShare",
        "ram:DeleteResourceShare",
        "ram:DisassociateResourceShare",
        "ram:EnableSharingWithAwsOrganization",
        "ram:RejectResourceShareInvitation",
        "ram:UpdateResourceShare",
        "rds:AuthorizeDBSecurityGroupIngress",
        "rds:DeleteDBCluster",
        "rds:DeleteDBInstance",
        "redshift:AuthorizeSnapshotAccess",
        "redshift:CreateSnapshotCopyGrant",
        "redshift:DeleteCluster",
        "redshift:JoinGroup",
        "redshift:ModifyClusterIamRoles",
        "redshift:RevokeSnapshotAccess",
        "route53resolver:PutResolverRulePolicy",
        "s3:BypassGovernanceRetention",
        "s3:DeleteAccessPointPolicy",
        "s3:DeleteBucket",
        "s3:DeleteBucketPolicy",
        "s3:DeleteObject",
        "s3:ObjectOwnerOverrideToBucketOwner",
        "s3:PutAccessPointPolicy",
        "s3:PutAccountPublicAccessBlock",
        "s3:PutBucketAcl",
        "s3:PutBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutLifecycleConfiguration",
        "s3:PutObjectAcl",
        "s3:PutObjectVersionAcl",
        "secretsmanager:DeleteResourcePolicy",
        "secretsmanager:DeleteSecret",
        "secretsmanager:PutResourcePolicy",
        "secretsmanager:PutSecretValue",
        "secretsmanager:ValidateResourcePolicy",
        "servicecatalog:CreatePortfolioShare",
        "servicecatalog:DeletePortfolioShare",
        "sns:AddPermission",
        "sns:CreateTopic",
        "sns:RemovePermission",
        "sns:SetTopicAttributes",
        "sqs:AddPermission",
        "sqs:CreateQueue",
        "sqs:RemovePermission",
        "sqs:SetQueueAttributes",
        "ssm:DeleteParameter",
        "ssm:ModifyDocumentPermission",
        "ssm:PutParameter",
        "sso-directory:AddMemberToGroup",
        "sso-directory:CreateAlias",
        "sso-directory:CreateGroup",
        "sso-directory:CreateUser",
        "sso-directory:DeleteGroup",
        "sso-directory:DeleteUser",
        "sso-directory:DisableUser",
        "sso-directory:EnableUser",
        "sso-directory:RemoveMemberFromGroup",
        "sso-directory:UpdateGroup",
        "sso-directory:UpdatePassword",
        "sso-directory:UpdateUser",
        "sso-directory:VerifyEmail",
        "sso:AssociateDirectory",
        "sso:AssociateProfile",
        "sso:CreateApplicationInstance",
        "sso:CreateApplicationInstanceCertificate",
        "sso:CreatePermissionSet",
        "sso:CreateProfile",
        "sso:CreateTrust",
        "sso:DeleteApplicationInstance",
        "sso:DeleteApplicationInstanceCertificate",
        "sso:DeletePermissionSet",
        "sso:DeletePermissionsPolicy",
        "sso:DeleteProfile",
        "sso:DisassociateDirectory",
        "sso:DisassociateProfile",
        "sso:ImportApplicationInstanceServiceProviderMetadata",
        "sso:PutPermissionsPolicy",
        "sso:StartSSO",
        "sso:UpdateApplicationInstanceActiveCertificate",
        "sso:UpdateApplicationInstanceDisplayData",
        "sso:UpdateApplicationInstanceResponseConfiguration",
        "sso:UpdateApplicationInstanceResponseSchemaConfiguration",
        "sso:UpdateApplicationInstanceSecurityConfiguration",
        "sso:UpdateApplicationInstanceServiceProviderConfiguration",
        "sso:UpdateApplicationInstanceStatus",
        "sso:UpdateDirectoryAssociation",
        "sso:UpdatePermissionSet",
        "sso:UpdateProfile",
        "sso:UpdateSSOConfiguration",
        "sso:UpdateTrust",
        "storagegateway:DeleteChapCredentials",
        "storagegateway:SetLocalConsolePassword",
        "storagegateway:SetSMBGuestPassword",
        "storagegateway:UpdateChapCredentials",
        "waf-regional:DeletePermissionPolicy",
        "waf-regional:GetChangeToken",
        "waf-regional:PutPermissionPolicy",
        "waf:DeletePermissionPolicy",
        "waf:GetChangeToken",
        "waf:PutPermissionPolicy",
        "wafv2:CreateWebACL",
        "wafv2:DeletePermissionPolicy",
        "wafv2:DeleteWebACL",
        "wafv2:PutPermissionPolicy",
        "wafv2:UpdateWebACL",
        "worklink:UpdateDevicePolicyConfiguration",
        "workmail:ResetPassword",
        "workmail:ResetUserPassword",
        "xray:PutEncryptionConfig",
    }
)

# ============================================================================
# Combined Actions Set (for backward compatibility)
# ============================================================================

DEFAULT_SENSITIVE_ACTIONS: Final[frozenset[str]] = (
    CREDENTIAL_EXPOSURE_ACTIONS | DATA_ACCESS_ACTIONS | PRIV_ESC_ACTIONS | RESOURCE_EXPOSURE_ACTIONS
)


# ============================================================================
# Default privilege-escalation combos (cross-statement, all_of, sensitive_action check)
# ============================================================================
# User config for `sensitive_action.sensitive_actions` merges with these via
# SensitiveActionCheck._apply_merge_strategy; the key itself carries no defaults.

DEFAULT_PRIVILEGE_ESCALATION_COMBOS: Final[list[dict[str, Any]]] = [
    # User privilege escalation: Create user + attach admin policy
    {
        "all_of": ["iam:CreateUser", "iam:AttachUserPolicy"],
        "severity": "critical",
        "message": "Policy grants {actions} across statements - enables privilege escalation. {statements}",
        "suggestion": (
            "This combination allows an attacker to:\n"
            "1. Create a new IAM user\n"
            "2. Attach AdministratorAccess policy to that user\n"
            "3. Escalate to full account access\n\n"
            "Mitigation options:\n"
            "• Remove both of these permissions\n"
            "• Add strict IAM conditions (IP restrictions, tags, force a specific policy with `iam:PolicyARN` condition)\n"
        ),
        "example": (
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "iam:PolicyARN": "arn:aws:iam::*:policy/ReadOnlyAccess"\n'
            "    },\n"
            '    "IpAddress": {\n'
            '      "aws:SourceIp": ["10.0.0.0/8"]\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },
    # Role privilege escalation: Create role + attach admin policy
    {
        "all_of": ["iam:CreateRole", "iam:AttachRolePolicy"],
        "severity": "high",
        "message": "Policy grants {actions} across statements - enables privilege escalation. {statements}",
        "suggestion": (
            "This combination allows creating privileged roles with admin policies.\n\n"
            "Mitigation options:\n"
            "• Remove both of these permissions\n"
            "• Add strict IAM conditions with a Permissions Boundary and ABAC Tagging, force a specific policy with `iam:PolicyARN` condition\n"
        ),
        "example": (
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "iam:PermissionsBoundary": "arn:aws:iam::*:policy/MaxPermissions"\n'
            "    }\n"
            "  }\n"
            "}\n"
            "OR\n"
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "iam:PolicyARN": "arn:aws:iam::*:policy/MaxPermissions"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },
    # Lambda backdoor: Create/update function + invoke
    {
        "all_of": ["lambda:CreateFunction", "lambda:InvokeFunction"],
        "severity": "medium",
        "message": "Policy grants {actions} across statements - enables code execution. {statements}",
        "suggestion": (
            "This combination allows an attacker to:\n"
            "1. Create a Lambda function with malicious code\n"
            "2. Execute the function to perform operations with the Lambda's role\n\n"
            "Mitigation options:\n"
            "• Restrict Lambda creation to specific function names/paths\n"
            "• Require resource tags on functions and tag-based invocation controls\n"
            "• Require MFA for Lambda function creation\n"
            "• Use separate policies for creation vs invocation"
        ),
        "example": (
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "aws:PrincipalTag/team": "${aws:ResourceTag/team}"\n'
            "    },\n"
            '    "SourceIp": {\n'
            '      "aws:SourceIp": ["10.0.0.0/8"]\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },
    # Lambda code modification backdoor
    {
        "all_of": ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
        "severity": "medium",
        "message": "Policy grants {actions} across statements - enables code injection. {statements}",
        "suggestion": (
            "This combination allows modifying existing Lambda functions and executing them.\n\n"
            "Mitigation options:\n"
            "• Use resource-based policies to restrict which functions can be modified\n"
            "• Require MFA for code updates\n"
            "• Use separate policies for code updates vs invocation\n"
            "• Implement code signing for Lambda functions"
        ),
        "example": (
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "aws:ResourceAccount": "${aws:PrincipalAccount}"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },
    # EC2 instance privilege escalation
    {
        "all_of": ["ec2:RunInstances", "iam:PassRole"],
        "severity": "high",
        "message": "Policy grants {actions} across statements - enables privilege escalation via instance profile. {statements}",
        "suggestion": (
            "This combination allows launching EC2 instances with privileged roles.\n\n"
            "Mitigation options:\n"
            "• Add iam:PassedToService condition requiring ec2.amazonaws.com\n"
            "• Restrict instance creation to specific AMIs or instance types\n"
            "• Limit PassRole to specific low-privilege roles\n"
            "• Require tagging and ABAC controls"
        ),
        "example": (
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "iam:PassedToService": "ec2.amazonaws.com"\n'
            "    },\n"
            '    "ArnLike": {\n'
            '      "iam:AssociatedResourceArn": "arn:aws:ec2:*:*:instance/*"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },
    # Glue dev endpoint privilege escalation
    {
        "all_of": ["glue:CreateDevEndpoint", "iam:PassRole"],
        "severity": "high",
        "message": "Policy grants {actions} across statements - enables privilege escalation via Glue dev endpoint. {statements}",
        "suggestion": (
            "This combination allows creating a Glue development endpoint with a "
            "privileged role attached, then using the endpoint (e.g. via SSH) to "
            "act with that role's permissions.\n\n"
            "Mitigation options:\n"
            "• Add iam:PassedToService condition requiring glue.amazonaws.com\n"
            "• Limit PassRole to specific low-privilege roles\n"
            "• Remove glue:CreateDevEndpoint if not needed"
        ),
        "example": (
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "iam:PassedToService": "glue.amazonaws.com"\n'
            "    },\n"
            '    "ArnLike": {\n'
            '      "iam:PolicyARN": "arn:aws:iam::*:role/glue-limited-*"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },
    # CloudFormation stack privilege escalation
    {
        "all_of": ["cloudformation:CreateStack", "iam:PassRole"],
        "severity": "high",
        "message": "Policy grants {actions} across statements - enables privilege escalation via CloudFormation service role. {statements}",
        "suggestion": (
            "This combination allows launching a CloudFormation stack with a "
            "privileged service role; the stack template can then create or "
            "modify any resource that role permits (including IAM).\n\n"
            "Mitigation options:\n"
            "• Add iam:PassedToService condition requiring cloudformation.amazonaws.com\n"
            "• Limit PassRole to specific low-privilege stack roles\n"
            "• Restrict cloudformation:TemplateUrl to trusted buckets"
        ),
        "example": (
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "iam:PassedToService": "cloudformation.amazonaws.com"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },
    # SageMaker notebook privilege escalation
    {
        "all_of": ["sagemaker:CreateNotebookInstance", "iam:PassRole"],
        "severity": "high",
        "message": "Policy grants {actions} across statements - enables privilege escalation via SageMaker notebook role. {statements}",
        "suggestion": (
            "This combination allows creating a SageMaker notebook instance with "
            "a privileged execution role, then running code in the notebook with "
            "that role's permissions.\n\n"
            "Mitigation options:\n"
            "• Add iam:PassedToService condition requiring sagemaker.amazonaws.com\n"
            "• Limit PassRole to specific low-privilege execution roles"
        ),
        "example": (
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "iam:PassedToService": "sagemaker.amazonaws.com"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },
    # SSM run-command lateral movement with a passable role
    {
        "all_of": ["ssm:SendCommand", "iam:PassRole"],
        "severity": "high",
        "message": "Policy grants {actions} across statements - enables privilege escalation via remote command execution. {statements}",
        "suggestion": (
            "ssm:SendCommand executes commands on managed instances with the "
            "instance profile's permissions; combined with iam:PassRole the "
            "principal can also wire privileged roles onto resources it "
            "controls.\n\n"
            "Mitigation options:\n"
            "• Restrict ssm:SendCommand to specific instances or tags\n"
            "• Limit PassRole to specific low-privilege roles\n"
            "• Require aws:ResourceTag conditions on target instances"
        ),
        "example": (
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "aws:ResourceTag/environment": "sandbox"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },
    # CodeBuild project privilege escalation
    {
        "all_of": ["codebuild:CreateProject", "iam:PassRole"],
        "severity": "high",
        "message": "Policy grants {actions} across statements - enables privilege escalation via CodeBuild service role. {statements}",
        "suggestion": (
            "This combination allows creating a CodeBuild project with a "
            "privileged service role; the buildspec then runs arbitrary "
            "commands with that role's permissions.\n\n"
            "Mitigation options:\n"
            "• Add iam:PassedToService condition requiring codebuild.amazonaws.com\n"
            "• Limit PassRole to specific low-privilege build roles"
        ),
        "example": (
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "iam:PassedToService": "codebuild.amazonaws.com"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },
    # Data Pipeline privilege escalation
    {
        "all_of": [
            "datapipeline:CreatePipeline",
            "datapipeline:PutPipelineDefinition",
            "iam:PassRole",
        ],
        "severity": "high",
        "message": "Policy grants {actions} across statements - enables privilege escalation via Data Pipeline roles. {statements}",
        "suggestion": (
            "This combination allows creating a Data Pipeline whose definition "
            "runs shell activities with a passed (potentially privileged) "
            "role.\n\n"
            "Mitigation options:\n"
            "• Add iam:PassedToService condition requiring datapipeline.amazonaws.com\n"
            "• Limit PassRole to specific low-privilege pipeline roles\n"
            "• Remove Data Pipeline permissions (the service is deprecated)"
        ),
        "example": (
            "{\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "iam:PassedToService": "datapipeline.amazonaws.com"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },
]


# ============================================================================
# Category Metadata
# ============================================================================

SENSITIVE_ACTION_CATEGORIES = {
    "credential_exposure": {
        "name": "Credential Exposure",
        "description": "Actions that expose credentials, secrets, API keys, or authentication tokens",
        "actions": CREDENTIAL_EXPOSURE_ACTIONS,
        "severity": "critical",
    },
    "data_access": {
        "name": "Data Access",
        "description": "Actions that retrieve sensitive data from databases, storage, or services",
        "actions": DATA_ACCESS_ACTIONS,
        "severity": "high",
    },
    "priv_esc": {
        "name": "Privilege Escalation",
        "description": "Actions that enable privilege escalation through IAM modifications",
        "actions": PRIV_ESC_ACTIONS,
        "severity": "critical",
    },
    "resource_exposure": {
        "name": "Resource Exposure",
        "description": "Actions that modify resource policies or permissions, potentially exposing resources",
        "actions": RESOURCE_EXPOSURE_ACTIONS,
        "severity": "high",
    },
}


# ============================================================================
# Helper Functions
# ============================================================================


def get_sensitive_actions(
    categories: list[str] | None = None,
) -> frozenset[str]:
    """
    Get sensitive actions filtered by category.

    Args:
        categories: List of category IDs to include. If None, returns all actions.
                   Valid categories: 'credential_exposure', 'data_access',
                   'priv_esc', 'resource_exposure'

    Returns:
        Frozenset of sensitive actions matching the specified categories

    Examples:
        >>> # Get all sensitive actions (default behavior)
        >>> all_actions = get_sensitive_actions()

        >>> # Get only privilege escalation actions
        >>> priv_esc = get_sensitive_actions(['priv_esc'])

        >>> # Get credential exposure and data access actions
        >>> sensitive = get_sensitive_actions(['credential_exposure', 'data_access'])
    """
    if categories is None:
        return DEFAULT_SENSITIVE_ACTIONS

    result_actions: set[str] = set()
    for category in categories:
        if category in SENSITIVE_ACTION_CATEGORIES:
            result_actions.update(SENSITIVE_ACTION_CATEGORIES[category]["actions"])

    return frozenset(result_actions)


def get_category_for_action(action: str) -> str | None:
    """
    Get the category for a specific action.

    Args:
        action: The AWS action to look up (e.g., 'iam:PassRole')

    Returns:
        Category ID if found, None otherwise

    Examples:
        >>> get_category_for_action('iam:PassRole')
        'priv_esc'

        >>> get_category_for_action('s3:GetObject')
        'data_access'
    """
    for category_id, category_data in SENSITIVE_ACTION_CATEGORIES.items():
        if action in category_data["actions"]:
            return category_id
    return None

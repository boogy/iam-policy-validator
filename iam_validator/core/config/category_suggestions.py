"""
Category-specific suggestions for sensitive actions.

This module defines ABAC-focused (Attribute-Based Access Control) suggestions
and examples for each sensitive action category. These provide actionable
guidance for securing sensitive AWS actions.

ABAC is the recommended approach as it:
- Scales across all AWS services
- Reduces policy maintenance overhead
- Provides fine-grained access control
- Enables self-service resource management
"""

from typing import Any, Final

# ============================================================================
# ABAC-Focused Category Suggestions
# ============================================================================
# Each category provides tailored guidance based on the security risk profile
# ============================================================================

DEFAULT_CATEGORY_SUGGESTIONS: Final[dict[str, dict[str, Any]]] = {
    "credential_exposure": {
        "suggestion": (
            "This action can expose credentials or secrets. Use ABAC to restrict access:\n"
            "• Match principal tags to resource tags (aws:PrincipalTag/team = aws:ResourceTag/team)\n"
            "• Require MFA (aws:MultiFactorAuthPresent = true)\n"
            "• Restrict to trusted networks (aws:SourceIp)\n"
            "• Limit to business hours (aws:CurrentTime)"
        ),
        "example": (
            '"Condition": {\n'
            '  "StringEquals": {\n'
            '    "aws:PrincipalTag/owner": "${aws:ResourceTag/owner}"\n'
            "  },\n"
            '  "Bool": {"aws:MultiFactorAuthPresent": "true"}\n'
            "}"
        ),
        "action_overrides": {
            "iam:CreateAccessKey": {
                "suggestion": (
                    "This action creates long-term credentials that can be compromised. Restrict creation to authorized roles:\n"
                    "• Require MFA (`aws:MultiFactorAuthPresent` = `true`) - CRITICAL\n"
                    "• Limit to specific principal tags (`aws:PrincipalTag/role` = `security-admin`)\n"
                    "• Restrict to corporate networks (`aws:SourceIp`)\n"
                    "• Consider requiring approval tags (`aws:RequestTag/approved-by`)"
                ),
                "example": (
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:PrincipalTag/role": "security-admin"\n'
                    "  },\n"
                    '  "Bool": {"aws:MultiFactorAuthPresent": "true"},\n'
                    '  "IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]}\n'
                    "}"
                ),
            },
        },
    },
    "data_access": {
        "suggestion": (
            "This action retrieves sensitive data. Use ABAC to control data access:\n"
            "• Match principal tags to resource tags (aws:PrincipalTag/data-access = aws:ResourceTag/data-classification)\n"
            "• Limit by department/team (aws:PrincipalTag/department = aws:ResourceTag/owner)\n"
            "• Restrict data exfiltration (aws:SourceIp or aws:SourceVpc)\n"
            "• Consider data classification levels"
        ),
        "example": (
            '"Condition": {\n'
            '  "StringEquals": {\n'
            '    "aws:PrincipalTag/owner": "${aws:ResourceTag/owner}",\n'
            '    "aws:ResourceTag/data-classification": ["public", "internal"]\n'
            "  }\n"
            "}"
        ),
    },
    "priv_esc": {
        "suggestion": (
            "This action enables privilege escalation. Use ABAC + strong controls:\n"
            "• Require specific role tags (aws:PrincipalTag/role = admin)\n"
            "• Enforce permissions boundary (iam:PermissionsBoundary)\n"
            "• Require MFA (aws:MultiFactorAuthPresent = true) - CRITICAL\n"
            "• Limit request tags (aws:RequestTag/environment != production)"
        ),
        "example": (
            '"Condition": {\n'
            '  "StringEquals": {\n'
            '    "aws:PrincipalTag/role": "security-admin",\n'
            '    "iam:PermissionsBoundary": "arn:aws:iam::*:policy/MaxPermissions"\n'
            "  },\n"
            '  "Bool": {"aws:MultiFactorAuthPresent": "true"}\n'
            "}"
        ),
    },
    "resource_exposure": {
        "suggestion": (
            "This action modifies resource policies. Use ABAC to prevent unauthorized changes:\n"
            "• Match principal tags to resource tags (aws:PrincipalTag/team = aws:ResourceTag/managed-by)\n"
            "• Restrict by environment (aws:ResourceTag/environment = development)\n"
            "• Prevent external access (aws:PrincipalOrgID)\n"
            "• Require approval tags (aws:RequestTag/change-approved = true)"
        ),
        "example": (
            '"Condition": {\n'
            '  "StringEquals": {\n'
            '    "aws:PrincipalTag/owner": "${aws:ResourceTag/managed-by}",\n'
            '    "aws:ResourceTag/environment": "${aws:PrincipalTag/environment}",\n'
            '    "aws:PrincipalOrgID": "o-xxxxxxxxxx"\n'
            "  }\n"
            "}"
        ),
        "action_overrides": {
            "s3:DeleteObject": {
                "suggestion": (
                    "This action permanently deletes S3 objects. Apply strict controls to prevent data loss:\n"
                    "• Restrict to organization buckets (`aws:ResourceOrgID` = `${aws:PrincipalOrgID}`)\n"
                    "• Ensure account ownership (`aws:ResourceAccount` = `${aws:PrincipalAccount}`)\n"
                    "• Require MFA for additional protection (`aws:MultiFactorAuthPresent` = `true`)\n"
                    "• Consider restricting to specific environments (`aws:ResourceTag/environment` != `production`)"
                ),
                "example": (
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:ResourceOrgID": "${aws:PrincipalOrgID}",\n'
                    '    "aws:ResourceAccount": "${aws:PrincipalAccount}"\n'
                    "  },\n"
                    '  "Bool": {"aws:MultiFactorAuthPresent": "true"}\n'
                    "}"
                ),
            },
            "s3:PutBucketPolicy": {
                "suggestion": (
                    "This action modifies S3 bucket policies, which can expose data to unauthorized parties. Strictly control policy changes:\n"
                    "• Require organization ownership (`aws:ResourceOrgID` = `${aws:PrincipalOrgID}`)\n"
                    "• Ensure account ownership (`aws:ResourceAccount` = `${aws:PrincipalAccount}`)\n"
                    "• Require MFA (`aws:MultiFactorAuthPresent` = `true`) - CRITICAL\n"
                    "• Restrict to administrative roles (`aws:PrincipalTag/role` = `security-admin`)"
                ),
                "example": (
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:ResourceOrgID": "${aws:PrincipalOrgID}",\n'
                    '    "aws:PrincipalTag/role": "security-admin"\n'
                    "  },\n"
                    '  "Bool": {"aws:MultiFactorAuthPresent": "true"}\n'
                    "}"
                ),
            },
            "ec2:RunInstances": {
                "suggestion": (
                    "This action launches EC2 instances, which can incur costs and create security risks. Control instance creation:\n"
                    "• Require resource tagging (`aws:RequestTag/owner`, `aws:RequestTag/environment`)\n"
                    "• Restrict instance types (`ec2:InstanceType`)\n"
                    "• Limit to specific VPCs (`ec2:Vpc`)\n"
                    "• Enforce encryption (`ec2:Encrypted` = `true`)\n"
                    "• Match principal tags to resource tags for ownership tracking"
                ),
                "example": (
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:RequestTag/owner": "${aws:PrincipalTag/owner}",\n'
                    '    "ec2:Vpc": "vpc-xxxxxxxxx"\n'
                    "  },\n"
                    '  "Bool": {"ec2:Encrypted": "true"}\n'
                    "}"
                ),
            },
        },
    },
}


def get_category_suggestions() -> dict[str, dict[str, Any]]:
    """
    Get default category suggestions.

    Returns:
        Dictionary mapping category IDs to suggestion/example dictionaries
    """
    return DEFAULT_CATEGORY_SUGGESTIONS.copy()

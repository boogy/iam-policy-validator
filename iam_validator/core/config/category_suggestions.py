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
    },
}


def get_category_suggestions() -> dict[str, dict[str, Any]]:
    """
    Get default category suggestions.

    Returns:
        Dictionary mapping category IDs to suggestion/example dictionaries
    """
    return DEFAULT_CATEGORY_SUGGESTIONS.copy()

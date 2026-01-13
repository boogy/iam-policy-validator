"""
Built-in policy checks for IAM Policy Validator.
"""

from iam_validator.checks.action_condition_enforcement import (
    ActionConditionEnforcementCheck,
)
from iam_validator.checks.action_resource_matching import ActionResourceMatchingCheck
from iam_validator.checks.action_validation import ActionValidationCheck
from iam_validator.checks.condition_key_validation import ConditionKeyValidationCheck
from iam_validator.checks.condition_type_mismatch import ConditionTypeMismatchCheck
from iam_validator.checks.full_wildcard import FullWildcardCheck
from iam_validator.checks.mfa_condition_check import MFAConditionCheck
from iam_validator.checks.not_action_not_resource import NotActionNotResourceCheck
from iam_validator.checks.policy_size import PolicySizeCheck
from iam_validator.checks.policy_structure import PolicyStructureCheck
from iam_validator.checks.principal_validation import PrincipalValidationCheck
from iam_validator.checks.resource_validation import ResourceValidationCheck
from iam_validator.checks.sensitive_action import SensitiveActionCheck
from iam_validator.checks.service_wildcard import ServiceWildcardCheck
from iam_validator.checks.set_operator_validation import SetOperatorValidationCheck
from iam_validator.checks.sid_uniqueness import SidUniquenessCheck
from iam_validator.checks.trust_policy_validation import TrustPolicyValidationCheck
from iam_validator.checks.wildcard_action import WildcardActionCheck
from iam_validator.checks.wildcard_resource import WildcardResourceCheck

__all__ = [
    "ActionConditionEnforcementCheck",
    "ActionResourceMatchingCheck",
    "ActionValidationCheck",
    "ConditionKeyValidationCheck",
    "ConditionTypeMismatchCheck",
    "FullWildcardCheck",
    "MFAConditionCheck",
    "NotActionNotResourceCheck",
    "PolicySizeCheck",
    "PolicyStructureCheck",
    "PrincipalValidationCheck",
    "ResourceValidationCheck",
    "SensitiveActionCheck",
    "ServiceWildcardCheck",
    "SetOperatorValidationCheck",
    "SidUniquenessCheck",
    "TrustPolicyValidationCheck",
    "WildcardActionCheck",
    "WildcardResourceCheck",
]

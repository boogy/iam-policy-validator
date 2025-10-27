"""
Built-in policy checks for IAM Policy Validator.
"""

from iam_validator.checks.action_condition_enforcement import (
    ActionConditionEnforcementCheck,
)
from iam_validator.checks.action_resource_constraint import ActionResourceConstraintCheck
from iam_validator.checks.action_validation import ActionValidationCheck
from iam_validator.checks.condition_key_validation import ConditionKeyValidationCheck
from iam_validator.checks.policy_size import PolicySizeCheck
from iam_validator.checks.resource_validation import ResourceValidationCheck
from iam_validator.checks.security_best_practices import SecurityBestPracticesCheck
from iam_validator.checks.sid_uniqueness import SidUniquenessCheck

__all__ = [
    "ActionConditionEnforcementCheck",
    "ActionResourceConstraintCheck",
    "ActionValidationCheck",
    "ConditionKeyValidationCheck",
    "PolicySizeCheck",
    "ResourceValidationCheck",
    "SecurityBestPracticesCheck",
    "SidUniquenessCheck",
]

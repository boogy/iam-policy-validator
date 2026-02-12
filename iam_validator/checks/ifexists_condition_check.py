"""IfExists Condition Usage Check.

Validates proper usage of the IfExists suffix on IAM condition operators.

Detects:
- IfExists on security-sensitive keys in Allow statements (may bypass controls)
- Non-negated IfExists in Deny statements (weakens the Deny)
- IfExists on always-present keys (redundant)
- Suggests IfExists for negated operators in Deny without it
"""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.condition_validators import (
    ALWAYS_PRESENT_CONDITION_KEYS,
    SECURITY_SENSITIVE_CONDITION_KEYS,
    has_if_exists_suffix,
    is_negated_operator,
    normalize_operator,
)
from iam_validator.core.models import Statement, ValidationIssue


class IfExistsConditionCheck(PolicyCheck):
    """Check for improper or risky usage of IfExists condition operators."""

    check_id: ClassVar[str] = "ifexists_condition_usage"
    description: ClassVar[str] = "Validates proper usage of IfExists suffix on condition operators"
    default_severity: ClassVar[str] = "warning"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute IfExists condition usage checks."""
        issues: list[ValidationIssue] = []

        if not statement.condition:
            return issues

        statement_sid = statement.sid
        line_number = statement.line_number
        effect = statement.effect

        # Config options
        warn_security_sensitive_allow = config.config.get("warn_security_sensitive_allow", True)
        suggest_deny_ifexists = config.config.get("suggest_deny_ifexists", False)
        warn_always_present_keys = config.config.get("warn_always_present_keys", True)
        additional_security_keys = config.config.get("additional_security_sensitive_keys", [])

        # Build the full set of security-sensitive keys
        security_keys = SECURITY_SENSITIVE_CONDITION_KEYS | frozenset(additional_security_keys)

        # Collect Null-checked keys for suppression (normalized to lowercase)
        null_checked_keys: set[str] = set()
        for op, conds in statement.condition.items():
            base_op, _, _ = normalize_operator(op)
            if base_op == "Null":
                for key, value in conds.items():
                    # Only suppress if Null checks for key presence (value = "false")
                    values = value if isinstance(value, list) else [value]
                    if any(str(v).lower() == "false" for v in values):
                        null_checked_keys.add(key.lower())

        for operator, conditions in statement.condition.items():
            has_ifexists = has_if_exists_suffix(operator)
            is_negated = is_negated_operator(operator)
            base_op, _, _ = normalize_operator(operator)

            for condition_key in conditions:
                # Normalize condition key for case-insensitive comparison
                key_lower = condition_key.lower()

                # Skip MFA key - handled by mfa_condition_antipattern check
                if key_lower == "aws:multifactorauthpresent":
                    continue

                if has_ifexists:
                    # IfExists on always-present keys is redundant
                    if warn_always_present_keys:
                        always_present_match = any(k.lower() == key_lower for k in ALWAYS_PRESENT_CONDITION_KEYS)
                        if always_present_match:
                            # Reconstruct the operator without IfExists for the message
                            raw_base = operator
                            if ":" in operator:
                                parts = operator.split(":", 1)
                                if parts[0] in ("ForAllValues", "ForAnyValue"):
                                    raw_base = parts[1]
                            base_without_ifexists = raw_base[:-8] if raw_base.endswith("IfExists") else raw_base
                            if ":" in operator:
                                parts = operator.split(":", 1)
                                if parts[0] in ("ForAllValues", "ForAnyValue"):
                                    base_without_ifexists = f"{parts[0]}:{base_without_ifexists}"

                            issues.append(
                                ValidationIssue(
                                    severity="info",
                                    message=(
                                        f"Redundant `IfExists`: The condition key "
                                        f"`{condition_key}` is always present in the "
                                        f"request context. Using `{operator}` has the "
                                        f"same effect as `{base_without_ifexists}` for "
                                        f"this key."
                                    ),
                                    statement_sid=statement_sid,
                                    statement_index=statement_idx,
                                    issue_type="ifexists_on_always_present_key",
                                    condition_key=condition_key,
                                    line_number=line_number,
                                    field_name="condition",
                                )
                            )

                    # Check if key is security-sensitive (case-insensitive)
                    is_security_key = any(k.lower() == key_lower for k in security_keys)

                    if effect == "Allow" and warn_security_sensitive_allow:
                        # IfExists on security-sensitive keys in Allow may bypass controls
                        if is_security_key:
                            # Check for complementary Null check (compare lowered)
                            if key_lower not in null_checked_keys:
                                issues.append(
                                    ValidationIssue(
                                        severity=self.get_severity(config),
                                        message=(
                                            f"Security control may be bypassed: "
                                            f"`{operator}` with `{condition_key}` in "
                                            f"an `Allow` statement means the restriction "
                                            f"is not enforced when the key is missing "
                                            f"from the request context. Not all API "
                                            f"calls include `{condition_key}` (e.g., "
                                            f"calls made by AWS services on your "
                                            f"behalf). Consider using the operator "
                                            f"without `IfExists` or adding a `Null` "
                                            f"condition check."
                                        ),
                                        statement_sid=statement_sid,
                                        statement_index=statement_idx,
                                        issue_type="ifexists_weakens_security_condition",
                                        condition_key=condition_key,
                                        line_number=line_number,
                                        field_name="condition",
                                    )
                                )

                    elif effect == "Deny":
                        # Non-negated IfExists in Deny weakens the restriction
                        if not is_negated and is_security_key:
                            if key_lower not in null_checked_keys:
                                issues.append(
                                    ValidationIssue(
                                        severity=self.get_severity(config),
                                        message=(
                                            f"Weakened `Deny`: `{operator}` with "
                                            f"`{condition_key}` in a `Deny` statement "
                                            f"means the `Deny` does not apply when "
                                            f"`{condition_key}` is missing from the "
                                            f"request context. Consider removing "
                                            f"`IfExists` or adding a `Null` condition "
                                            f"check."
                                        ),
                                        statement_sid=statement_sid,
                                        statement_index=statement_idx,
                                        issue_type="ifexists_weakens_deny",
                                        condition_key=condition_key,
                                        line_number=line_number,
                                        field_name="condition",
                                    )
                                )

                elif not has_ifexists and effect == "Deny" and suggest_deny_ifexists:
                    # Suggest IfExists for negated operator in Deny without it
                    if is_negated:
                        # Only suggest for keys that may be absent
                        is_always_present = any(k.lower() == key_lower for k in ALWAYS_PRESENT_CONDITION_KEYS)
                        is_security_key = any(k.lower() == key_lower for k in security_keys)
                        if not is_always_present and is_security_key:
                            issues.append(
                                ValidationIssue(
                                    severity="info",
                                    message=(
                                        f"Consider using `{base_op}IfExists` instead "
                                        f"of `{base_op}` in this Deny statement. "
                                        f"Without `IfExists`, the `Deny` does not apply "
                                        f"when `{condition_key}` is missing from the "
                                        f"request context. With `{base_op}IfExists`, "
                                        f"the `Deny` still applies even when the key is "
                                        f"absent."
                                    ),
                                    statement_sid=statement_sid,
                                    statement_index=statement_idx,
                                    issue_type="ifexists_deny_suggestion",
                                    condition_key=condition_key,
                                    line_number=line_number,
                                    field_name="condition",
                                )
                            )

        return issues

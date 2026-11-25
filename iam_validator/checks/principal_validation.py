"""Principal Validation Check.

Validates Principal elements in resource-based policies for security best practices.
This check enforces:
- Blocked principals (e.g., public access via "*")
- Service principal wildcards (e.g., {"Service": "*"} - extremely dangerous)
- Allowed principals whitelist (optional)
- Rich condition requirements for principals (supports any_of/all_of/none_of)
- Service principal validation

Only runs for RESOURCE_POLICY and TRUST_POLICY types. ``Effect: Deny`` statements are
skipped unless they use ``NotPrincipal``: a Deny over ``Principal`` cannot over-grant,
but ``NotPrincipal`` inverts the set, so a broad exception list is a real exposure.

Configuration format:

principal_condition_requirements:
  - principals:
      - "*"  # Can be a list of principal patterns
    severity: critical  # Optional: override default severity
    required_conditions:
      any_of:  # At least ONE of these conditions must be present
        - condition_key: "aws:SourceArn"
          description: "Limit by source ARN"
        - condition_key: "aws:SourceAccount"
          expected_value: "123456789012"  # Optional: validate specific value
          operator: "StringEquals"  # Optional: validate specific operator

  - principals:
      - "arn:aws:iam::*:root"
    required_conditions:
      all_of:  # ALL of these conditions must be present
        - condition_key: "aws:PrincipalOrgID"
          expected_value: "o-xxxxx"
        - condition_key: "aws:SourceAccount"

Supports: any_of, all_of, none_of, and expected_value (single value or list)
"""

import fnmatch
from collections.abc import Callable
from functools import partial
from typing import Any, ClassVar

from iam_validator.checks.utils import format_list_with_backticks
from iam_validator.checks.utils.condition_matching import (
    has_condition_key,
    is_deny,
    is_negated_operator,
)
from iam_validator.checks.utils.finding_identity import (
    PRESENTATION_KEYS,
    keep_most_severe,
    rule_key,
    severity_problem_key,
    unordered,
)
from iam_validator.checks.utils.requirement_branches import (
    CONDITION_GROUPS,
    VALID_SEVERITIES,
    describe_entry,
    has_no_conditions,
    is_evaluable_entry,
    severity_problem,
    without_null_all_of,
)
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.condition_validators import is_operator_supports_wildcards
from iam_validator.core.config.service_principals import is_aws_service_principal
from iam_validator.core.constants import ACCOUNT_ID_PATTERN, ARN_PARTITIONS, ROOT_ARN_PATTERN
from iam_validator.core.models import IAMPolicy, Statement, ValidationIssue

_Render = Callable[[list[str]], ValidationIssue]


def _dedupe(issues: list[ValidationIssue]) -> list[ValidationIssue]:
    """``issues`` without repeats of the same finding, the most severe kept."""
    return keep_most_severe(
        issues,
        lambda i: (
            i.issue_type,
            i.statement_index,
            i.condition_key,
            i.finding_key,
            i.message if i.finding_key is None else None,
        ),
    )


def principal_spellings(principal: str) -> list[str]:
    """Every way AWS lets you name ``principal``, itself first.

    A bare account id and that account's root ARN are the same principal to AWS, so a
    denylist or allowlist entry written one way must match the other.
    """
    candidate = principal.strip()

    root_arn = ROOT_ARN_PATTERN.match(candidate)
    if root_arn:
        return [principal, root_arn.group(2)]

    if ACCOUNT_ID_PATTERN.match(candidate):
        return [principal, *(f"arn:{p}:iam::{candidate}:root" for p in ARN_PARTITIONS)]

    return [principal]


class PrincipalValidationCheck(PolicyCheck):
    """Validates Principal elements in resource policies."""

    check_id: ClassVar[str] = "principal_validation"
    description: ClassVar[str] = "Validates Principal elements in resource policies for security best practices"
    default_severity: ClassVar[str] = "high"
    # RCPs require Principal: "*" by AWS syntax rule, so wildcard-principal findings are structural noise there.
    applies_to_policy_types: ClassVar[frozenset[str] | None] = frozenset(
        {"IDENTITY_POLICY", "RESOURCE_POLICY", "TRUST_POLICY", "SERVICE_CONTROL_POLICY"}
    )

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute principal validation on a single statement.

        Args:
            statement: The statement to validate
            statement_idx: Index of the statement in the policy
            fetcher: AWS service fetcher instance
            config: Configuration for this check

        Returns:
            List of validation issues
        """
        issues: list[ValidationIssue] = []

        # Skip if no principal
        if statement.principal is None and statement.not_principal is None:
            return issues

        # A Deny over Principal grants nothing, so the rules below do not apply -- except
        # that an inverted Deny carves principals *out* of the deny, and a carve-out of
        # "*" denies nobody. NotPrincipal spells that inversion with a principal, and
        # ArnNotEquals & friends spell it with a condition; both forms are checked here.
        if is_deny(statement):
            if statement.not_principal is None:
                return self._check_deny_carve_out(statement, statement_idx, config)
            # NotPrincipal still falls through to the blocked/allowed rules below.
            issues.extend(self._check_not_principal_carve_out(statement, statement_idx, config))

        # Get configuration (defaults match defaults.py)
        blocked_principals = self._blocked_principals(config)
        raw_allowed = config.config.get("allowed_principals", [])
        allowlist_configured = raw_allowed not in (None, [], "")
        allowed_principals = self._string_entries(raw_allowed)
        principal_condition_requirements = self._requirement_entries(config)
        # Default: "aws:*" allows ALL AWS service principals (*.amazonaws.com)
        # This matches the default in defaults.py
        raw_services = config.config.get("allowed_service_principals")
        allowed_service_principals = self._string_entries(["aws:*"] if raw_services is None else raw_services)
        # Check for service principal wildcards FIRST (highest priority security issue)
        service_wildcard_issues: list[ValidationIssue] = []
        if config.config.get("block_service_principal_wildcard", True):
            service_wildcard_issues = self._check_service_principal_wildcards(statement, statement_idx, config)
            issues.extend(service_wildcard_issues)

        # Extract principals from statement
        principals = self._extract_principals(statement)

        # Skip only the "*" entries of a {"Service": "*"} already reported above
        service_wildcards = self._service_principal_wildcard_count(statement) if service_wildcard_issues else 0

        for principal in principals:
            if principal == "*" and service_wildcards:
                service_wildcards -= 1
                continue

            # Check if principal is blocked
            if self._is_blocked_principal(principal, blocked_principals):
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        issue_type="blocked_principal",
                        message=f"Blocked principal detected: `{principal}`. "
                        f"This principal is explicitly blocked by your security policy.",
                        statement_index=statement_idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion=f"Remove the `Principal` `{principal}` or add appropriate `Condition`s to restrict access. "
                        "Consider using more specific `Principal`s instead of `*` (wildcard).",
                        field_name="principal",
                        finding_key=principal,
                    )
                )
                continue

            # Check if principal is in whitelist (if whitelist is configured)
            if allowlist_configured and not self._is_allowed_principal(
                principal, allowed_principals, allowed_service_principals
            ):
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        issue_type="unauthorized_principal",
                        message=f"`Principal` not in allowed list: `{principal}`. "
                        f"Only principals in the `allowed_principals` allow-list are permitted.",
                        statement_index=statement_idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion=f"Add `{principal}` to the `allowed_principals` list in your config, "
                        "or use a `Principal` that matches an allowed pattern.",
                        field_name="principal",
                        finding_key=principal,
                    )
                )
                continue

        if principal_condition_requirements:
            principals_to_check = self._condition_requirement_principals(statement, config)
            if principals_to_check:
                condition_issues = self._validate_principal_condition_requirements(
                    statement,
                    statement_idx,
                    principals_to_check,
                    principal_condition_requirements,
                    config,
                )
                issues.extend(condition_issues)

        return _dedupe(issues)

    async def execute_policy(
        self,
        policy: IAMPolicy,
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs: Any,
    ) -> list[ValidationIssue]:
        """Report requirement-level config problems once per policy, for policies ``execute`` would evaluate."""
        del policy_file, fetcher, kwargs
        return _dedupe(self._policy_problems(policy, config))

    def _policy_problems(self, policy: IAMPolicy, config: CheckConfig) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        if any(self._reaches_principal_rules(statement) for statement in policy.statement or []):
            issues.extend(
                self._create_non_string_principal_issue(f"`{key}`", entry, whole_value=not isinstance(value, list))
                for key in self._PRINCIPAL_LIST_KEYS
                for value in [config.config.get(key)]
                for entry in self._non_string_entries(value)
            )
        evaluated = [
            principals
            for statement in policy.statement or []
            if (principals := self._condition_requirement_principals(statement, config))
        ]
        if not evaluated:
            return issues
        raw_requirements = config.config.get("principal_condition_requirements")
        if raw_requirements is not None and not isinstance(raw_requirements, list):
            issues.append(self._create_invalid_requirement_entry_issue(raw_requirements, "is not a list"))
        elif isinstance(raw_requirements, list):
            issues.extend(
                self._create_invalid_requirement_entry_issue(entry, "has an entry that is not a mapping")
                for entry in raw_requirements
                if not isinstance(entry, dict)
            )
        for requirement in self._requirement_entries(config):
            patterns = self._principal_patterns(requirement)
            if patterns is None:
                issues.append(self._create_invalid_principals_issue(requirement))
                continue
            non_string = self._non_string_entries(requirement.get("principals"))
            if (patterns or not non_string) and not any(
                self._get_matching_principals(principals, requirement) for principals in evaluated
            ):
                continue
            issues.extend(
                self._create_non_string_principal_issue("`principal_condition_requirements` `principals`", entry)
                for entry in non_string
            )
            if not patterns and non_string:
                continue
            conditions = requirement.get("required_conditions")
            if has_no_conditions(conditions):
                continue
            severity = requirement.get("severity")
            if severity_problem(severity) is not None:
                issues.append(self._create_invalid_severity_issue(requirement, severity, "", requirement))
            issues.extend(self._prepare_conditions(conditions, requirement)[1])
        return issues

    _PRINCIPAL_LIST_KEYS: ClassVar[tuple[str, ...]] = (
        "blocked_principals",
        "allowed_principals",
        "allowed_service_principals",
    )

    @staticmethod
    def _string_entries(value: Any) -> list[str]:
        """A configured principal list's string entries (a string is one entry); ``execute_policy`` reports the rest."""
        if isinstance(value, str):
            return [value]
        return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []

    @staticmethod
    def _non_string_entries(value: Any) -> list[Any]:
        """A principal list's non-string entries; a non-list, non-string value is one bad entry."""
        if value is None or isinstance(value, str):
            return []
        return [v for v in value if not isinstance(v, str)] if isinstance(value, list) else [value]

    @staticmethod
    def _requirement_entries(config: CheckConfig) -> list[dict[str, Any]]:
        """The mapping entries of ``principal_condition_requirements``; ``execute_policy`` reports the rest."""
        value = config.config.get("principal_condition_requirements")
        return [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []

    @staticmethod
    def _reaches_principal_rules(statement: Statement) -> bool:
        """Whether ``execute`` applies the blocked/allowed principal rules to ``statement``."""
        if statement.principal is None and statement.not_principal is None:
            return False
        return not (is_deny(statement) and statement.not_principal is None)

    @classmethod
    def _blocked_principals(cls, config: CheckConfig) -> list[str]:
        blocked = cls._string_entries(config.config.get("blocked_principals", []))
        if config.config.get("block_wildcard_principal", False) and "*" not in blocked:
            blocked.append("*")
        return blocked

    def _condition_requirement_principals(self, statement: Statement, config: CheckConfig) -> list[str]:
        """Principals ``execute`` checks against ``principal_condition_requirements``; ``[]`` when it skips them."""
        if not self._reaches_principal_rules(statement):
            return []
        if config.config.get("block_service_principal_wildcard", True) and self._service_principal_wildcard_count(
            statement
        ):
            return []
        blocked = self._blocked_principals(config)
        return [p for p in self._extract_principals(statement) if not self._is_blocked_principal(p, blocked)]

    @classmethod
    def _rule_key(cls, kind: str, requirement: dict[str, Any], *parts: Any) -> str:
        """A ``finding_key`` for a requirement rule, independent of message wording and matching principals."""
        return rule_key(kind, sorted(set(cls._principal_patterns(requirement) or [])), *parts)

    @classmethod
    def _principal_patterns(cls, requirement: dict[str, Any]) -> list[str] | None:
        """A requirement's string ``principals`` (a string is one pattern); ``None`` when not a string or list."""
        patterns = requirement.get("principals")
        if patterns is None:
            return []
        if isinstance(patterns, str | list):
            return cls._string_entries(patterns)
        return None

    #: Condition keys that identify *who* the caller is, as opposed to what they request.
    _PRINCIPAL_CONDITION_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "aws:principalarn",
            "aws:principalaccount",
            "aws:principalorgid",
            "aws:principalorgpaths",
            "aws:principalservicename",
            "aws:principaltype",
            "aws:principalisawsservice",
            "aws:userid",
            "aws:username",
        }
    )

    @classmethod
    def _is_principal_condition_key(cls, key: str) -> bool:
        normalized = key.strip().lower()
        return normalized in cls._PRINCIPAL_CONDITION_KEYS or normalized.startswith("aws:principaltag/")

    def _check_not_principal_carve_out(
        self,
        statement: Statement,
        statement_idx: int,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Flag a ``Deny`` whose ``NotPrincipal`` carve-out is ``"*"``.

        ``NotPrincipal`` exempts the principals it lists from the deny, and ``"*"`` is the
        one wildcard AWS resolves in a principal -- it matches everyone, so no principal is
        left outside the carve-out and the statement denies nothing. This is the
        principal-spelled form of ``ineffective_deny_carve_out``.
        """
        if not any(str(p).strip() == "*" for p in self._extract_not_principals(statement)):
            return []

        return [
            ValidationIssue(
                severity=self.get_severity(config),
                statement_sid=statement.sid,
                statement_index=statement_idx,
                issue_type="ineffective_deny_carve_out",
                message=(
                    "`NotPrincipal` is `*`, which exempts every principal from this `Deny`. "
                    "The statement denies nothing."
                ),
                suggestion=(
                    "List the specific principals that must be exempt, or drop the statement if "
                    'nothing should be denied. AWS recommends `Principal: "*"` with an '
                    "`ArnNotEquals` condition on `aws:PrincipalArn` instead of `NotPrincipal`."
                ),
                line_number=statement.line_number,
                field_name="principal",
            )
        ]

    def _check_deny_carve_out(
        self,
        statement: Statement,
        statement_idx: int,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Flag an inverted Deny whose principal carve-out is ``"*"``.

        A wildcard-capable operator (``ArnNotEquals``, ``StringNotLike``) exempts every
        principal, so the deny denies nothing. A literal operator (``StringNotEquals``)
        matches no principal, so the carve-out exempts nobody.
        """
        if not statement.condition:
            return []

        for operator, entries in statement.condition.items():
            if not is_negated_operator(operator) or not isinstance(entries, dict):
                continue
            for key, value in entries.items():
                if not self._is_principal_condition_key(key):
                    continue
                values = value if isinstance(value, list) else [value]
                wildcards = [v for v in values if str(v).strip() == "*"]
                if not wildcards:
                    continue
                if not is_operator_supports_wildcards(operator):
                    # Another AND-ed condition, or ForAnyValue on a missing key, may still exempt principals.
                    denies_everyone = (
                        self._names_every_principal(statement)
                        and len(wildcards) == len(values)
                        and self._condition_key_count(statement) == 1
                        and not operator.lower().startswith("foranyvalue:")
                    )
                    return [
                        ValidationIssue(
                            severity=self.get_severity(config),
                            statement_sid=statement.sid,
                            statement_index=statement_idx,
                            issue_type="literal_wildcard_deny_carve_out",
                            message=(
                                f"`{operator}` compares `*` on `{key}` literally, so the `*` value exempts no principal"
                                + (" and the `Deny` applies to every principal." if denies_everyone else ".")
                            ),
                            suggestion=(
                                "Use a wildcard-capable operator (`StringNotLike`, or `ArnNotLike` for "
                                "ARNs) if `*` is meant as a pattern, or list the exact values to exempt."
                            ),
                            line_number=statement.line_number,
                            field_name="condition",
                        )
                    ]
                return [
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="ineffective_deny_carve_out",
                        message=(
                            f"`Deny` carve-out `{operator}` on `{key}` is `*`, which exempts every "
                            "principal from the deny. The statement denies nothing."
                        ),
                        suggestion=(
                            "Replace `*` with the specific principals that must be exempt, or remove "
                            f"the `{key}` condition if nothing should be exempt."
                        ),
                        line_number=statement.line_number,
                        field_name="condition",
                    )
                ]
        return []

    @staticmethod
    def _condition_key_count(statement: Statement) -> int:
        """Number of condition keys tested; a non-dict operator entry counts as one."""
        return sum(len(e) if isinstance(e, dict) else 1 for e in (statement.condition or {}).values())

    @staticmethod
    def _names_every_principal(statement: Statement) -> bool:
        """True for ``Principal: "*"`` or an ``AWS`` principal of ``"*"``."""
        principal = statement.principal
        if principal == "*":
            return True
        if not isinstance(principal, dict):
            return False
        aws = principal.get("AWS")
        return aws == "*" or (isinstance(aws, list) and "*" in aws)

    def _extract_principals(self, statement: Statement) -> list[str]:
        """Extract all principals from a statement.

        Args:
            statement: The statement to extract principals from

        Returns:
            List of principal strings
        """
        return self._flatten_principal_field(statement.principal) + self._extract_not_principals(statement)

    def _extract_not_principals(self, statement: Statement) -> list[str]:
        """Extract the principals a statement's `NotPrincipal` carves out."""
        return self._flatten_principal_field(statement.not_principal)

    @staticmethod
    def _flatten_principal_field(field: object) -> list[str]:
        """Flatten a `Principal`/`NotPrincipal` value (string, or dict of string/list) to a flat list."""
        if not field:
            return []
        if isinstance(field, str):
            return [field]
        if not isinstance(field, dict):
            return []

        principals: list[str] = []
        for value in field.values():
            if isinstance(value, str):
                principals.append(value)
            elif isinstance(value, list):
                principals.extend(v for v in value if isinstance(v, str))
        return principals

    @staticmethod
    def _service_principal_wildcard_count(statement: Statement) -> int:
        """Number of ``"*"`` values under ``Principal.Service``."""
        if not isinstance(statement.principal, dict):
            return 0
        service = statement.principal.get("Service")
        if isinstance(service, str):
            return int(service == "*")
        if isinstance(service, list):
            return service.count("*")
        return 0

    def _check_service_principal_wildcards(
        self,
        statement: Statement,
        statement_idx: int,
        _config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Check for dangerous service principal wildcards in Principal field.

        Detects patterns like:
        - "Principal": {"Service": "*"}
        - "Principal": {"Service": ["*"]}
        - "Principal": {"Service": ["lambda.amazonaws.com", "*"]}

        These are dangerous because they allow ANY AWS service to access the resource
        or assume the role. Without proper source verification conditions (aws:SourceArn,
        aws:SourceAccount), any service in any account could potentially access the resource.

        Note: NotPrincipal with {"Service": "*"} is NOT flagged here because it means
        "allow everyone EXCEPT all services" - a different concern (overly broad exclusion)
        but not an overly permissive grant.

        Args:
            statement: The statement to check
            statement_idx: Index of the statement
            config: Check configuration

        Returns:
            List of validation issues
        """
        issues: list[ValidationIssue] = []

        # Only check Principal field (not NotPrincipal)
        # NotPrincipal: {"Service": "*"} means "everyone EXCEPT services" which is
        # a different concern (overly broad exclusion) but not an overly permissive grant
        if statement.principal is None:
            return issues

        if not isinstance(statement.principal, dict):
            return issues

        # Check the "Service" key specifically
        service_principals = statement.principal.get("Service")
        if service_principals is None:
            return issues

        # Normalize to list
        if isinstance(service_principals, str):
            service_principals = [service_principals]

        # Check for wildcard in service principals
        for service_principal in service_principals:
            if service_principal == "*":
                issues.append(
                    ValidationIssue(
                        severity="critical",  # Always critical - extremely permissive
                        issue_type="service_principal_wildcard",
                        message=(
                            'Dangerous service principal wildcard: `"Principal": {"Service": "*"}`. '
                            "This allows ANY AWS service to access this resource or assume this role. "
                            "Without source verification conditions, this creates an overly permissive "
                            "trust relationship."
                        ),
                        statement_index=statement_idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion=(
                            "Replace the wildcard with specific AWS service principals and add "
                            "source verification conditions:\n\n"
                            "1. Specify exact services:\n"
                            '   `"Principal": {"Service": "lambda.amazonaws.com"}`\n\n'
                            "2. Add source conditions:\n"
                            "```json\n"
                            '   "Condition": {\n'
                            '     "ArnLike": {"aws:SourceArn": "arn:aws:lambda:*:ACCOUNT:function:*"},\n'
                            '     "StringEquals": {"aws:SourceAccount": "ACCOUNT"}\n\n'
                            "   }\n"
                            "```\n"
                        ),
                        field_name="principal",
                    )
                )
                break  # One issue is enough

        return issues

    def _is_blocked_principal(self, principal: str, blocked_list: list[str]) -> bool:
        """Check if a principal is blocked.

        Args:
            principal: The principal to check
            blocked_list: List of blocked principal patterns

        Returns:
            True if the principal is blocked
        """
        # blocked_principals is a denylist: no service allowlist entry exempts a match.
        spellings = principal_spellings(principal)
        for blocked_pattern in blocked_list:
            # "*" in the blocked list matches only literal "*" (public access), not everything
            if blocked_pattern == "*":
                if principal == "*":
                    return True
            elif any(fnmatch.fnmatch(spelling, blocked_pattern) for spelling in spellings):
                return True

        return False

    def _is_allowed_principal(self, principal: str, allowed_list: list[str], service_whitelist: list[str]) -> bool:
        """Check if a principal is in the allowed list.

        Args:
            principal: The principal to check
            allowed_list: List of allowed principal patterns
            service_whitelist: List of allowed service principals (supports "aws:*" for all AWS services)

        Returns:
            True if the principal is allowed
        """
        # Check if service_whitelist contains "aws:*" (allow all AWS service principals)
        if "aws:*" in service_whitelist and is_aws_service_principal(principal):
            return True

        # Service principals in explicit whitelist are always allowed
        if is_aws_service_principal(principal) and principal in service_whitelist:
            return True

        # Check against allowed list (supports wildcards)
        spellings = principal_spellings(principal)
        for allowed_pattern in allowed_list:
            # Special case: "*" in allowed list should only match literal "*" (public access)
            # not use it as a wildcard pattern that matches everything
            if allowed_pattern == "*":
                if principal == "*":
                    return True
            elif any(fnmatch.fnmatch(spelling, allowed_pattern) for spelling in spellings):
                return True

        return False

    def _validate_principal_condition_requirements(
        self,
        statement: Statement,
        statement_idx: int,
        principals: list[str],
        requirements: list[dict[str, Any]],
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Validate advanced principal condition requirements.

        Args:
            statement: The statement to validate
            statement_idx: Index of the statement
            principals: List of principals from the statement
            requirements: List of principal condition requirements
            config: Check configuration

        Returns:
            List of validation issues
        """
        best: dict[tuple[Any, ...], tuple[_Render, int, set[str]]] = {}

        for requirement in requirements:
            # Check if any principal matches this requirement
            matching_principals = self._get_matching_principals(principals, requirement)

            if not matching_principals:
                continue

            # Get required conditions from the requirement
            required_conditions_config = requirement.get("required_conditions")
            if has_no_conditions(required_conditions_config):
                continue

            for render in self._validate_conditions(
                statement, statement_idx, required_conditions_config, config, requirement
            ):
                sample = render(matching_principals)
                if sample.severity == "none" or not config.should_show_severity(sample.severity):
                    continue
                key = (sample.issue_type, sample.condition_key, sample.finding_key)
                rank = sample.get_severity_rank()
                current = best.get(key)
                if current is None:
                    best[key] = (render, rank, set(matching_principals))
                    continue
                current[2].update(matching_principals)
                if rank > current[1]:
                    best[key] = (render, rank, current[2])

        issues: list[ValidationIssue] = []
        for render, _, matched in best.values():
            issue = render([p for p in dict.fromkeys(principals) if p in matched])
            if "*" in matched:
                issue.finding_key = rule_key(issue.finding_key, "public")
            issues.append(issue)
        return issues

    def _get_matching_principals(self, principals: list[str], requirement: dict[str, Any]) -> list[str]:
        """Get principals that match the requirement pattern.

        Args:
            principals: List of principals from the statement
            requirement: Principal condition requirement config

        Returns:
            List of matching principals
        """
        principal_patterns = self._principal_patterns(requirement)
        if not principal_patterns:
            return []

        def matches(principal: str, pattern: str) -> bool:
            if pattern == "*":
                return principal == "*"
            return any(fnmatch.fnmatch(spelling, pattern) for spelling in principal_spellings(principal))

        return list(dict.fromkeys(p for p in principals if any(matches(p, pattern) for pattern in principal_patterns)))

    def _validate_conditions(
        self,
        statement: Statement,
        statement_idx: int,
        required_conditions_config: Any,
        config: CheckConfig,
        requirement: dict[str, Any],
    ) -> list[_Render]:
        """One renderer per unmet condition requirement, taking the matched principals to name.

        Supports: simple list, all_of, any_of, none_of formats.
        """
        renders: list[_Render] = []
        groups, _ = self._prepare_conditions(required_conditions_config, requirement)

        for requirement_type in ("required", "all_of"):
            for condition_requirement in groups.get(requirement_type, []):
                if not self._has_condition_requirement(statement, condition_requirement):
                    renders.append(
                        partial(
                            self._create_condition_issue,
                            statement,
                            statement_idx,
                            condition_requirement,
                            config=config,
                            requirement=requirement,
                            requirement_type=requirement_type,
                        )
                    )

        any_of = groups.get("any_of", [])
        if any_of and not any(self._has_condition_requirement(statement, cond_req) for cond_req in any_of):
            condition_keys = ", ".join(describe_entry(cond) for cond in any_of)
            severity = self._severity(config, requirement)
            suggestion = self._build_any_of_suggestion(any_of)

            def render_any_of(matching_principals: list[str]) -> ValidationIssue:
                return ValidationIssue(
                    severity=severity,
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="missing_principal_condition_any_of",
                    message=(
                        f"`Principal`s {format_list_with_backticks(matching_principals)} require at least ONE of "
                        f"these conditions: {condition_keys}"
                    ),
                    suggestion=suggestion,
                    line_number=statement.line_number,
                    field_name="principal",
                    finding_key=rule_key("any_of", unordered(any_of)),
                )

            renders.append(render_any_of)

        for condition_requirement in groups.get("none_of", []):
            if self._has_condition_requirement(statement, condition_requirement):
                renders.append(
                    partial(
                        self._create_none_of_condition_issue,
                        statement,
                        statement_idx,
                        condition_requirement,
                        config=config,
                        requirement=requirement,
                    )
                )

        return renders

    def _prepare_conditions(
        self, required_conditions_config: Any, requirement: dict[str, Any]
    ) -> tuple[dict[str, list[dict[str, Any]]], list[ValidationIssue]]:
        """Split ``required_conditions`` into evaluable groups and the config problems found in it."""
        problems: list[ValidationIssue] = []

        def report_entry_severities(entry: dict[str, Any], label: str) -> None:
            severity = entry.get("severity")
            if severity_problem(severity) is not None:
                problems.append(
                    self._create_invalid_severity_issue(requirement, severity, f"an entry under `{label}`", entry)
                )
            for nested in entry.get("all_of", []):
                report_entry_severities(nested, f"{label}.all_of")

        def entries(value: Any, label: str) -> list[dict[str, Any]]:
            if not isinstance(value, list):
                if value is not None:
                    problems.append(
                        self._create_invalid_entry_issue(requirement, value, "a list", kind="group", where=label)
                    )
                return []
            enforceable: list[dict[str, Any]] = []
            for item in value:
                if is_evaluable_entry(item):
                    item = without_null_all_of(item)
                    report_entry_severities(item, label)
                    enforceable.append(item)
                elif not isinstance(item, dict):
                    problems.append(self._create_invalid_entry_issue(requirement, item, "a mapping", where=label))
                else:
                    problems.append(
                        self._create_invalid_entry_issue(
                            requirement,
                            item,
                            "a mapping with a string `condition_key` (and a string `operator`, if set) "
                            "or a non-empty `all_of` list of them",
                            where=label,
                        )
                    )
            return enforceable

        if isinstance(required_conditions_config, list):
            return {"required": self._leaves(entries(required_conditions_config, "required_conditions"))}, problems
        if not isinstance(required_conditions_config, dict):
            problems.append(
                self._create_invalid_entry_issue(
                    requirement, required_conditions_config, "a list or mapping", kind="conditions"
                )
            )
            return {}, problems
        problems.extend(
            self._create_invalid_entry_issue(requirement, unknown, "`all_of`, `any_of` or `none_of`", kind="group_key")
            for unknown in sorted(required_conditions_config.keys() - set(CONDITION_GROUPS), key=str)
        )
        groups = {
            "all_of": self._leaves(entries(required_conditions_config.get("all_of"), "all_of")),
            "any_of": entries(required_conditions_config.get("any_of"), "any_of"),
            "none_of": entries(required_conditions_config.get("none_of"), "none_of"),
        }
        return groups, problems

    @staticmethod
    def _create_invalid_severity_issue(
        requirement: dict[str, Any], severity: Any, where: str, node: dict[str, Any]
    ) -> ValidationIssue:
        patterns = PrincipalValidationCheck._principal_patterns(requirement) or []
        principals = format_list_with_backticks([str(p) for p in patterns])
        located = f" in {where}" if where else ""
        fallback = "the enclosing severity" if where else "the check severity"
        return ValidationIssue(
            severity="error",
            statement_sid=None,
            statement_index=-1,
            issue_type="invalid_condition_requirement",
            message=(
                f"`principal_condition_requirements` entry for principal(s) {principals} has an invalid "
                f"`severity` `{severity!r}`{located}; its findings use {fallback} instead"
            ),
            suggestion=f"Set `severity` to one of {', '.join(sorted(VALID_SEVERITIES))}, or remove it.",
            field_name="principal",
            finding_key=PrincipalValidationCheck._rule_key(
                "severity", requirement, where, severity, severity_problem_key(node)
            ),
        )

    @staticmethod
    def _create_invalid_principals_issue(requirement: dict[str, Any]) -> ValidationIssue:
        return ValidationIssue(
            severity="error",
            statement_sid=None,
            statement_index=-1,
            issue_type="invalid_condition_requirement",
            message=(
                f"`principal_condition_requirements` entry has a `principals` value `{requirement.get('principals')!r}` "
                "that is not a string or list, so it matches no principal and is not enforced"
            ),
            suggestion='Set `principals` to a principal pattern or a list of them (e.g. `- "*"`).',
            line_number=None,
            field_name="principal",
            finding_key=rule_key("principals", repr(requirement.get("principals"))),
        )

    @staticmethod
    def _create_non_string_principal_issue(label: str, entry: Any, *, whole_value: bool = False) -> ValidationIssue:
        message = (
            f"{label} is not a string or list: `{entry!r}`; it matches no principal"
            if whole_value
            else f"{label} has a non-string entry `{entry!r}`, which matches no principal and is ignored"
        )
        return ValidationIssue(
            severity="error",
            statement_sid=None,
            statement_index=-1,
            issue_type="invalid_condition_requirement",
            message=message,
            suggestion=(
                'Quote the entry as a string (e.g. `"123456789012"`); YAML reads an unquoted account id as a '
                "number and drops its leading zeros."
            ),
            line_number=None,
            field_name="principal",
            finding_key=rule_key("non_string_principal", label, repr(entry), whole_value),
        )

    @staticmethod
    def _create_invalid_requirement_entry_issue(entry: Any, problem: str) -> ValidationIssue:
        return ValidationIssue(
            severity="error",
            statement_sid=None,
            statement_index=-1,
            issue_type="invalid_condition_requirement",
            message=f"`principal_condition_requirements` {problem}, so it is not enforced: `{entry!r}`",
            suggestion="Make `principal_condition_requirements` a list of mappings, each with `principals` and "
            "`required_conditions`.",
            line_number=None,
            field_name="principal",
            finding_key=rule_key("requirement_entry", problem, repr(entry)),
        )

    @staticmethod
    def _create_invalid_entry_issue(
        requirement: dict[str, Any], entry: Any, expected: str, *, kind: str = "entry", where: str | None = None
    ) -> ValidationIssue:
        patterns = PrincipalValidationCheck._principal_patterns(requirement) or []
        principals = format_list_with_backticks([str(p) for p in patterns])
        field = "required_conditions" if where in (None, "required_conditions") else f"required_conditions.{where}"
        return ValidationIssue(
            severity="error",
            statement_sid=None,
            statement_index=-1,
            issue_type="invalid_condition_requirement",
            message=(
                f"`principal_condition_requirements` entry for principal(s) {principals} has a "
                f"`{field}` value `{entry!r}` that is not {expected}, so it is not enforced"
            ),
            suggestion=(
                "Use a list of mappings (e.g. `- condition_key: aws:SourceArn`), or an `all_of`/`any_of`/`none_of` "
                "mapping of such lists."
            ),
            line_number=None,
            field_name="principal",
            finding_key=PrincipalValidationCheck._rule_key(kind, requirement, where, repr(entry)),
        )

    @classmethod
    def _leaves(cls, entries: list[dict[str, Any]], inherited: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """``entries`` with each nested ``all_of`` replaced by its leaves, which inherit the parent's presentation."""
        leaves: list[dict[str, Any]] = []
        for entry in entries:
            own = {**(inherited or {}), **{k: entry[k] for k in PRESENTATION_KEYS if cls._is_set(k, entry.get(k))}}
            leaves.extend(cls._leaves(entry["all_of"], own) if "all_of" in entry else [{**entry, **own}])
        return leaves

    @staticmethod
    def _is_set(key: str, value: Any) -> bool:
        return value is not None and (key != "severity" or severity_problem(value) is None)

    def _severity(self, config: CheckConfig, *nodes: dict[str, Any]) -> str:
        """The first valid ``severity`` among ``nodes``, else the check severity."""
        for node in nodes:
            severity = node.get("severity")
            if severity is not None and severity_problem(severity) is None:
                return severity
        return self.get_severity(config)

    def _has_condition_requirement(self, statement: Statement, condition_requirement: dict[str, Any]) -> bool:
        """Check if statement has the required condition.

        Args:
            statement: The statement to check
            condition_requirement: Condition requirement config

        Returns:
            True if condition is present and matches requirements
        """
        if "all_of" in condition_requirement:
            return all(self._has_condition_requirement(statement, nested) for nested in condition_requirement["all_of"])
        condition_key = condition_requirement.get("condition_key")
        if not isinstance(condition_key, str) or not condition_key:
            return False

        operator = condition_requirement.get("operator")
        expected_value = condition_requirement.get("expected_value")

        return has_condition_key(statement, condition_key, operator, expected_value)

    def _create_condition_issue(
        self,
        statement: Statement,
        statement_idx: int,
        condition_requirement: dict[str, Any],
        matching_principals: list[str],
        *,
        config: CheckConfig,
        requirement: dict[str, Any],
        requirement_type: str = "required",
    ) -> ValidationIssue:
        """Create a validation issue for a missing condition.

        Severity precedence:
        1. Individual condition requirement's severity (condition_requirement['severity'])
        2. Parent requirement's severity (requirement['severity'])
        3. Global check severity (config.severity)

        Args:
            statement: The statement being validated
            statement_idx: Index of the statement
            condition_requirement: The condition requirement config
            matching_principals: Principals that matched
            config: Check configuration
            requirement: Parent requirement config
            requirement_type: Type of requirement (required, all_of)

        Returns:
            ValidationIssue
        """
        condition_key = condition_requirement.get("condition_key", "unknown")
        description = condition_requirement.get("description", "")
        expected_value = condition_requirement.get("expected_value")
        example = condition_requirement.get("example", "")
        operator = condition_requirement.get("operator") or "StringEquals"

        message_prefix = "ALL required:" if requirement_type == "all_of" else "Required:"

        # Determine severity with precedence: condition > requirement > global
        severity = self._severity(config, condition_requirement, requirement)

        suggestion_text, example_code = self._build_condition_suggestion(
            condition_key, description, example, expected_value, operator
        )

        return ValidationIssue(
            severity=severity,
            statement_sid=statement.sid,
            statement_index=statement_idx,
            issue_type="missing_principal_condition",
            condition_key=condition_key,
            message=f"{message_prefix} Principal(s) {format_list_with_backticks(matching_principals)} require condition `{condition_key}`",
            suggestion=suggestion_text,
            example=example_code,
            line_number=statement.line_number,
            field_name="principal",
            finding_key=rule_key("required", condition_requirement),
        )

    def _build_condition_suggestion(
        self,
        condition_key: str,
        description: str,
        example: str,
        expected_value: Any = None,
        operator: str = "StringEquals",
    ) -> tuple[str, str]:
        """Build suggestion and example for adding the missing condition.

        Args:
            condition_key: The condition key
            description: Description of the condition
            example: Example usage
            expected_value: Expected value for the condition
            operator: Condition operator

        Returns:
            Tuple of (suggestion_text, example_code)
        """
        suggestion = description if description else f"Add condition: `{condition_key}`"

        # Build example based on condition key type
        if example:
            example_code = example
        else:
            # Auto-generate example
            example_lines = [f'  "{operator}": {{']

            if isinstance(expected_value, list):
                value_str = (
                    "["
                    + ", ".join([f'"{v}"' if not str(v).startswith("${") else f'"{v}"' for v in expected_value])
                    + "]"
                )
            elif expected_value is not None:
                # Don't quote if it's a variable reference like ${aws:PrincipalTag/owner}
                if str(expected_value).startswith("${"):
                    value_str = f'"{expected_value}"'
                elif isinstance(expected_value, bool):
                    value_str = str(expected_value).lower()
                else:
                    value_str = f'"{expected_value}"'
            else:
                value_str = '"<value>"'

            example_lines.append(f'    "{condition_key}": {value_str}')
            example_lines.append("  }")

            example_code = "\n".join(example_lines)

        return suggestion, example_code

    def _build_any_of_suggestion(self, any_of_conditions: list[dict[str, Any]]) -> str:
        """Build suggestion for any_of conditions.

        Args:
            any_of_conditions: List of condition requirements

        Returns:
            Suggestion string
        """
        suggestions = []
        suggestions.append("Add at least ONE of these conditions:")

        for i, cond in enumerate(any_of_conditions, 1):
            condition_key = describe_entry(cond)
            leaves = self._leaves(cond["all_of"]) if "all_of" in cond else []
            description = cond.get("description") or next(
                (leaf["description"] for leaf in leaves if leaf.get("description")), ""
            )
            expected_value = None if leaves else cond.get("expected_value")
            child_values = [
                f"`{leaf['condition_key']}`: `{leaf['expected_value']}`"
                for leaf in leaves
                if leaf.get("expected_value") is not None
            ]

            option = f"\n- **Option {i}**: {condition_key}"
            if description:
                option += f" - {description}"
            if expected_value is not None:
                option += f" (value: `{expected_value}`)"
            elif child_values:
                option += f" (values: {', '.join(child_values)})"

            suggestions.append(option)

        return "".join(suggestions)

    def _create_none_of_condition_issue(
        self,
        statement: Statement,
        statement_idx: int,
        condition_requirement: dict[str, Any],
        matching_principals: list[str],
        *,
        config: CheckConfig,
        requirement: dict[str, Any],
    ) -> ValidationIssue:
        """Create a validation issue for a forbidden condition that is present.

        Args:
            statement: The statement being validated
            statement_idx: Index of the statement
            condition_requirement: The condition requirement config
            matching_principals: Principals that matched
            config: Check configuration
            requirement: Parent requirement config

        Returns:
            ValidationIssue
        """
        condition_key = describe_entry(condition_requirement)
        description = condition_requirement.get("description", "")
        expected_value = condition_requirement.get("expected_value")

        matching_principals_str = format_list_with_backticks(matching_principals)
        message = f"FORBIDDEN: `Principal`s {matching_principals_str} must NOT have `Condition` {condition_key}"
        if expected_value is not None:
            message += f" with value `{expected_value}`"

        suggestion = f"Remove the {condition_key} `Condition` from the statement"
        if description:
            suggestion += f". {description}"

        severity = self._severity(config, condition_requirement, requirement)

        return ValidationIssue(
            severity=severity,
            statement_sid=statement.sid,
            statement_index=statement_idx,
            issue_type="forbidden_principal_condition",
            condition_key=condition_requirement.get("condition_key"),
            message=message,
            suggestion=suggestion,
            line_number=statement.line_number,
            field_name="principal",
            finding_key=rule_key("none_of", condition_requirement),
        )

"""Policy size validation check.

This check validates that IAM policies don't exceed AWS's maximum size limits.
AWS enforces different size limits based on policy type:

- Managed policies: 6,144 bytes
- Inline user policies: 2,048 bytes
- Inline group policies: 5,120 bytes
- Inline role policies: 10,240 bytes
- Inline role trust policies: 2,048 bytes
- Service Control Policies (SCP): 10,240 bytes (raised from 5,120 on 2026-05-15)
- Resource Control Policies (RCP): 5,120 bytes

Resource-based policies (S3 bucket, SQS, SNS, Lambda, etc.) vary by service and
are not checked here unless the user configures an explicit limit.

Whitespace is where the two services disagree, so the measurement depends on the
policy type:

- **IAM** (managed and inline) "doesn't count white space when calculating the
  size of a policy against these limits", so the policy is measured as compact
  JSON — no inter-token whitespace.
- **Organizations** (SCP and RCP) strips whitespace only when the console saves
  the policy: "If you save the policy using an SDK operation or the AWS CLI,
  then the policy is saved exactly as you provided." Terraform, the CLI and the
  SDKs all submit the document verbatim, so an SCP/RCP backed by a ``.json``
  file is measured as written — a 2-space indented policy is roughly 1.7x its
  compact size. Without such a file (an SDK caller passing a dict, or a YAML
  source that the deploy tool re-serializes) it falls back to compact JSON.
  ``organizations_measurement: compact`` opts out when the deploy pipeline
  minifies the document.

Either way the count is UTF-8 bytes, matching AWS counting bytes rather than
Unicode codepoints. Whitespace inside string values (SIDs, condition values) is
always counted, as AWS counts those characters.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, ClassVar

from iam_validator.checks.policy_type_validation import looks_like_rcp
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.constants import AWS_POLICY_SIZE_LIMITS, AWS_POLICY_TYPE_TO_SIZE_KEY
from iam_validator.core.models import IAMPolicy, ValidationIssue

logger = logging.getLogger(__name__)


# Human-readable descriptions keyed by size-limit key
_LIMIT_DESCRIPTIONS = {
    "managed": "managed policy",
    "inline_user": "inline policy for users",
    "inline_group": "inline policy for groups",
    "inline_role": "inline policy for roles",
    "inline_role_trust": "inline role trust policy",
    "scp": "Service Control Policy",
    "rcp": "Resource Control Policy",
}

# Limit keys for AWS Organizations policies. Organizations strips whitespace only
# on a console save — a CLI/SDK/Terraform deploy stores the document verbatim —
# so these are measured as written rather than minified. Every IAM limit key is
# absent here because IAM never counts whitespace.
_WHITESPACE_COUNTING_LIMITS = frozenset({"scp", "rcp"})

_UTF8_BOM = b"\xef\xbb\xbf"


class PolicySizeCheck(PolicyCheck):
    """Validates that IAM policies don't exceed AWS size limits."""

    # AWS IAM policy size limits (loaded from constants module)
    DEFAULT_LIMITS = AWS_POLICY_SIZE_LIMITS

    check_id: ClassVar[str] = "policy_size"
    description: ClassVar[str] = "Validates that IAM policies don't exceed AWS size limits"
    default_severity: ClassVar[str] = "error"

    async def execute_policy(
        self,
        policy: IAMPolicy,
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        """Execute the policy size check on the entire policy.

        Measures the policy in UTF-8 bytes — compact JSON for IAM policies, the
        document as written for an SCP/RCP backed by a ``.json`` file (see the
        module docstring on whitespace) — and validates it against the AWS limit
        appropriate for the policy type. The limit is resolved in this priority
        order:

        1. YAML config ``policy_size.policy_type`` (explicit
           override for users who know the deployment target — e.g., a policy
           headed for an inline user attachment rather than a managed policy).
        2. The runtime ``policy_type`` kwarg (from ``--policy-type`` or
           auto-detection) mapped through ``AWS_POLICY_TYPE_TO_SIZE_KEY``.
        3. Fallback to ``managed`` (6,144 bytes).

        Args:
            policy: The complete IAM policy to validate
            policy_file: Path to the policy file (for context/reporting)
            fetcher: AWS service fetcher (unused for this check)
            config: Configuration for this check instance
            **kwargs: May include ``policy_type`` (AWS policy type),
                ``raw_policy_dict`` (original parsed JSON/YAML, preferred for
                accurate size measurement) and ``policy_type_source`` (how the
                policy type was arrived at — see ``_ambiguous_limit_key``).

        Returns:
            List of ValidationIssue objects if policy exceeds size limits
        """
        del fetcher  # Unused
        issues: list[ValidationIssue] = []

        # Resolve size-limit key in priority order.
        size_limits = config.config.get("size_limits", self.DEFAULT_LIMITS.copy())
        explicit_key = config.config.get("policy_type")
        runtime_policy_type = kwargs.get("policy_type", "IDENTITY_POLICY")
        if explicit_key is not None:
            limit_key = explicit_key
        else:
            limit_key = AWS_POLICY_TYPE_TO_SIZE_KEY.get(runtime_policy_type, "managed")

        if limit_key not in size_limits:
            # User supplied an unknown key — fall back rather than crash.
            limit_key = "managed"

        max_size = size_limits[limit_key]

        # Prefer the raw parsed dict so we measure what AWS would actually
        # receive, not Pydantic's re-serialized view. Fall back to model_dump.
        raw_policy_dict = kwargs.get("raw_policy_dict")
        if raw_policy_dict is not None:
            policy_json = raw_policy_dict
        else:
            policy_json = policy.model_dump(by_alias=True, exclude_none=True)

        # Compact JSON strips inter-token whitespace; UTF-8 byte length matches
        # AWS's measurement (AWS counts bytes, not Unicode codepoints).
        policy_string = json.dumps(policy_json, separators=(",", ":"), ensure_ascii=False)
        compact_size = len(policy_string.encode("utf-8"))

        candidate_key = None
        if explicit_key is None:
            candidate_key = self._ambiguous_limit_key(
                policy,
                runtime_policy_type=runtime_policy_type,
                policy_type_source=kwargs.get("policy_type_source", "cli-flag"),
            )
            if candidate_key not in size_limits:
                candidate_key = None

        as_written_size = None
        measure_as_written = config.config.get("organizations_measurement", "as_written") != "compact"
        if measure_as_written and (
            limit_key in _WHITESPACE_COUNTING_LIMITS or candidate_key in _WHITESPACE_COUNTING_LIMITS
        ):
            as_written_size = await self._measure_as_written(policy_file, policy, raw_policy_dict)

        def size_for(key: str) -> int:
            if key in _WHITESPACE_COUNTING_LIMITS and as_written_size is not None:
                return as_written_size
            return compact_size

        policy_size = size_for(limit_key)
        measured_as_written = limit_key in _WHITESPACE_COUNTING_LIMITS and as_written_size is not None

        # One greppable line per policy so "why didn't the size check fire?" is
        # answerable from a single --log-level debug run. Every field is an
        # integer or from a closed set, and only the basename is logged.
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "policy_size=%d measured=%s limit_key=%s limit=%d limit_source=%s file=%s",
                policy_size,
                "as-written" if measured_as_written else "compact",
                limit_key if limit_key in AWS_POLICY_SIZE_LIMITS else "custom",
                max_size,
                "check-config" if explicit_key is not None else "policy-type",
                Path(policy_file).name,
            )

        if policy_size <= max_size:
            if candidate_key is not None:
                ambiguity_issue = self._type_ambiguity_issue(
                    candidate_key=candidate_key,
                    candidate_size=size_for(candidate_key),
                    candidate_limit=size_limits[candidate_key],
                    limit_key=limit_key,
                    max_size=max_size,
                )
                if ambiguity_issue is not None:
                    issues.append(ambiguity_issue)
            return issues

        severity = self.get_severity(config)
        percentage_over = ((policy_size - max_size) / max_size) * 100
        policy_type_desc = _LIMIT_DESCRIPTIONS.get(limit_key, limit_key)

        if measured_as_written:
            if compact_size <= max_size:
                minified_note = (
                    "within the limit — if your deployment pipeline minifies the document "
                    "(Terraform's jsonencode, for example), reformatting this file is enough"
                )
            else:
                minified_note = "still over the limit"
            measurement = f"Policy size ({policy_size:,} bytes as written)"
            whitespace_note = (
                f"AWS Organizations stores the document exactly as the CLI, an SDK or Terraform "
                f"submits it, so this file's formatting counts against the limit (only the console "
                f"strips whitespace). Minified the policy is {compact_size:,} bytes — {minified_note}."
            )
        else:
            measurement = f"Policy size ({policy_size:,} bytes)"
            whitespace_note = "Note: IAM does not count whitespace in the size calculation."

        issues.append(
            ValidationIssue(
                severity=severity,
                statement_sid=None,
                statement_index=-1,  # Policy-level issue
                issue_type="policy_size_exceeded",
                message=(f"{measurement} exceeds AWS limit for {policy_type_desc} ({max_size:,} bytes)"),
                suggestion=(
                    f"The policy is {policy_size - max_size:,} bytes over the limit "
                    f"({percentage_over:.1f}% too large). Consider:\n"
                    f"  1. Splitting the policy into multiple smaller policies\n"
                    f"  2. Using more concise action/resource patterns with wildcards\n"
                    f"  3. Removing unnecessary statements or conditions\n"
                    f"  4. For inline policies, consider using managed policies instead\n"
                    f"\n{whitespace_note}"
                ),
                line_number=None,
            )
        )

        return issues

    @staticmethod
    async def _measure_as_written(
        policy_file: str, policy: IAMPolicy, raw_policy_dict: dict[str, Any] | None
    ) -> int | None:
        """Byte length of the ``.json`` document on disk, excluding a UTF-8 BOM.

        ``None`` when there is no readable ``.json`` file that parses to the validated document
        (an SDK dict, a YAML source, or an unrelated file of the same name), so the
        caller falls back to the compact size.
        """
        path = Path(policy_file)
        if path.suffix.lower() != ".json":
            return None
        try:
            data = await asyncio.to_thread(path.read_bytes)
        except OSError:
            return None
        document = data.removeprefix(_UTF8_BOM)
        try:
            parsed = json.loads(document)
            if raw_policy_dict is not None:
                matches = parsed == raw_policy_dict
            else:
                # Model equality would compare the excluded, loader-set `line_number`.
                matches = IAMPolicy.model_validate(parsed).model_dump(by_alias=True) == policy.model_dump(by_alias=True)
        except ValueError:
            return None
        return len(document) if matches else None

    @staticmethod
    def _ambiguous_limit_key(policy: IAMPolicy, *, runtime_policy_type: str, policy_type_source: str) -> str | None:
        """Limit key of the Organizations policy type an inferred document is indistinguishable from.

        An SCP has the identity-policy shape and an RCP the ``Principal: "*"``
        resource-policy shape, so neither can be auto-detected. Inline limits
        are per-entity aggregates and opt-in via ``policy_size.policy_type``.
        """
        if policy_type_source not in ("auto-detect", "default"):
            return None
        if runtime_policy_type == "IDENTITY_POLICY":
            return "scp"
        if runtime_policy_type == "RESOURCE_POLICY" and looks_like_rcp(policy):
            return "rcp"
        return None

    @staticmethod
    def _type_ambiguity_issue(
        *,
        candidate_key: str,
        candidate_size: int,
        candidate_limit: int,
        limit_key: str,
        max_size: int,
    ) -> ValidationIssue | None:
        """Warn when an inferred policy fits its applied limit but not the look-alike type's limit.

        Advisory ``warning`` (not ``get_severity``) so it never inherits the
        check's ``error`` severity and fails the run.
        """
        if candidate_size <= candidate_limit:
            return None

        applied_desc = _LIMIT_DESCRIPTIONS.get(limit_key, limit_key)
        candidate_desc = _LIMIT_DESCRIPTIONS.get(candidate_key, candidate_key)
        declared_type = "SERVICE_CONTROL_POLICY" if candidate_key == "scp" else "RESOURCE_CONTROL_POLICY"
        inferred_type = "IDENTITY_POLICY" if candidate_key == "scp" else "RESOURCE_POLICY"
        written_note = " as written" if candidate_key in _WHITESPACE_COUNTING_LIMITS else ""

        return ValidationIssue(
            severity="warning",
            statement_sid=None,
            statement_index=-1,  # Policy-level issue
            issue_type="policy_size_type_ambiguous",
            message=(
                f"Policy fits the {applied_desc} limit ({max_size:,} bytes), but its type was "
                f"inferred, not declared — deployed as a {candidate_desc} it is "
                f"{candidate_size:,} bytes{written_note}, over the {candidate_limit:,}-byte limit"
            ),
            suggestion=(
                f"A {candidate_desc} cannot be told apart from this document's shape, so the "
                f"{applied_desc} limit was applied. Declare the deployment target:\n"
                f"  1. Pass --policy-type {declared_type} (or {inferred_type} if it is not one)\n"
                f"  2. Or map the file in your config:\n"
                f"     policy_types:\n"
                f"       - pattern: '**/{candidate_key}/*.json'\n"
                f"         type: {declared_type}"
            ),
            line_number=1,
            # Set explicitly so the registry's per-check_id enrichment does not
            # attach the `policy_size_exceeded` remediation.
            risk_explanation=(
                "The size limit applied depends on the policy type, and the type was guessed "
                "from the document. If the real deployment target has a stricter limit, AWS "
                "rejects the policy at attach time even though validation passed."
            ),
            remediation_steps=[
                "Pass `--policy-type` for the deployment target",
                "Or map the file in `policy_types:` in your config",
            ],
        )

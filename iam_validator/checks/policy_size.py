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

Either way the count is UTF-8 bytes, matching AWS counting bytes rather than
Unicode codepoints. Whitespace inside string values (SIDs, condition values) is
always counted, as AWS counts those characters.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.constants import AWS_POLICY_SIZE_LIMITS, AWS_POLICY_TYPE_TO_SIZE_KEY
from iam_validator.core.models import ValidationIssue

if TYPE_CHECKING:
    from iam_validator.core.models import IAMPolicy

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


class PolicySizeCheck(PolicyCheck):
    """Validates that IAM policies don't exceed AWS size limits."""

    # AWS IAM policy size limits (loaded from constants module)
    DEFAULT_LIMITS = AWS_POLICY_SIZE_LIMITS

    check_id: ClassVar[str] = "policy_size"
    description: ClassVar[str] = "Validates that IAM policies don't exceed AWS size limits"
    default_severity: ClassVar[str] = "error"

    async def execute_policy(
        self,
        policy: "IAMPolicy",
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
                policy type was arrived at — see ``_check_type_ambiguity``).

        Returns:
            List of ValidationIssue objects if policy exceeds size limits
        """
        del fetcher  # Unused
        issues: list[ValidationIssue] = []

        # Resolve size-limit key in priority order.
        size_limits = config.config.get("size_limits", self.DEFAULT_LIMITS.copy())
        explicit_key = config.config.get("policy_type")
        if explicit_key is not None:
            limit_key = explicit_key
        else:
            runtime_policy_type = kwargs.get("policy_type", "IDENTITY_POLICY")
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

        # IAM never counts whitespace, but AWS Organizations only strips it for
        # console saves — a CLI/SDK/Terraform deploy stores the document exactly
        # as submitted. For an SCP or RCP the file's own formatting therefore
        # counts, and the compact size understates the real one (a 2-space
        # indented policy is roughly 1.7x its compact form).
        as_written_size = None
        if limit_key in _WHITESPACE_COUNTING_LIMITS:
            as_written_size = await self._measure_as_written(policy_file)

        if as_written_size is not None:
            policy_size = as_written_size
        else:
            policy_size = compact_size

        # One greppable line per policy so "why didn't the size check fire?" is
        # answerable from a single --log-level debug run: it shows the limit that
        # was applied and where that limit came from. Every field is an integer
        # or from a closed set, and only the basename is logged.
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "policy_size=%d measured=%s limit_key=%s limit=%d limit_source=%s file=%s",
                policy_size,
                "as-written" if as_written_size is not None else "compact",
                limit_key if limit_key in AWS_POLICY_SIZE_LIMITS else "custom",
                max_size,
                "check-config" if explicit_key is not None else "policy-type",
                Path(policy_file).name,
            )

        if policy_size <= max_size:
            ambiguity_issue = self._check_type_ambiguity(
                policy_size=compact_size,
                max_size=max_size,
                size_limits=size_limits,
                limit_key=limit_key,
                explicit_key=explicit_key,
                runtime_policy_type=kwargs.get("policy_type", "IDENTITY_POLICY"),
                policy_type_source=kwargs.get("policy_type_source", "cli-flag"),
            )
            if ambiguity_issue is not None:
                issues.append(ambiguity_issue)
            return issues

        severity = self.get_severity(config)
        percentage_over = ((policy_size - max_size) / max_size) * 100
        policy_type_desc = _LIMIT_DESCRIPTIONS.get(limit_key, limit_key)

        if as_written_size is not None:
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
    async def _measure_as_written(policy_file: str) -> int | None:
        """Byte length of the JSON document on disk, or ``None`` if not applicable.

        Returns ``None`` — so the caller falls back to the compact size — when
        there is no readable ``.json`` file behind the policy: an SDK caller
        validating a dict, or a YAML source, which is not the document AWS
        receives (the deploy tool re-serializes it to JSON).
        """
        path = Path(policy_file)
        if path.suffix.lower() != ".json":
            return None
        try:
            return await asyncio.to_thread(lambda: len(path.read_bytes()))
        except OSError:
            return None

    @staticmethod
    def _check_type_ambiguity(
        *,
        policy_size: int,
        max_size: int,
        size_limits: dict[str, int],
        limit_key: str,
        explicit_key: str | None,
        runtime_policy_type: str,
        policy_type_source: str,
    ) -> ValidationIssue | None:
        """Warn when a policy fits its limit only because the type was inferred.

        An identity policy, an SCP, an RCP and an inline user/group/role policy
        are structurally identical — nothing in the document says which one it
        is. ``detect_policy_type()`` therefore falls back to IDENTITY_POLICY,
        which carries the *loosest* of those limits (managed, 6,144 bytes). A
        policy between the strictest applicable limit and that fallback passes
        validation and then fails on apply.

        The warning is advisory (``warning`` is not in the default
        ``fail_on_severity``) and is emitted only when nobody declared the
        target, so a declared type never produces noise.
        """
        # A declared type is authoritative — the applied limit is the right one.
        if explicit_key is not None or policy_type_source in ("cli-flag", "config-glob"):
            return None

        # Only the identity-policy shape is ambiguous. A trust or resource
        # policy is identified by its own structure (Principal, etc.).
        if runtime_policy_type != "IDENTITY_POLICY":
            return None

        stricter = {key: limit for key, limit in size_limits.items() if limit < max_size}
        exceeded = {key: limit for key, limit in stricter.items() if policy_size > limit}
        if not exceeded:
            return None

        strictest = min(exceeded.values())
        exceeded_desc = ", ".join(
            f"{_LIMIT_DESCRIPTIONS.get(key, key)} ({limit:,} bytes)"
            for key, limit in sorted(exceeded.items(), key=lambda kv: kv[1])
        )

        return ValidationIssue(
            severity="warning",
            statement_sid=None,
            statement_index=-1,  # Policy-level issue
            issue_type="policy_size_type_ambiguous",
            message=(
                f"Policy size ({policy_size:,} bytes) is within the "
                f"{_LIMIT_DESCRIPTIONS.get(limit_key, limit_key)} limit ({max_size:,} bytes), but the "
                f"policy type was inferred, not declared — and this policy exceeds stricter AWS "
                f"limits that apply to other deployment targets (as low as {strictest:,} bytes)"
            ),
            suggestion=(
                f"Identity policies, SCPs, RCPs and inline policies are structurally identical, so "
                f"the type could not be determined from the document and the "
                f"{_LIMIT_DESCRIPTIONS.get(limit_key, limit_key)} limit was applied. Declare the "
                f"deployment target so the real limit is enforced:\n"
                f"  1. Pass --policy-type (e.g. SERVICE_CONTROL_POLICY)\n"
                f"  2. Or map the file in your config:\n"
                f"     policy_types:\n"
                f"       - pattern: '**/scp/*.json'\n"
                f"         type: SERVICE_CONTROL_POLICY\n"
                f"  3. Or, for a target with no runtime type, set\n"
                f"     policy_size.policy_type: inline_user | inline_group | inline_role\n"
                f"\nLimits this policy already exceeds: {exceeded_desc}."
            ),
            line_number=1,
            # Set explicitly so the registry's per-check_id enrichment does not
            # attach the `policy_size_exceeded` remediation ("split the policy"),
            # which is the wrong advice for a policy that is not actually over
            # the limit it was measured against.
            risk_explanation=(
                "The size limit applied depends on the policy type, and the type was guessed "
                "from the document. If the real deployment target has a stricter limit, AWS "
                "rejects the policy at attach time even though validation passed."
            ),
            remediation_steps=[
                "Pass `--policy-type` for the deployment target",
                "Or map the file in `policy_types:` in your config",
                "Or set `policy_size.policy_type` for an inline target",
            ],
        )

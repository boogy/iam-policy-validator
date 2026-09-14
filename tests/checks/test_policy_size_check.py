"""Tests for policy size check."""

import json
import logging

import pytest

from iam_validator.checks.policy_size import PolicySizeCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement


class TestPolicySizeCheck:
    """Test suite for PolicySizeCheck."""

    @pytest.fixture
    def check(self):
        return PolicySizeCheck()

    @pytest.fixture
    def fetcher(self):
        return AWSServiceFetcher()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="policy_size")

    @pytest.mark.asyncio
    async def test_small_policy_passes(self, check, fetcher, config):
        """Test that small policies pass validation."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="ReadOnly",
                    Effect="Allow",
                    Action=["s3:GetObject"],
                    Resource=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_managed_policy_exceeds_limit(self, check, fetcher):
        """Test that managed policy exceeding 6144 chars is flagged."""
        actions = [f"s3:GetObject{i:04d}" for i in range(450)]
        config = CheckConfig(check_id="policy_size", config={"policy_type": "managed"})
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="ManyActions",
                    Effect="Allow",
                    Action=actions,
                    Resource=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "policy_size_exceeded"
        assert "6,144" in issues[0].message

    @pytest.mark.asyncio
    async def test_inline_user_policy_exceeds_limit(self, check, fetcher):
        """Test that inline user policy exceeding 2048 chars is flagged."""
        actions = [f"s3:GetObject{i:04d}" for i in range(150)]
        config = CheckConfig(check_id="policy_size", config={"policy_type": "inline_user"})
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Allow", Action=actions, Resource=["arn:aws:s3:::my-bucket/*"])],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 1
        assert "2,048" in issues[0].message

    @pytest.mark.asyncio
    async def test_custom_size_limits(self, check, fetcher):
        """Test using custom size limits."""
        config = CheckConfig(
            check_id="policy_size",
            config={"policy_type": "managed", "size_limits": {"managed": 500}},
        )
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Action=[f"s3:GetObject{i:02d}" for i in range(30)],
                    Resource=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        issues = await check.execute_policy(policy, "test.json", fetcher, config)
        assert len(issues) == 1
        assert "500" in issues[0].message

    @pytest.mark.asyncio
    async def test_trust_policy_limit_triggered_via_runtime_kwarg(self, check, fetcher, config):
        """Runtime policy_type=TRUST_POLICY maps to 2048-byte limit automatically."""
        # A trust policy just above 2048 bytes. Stuff Condition values (AWS
        # counts those) rather than actions so the payload looks trust-shaped.
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect="Allow",
                    Principal={"Service": "lambda.amazonaws.com"},
                    Action="sts:AssumeRole",
                    Condition={"StringEquals": {"aws:SourceAccount": "x" * 2200}},
                )
            ],
        )
        issues = await check.execute_policy(policy, "trust.json", fetcher, config, policy_type="TRUST_POLICY")
        assert len(issues) == 1
        assert "2,048" in issues[0].message
        assert "trust policy" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_scp_limit_triggered_via_runtime_kwarg(self, check, fetcher, config):
        """Runtime policy_type=SERVICE_CONTROL_POLICY maps to the 10240-byte limit.

        AWS raised the SCP quota from 5,120 to 10,240 on 2026-05-15; RCP was not
        changed, so the two are no longer the same number.
        """
        actions = [f"s3:GetObject{i:04d}" for i in range(760)]
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Deny", Action=actions, Resource="*")],
        )
        issues = await check.execute_policy(policy, "scp.json", fetcher, config, policy_type="SERVICE_CONTROL_POLICY")
        assert len(issues) == 1
        assert "10,240" in issues[0].message
        assert "Service Control Policy" in issues[0].message

    @pytest.mark.asyncio
    async def test_rcp_limit_triggered_via_runtime_kwarg(self, check, fetcher, config):
        """Runtime policy_type=RESOURCE_CONTROL_POLICY maps to 5120-byte limit."""
        actions = [f"s3:PutObject{i:04d}" for i in range(380)]
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Deny", Action=actions, Resource="*")],
        )
        issues = await check.execute_policy(policy, "rcp.json", fetcher, config, policy_type="RESOURCE_CONTROL_POLICY")
        assert len(issues) == 1
        assert "5,120" in issues[0].message
        assert "Resource Control Policy" in issues[0].message

    @pytest.mark.asyncio
    async def test_yaml_policy_type_overrides_runtime_kwarg(self, check, fetcher):
        """Explicit policy_type in YAML config takes priority over runtime kwarg."""
        # Build a policy around 3 KB — under managed (6144) but over inline_user (2048).
        actions = [f"s3:GetObject{i:04d}" for i in range(200)]
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Allow", Action=actions, Resource="*")],
        )
        # Runtime says IDENTITY_POLICY (which would resolve to managed/6144 -> no issue)
        # but YAML pins inline_user (2048 -> flagged).
        config = CheckConfig(check_id="policy_size", config={"policy_type": "inline_user"})
        issues = await check.execute_policy(policy, "p.json", fetcher, config, policy_type="IDENTITY_POLICY")
        assert len(issues) == 1
        assert "2,048" in issues[0].message

    @pytest.mark.asyncio
    async def test_size_uses_raw_policy_dict_when_available(self, check, fetcher, config):
        """When raw_policy_dict is supplied, it's measured (not the Pydantic view)."""
        # A small policy, but raw_policy_dict padded with extra keys AWS would see.
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Effect="Allow", Action="s3:GetObject", Resource="*")],
        )
        raw = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "x" * 3000,  # blow up the raw size
                }
            ],
        }
        cfg = CheckConfig(check_id="policy_size", config={"policy_type": "inline_user"})
        issues = await check.execute_policy(policy, "p.json", fetcher, cfg, raw_policy_dict=raw)
        assert len(issues) == 1
        assert "bytes" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_runtime_policy_type_routes_end_to_end_through_validate_policies(self, tmp_path):
        """Integration: --policy-type TRUST_POLICY reaches policy_size via validate_policies.

        Regression guard for a bug where `defaults.py` set `policy_size.policy_type = "managed"`
        in the DEFAULT config, which my priority rule treated as an explicit user choice and
        prevented the runtime --policy-type kwarg from ever reaching the check.
        """
        import json

        from iam_validator.core.policy_checks import validate_policies
        from iam_validator.core.policy_loader import PolicyLoader

        # Trust policy ~2.4 KB > 2048-byte limit
        raw = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"aws:SourceAccount": "x" * 2200}},
                }
            ],
        }
        path = tmp_path / "trust.json"
        path.write_text(json.dumps(raw))
        policies = PolicyLoader().load_from_paths([str(path)], recursive=False)
        results = await validate_policies(policies, policy_type="TRUST_POLICY")
        size_issues = [i for r in results for i in r.issues if i.check_id == "policy_size"]
        assert len(size_issues) == 1
        assert "2,048 bytes" in size_issues[0].message
        assert "trust policy" in size_issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_size_counts_utf8_bytes_not_codepoints(self, check, fetcher):
        """Non-ASCII characters count as multiple UTF-8 bytes, matching AWS."""
        # A single non-ASCII codepoint stuffed into a SID repeatedly.
        # 'é' is 2 bytes in UTF-8; '𝓐' (math script A) is 4 bytes.
        # Use tight limit so only the byte-counted size triggers the issue.
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Sid="A" * 50,  # harmless ascii SID kept short
                    Effect="Allow",
                    Action="s3:GetObject",
                    Resource="*",
                    Condition={"StringEquals": {"aws:PrincipalTag/owner": "𝓐" * 30}},
                )
            ],
        )
        cfg = CheckConfig(
            check_id="policy_size",
            config={"policy_type": "managed", "size_limits": {"managed": 200}},
        )
        issues = await check.execute_policy(policy, "p.json", fetcher, cfg)
        assert len(issues) == 1
        # 30 × 4 bytes for the math 'A' alone = 120 extra bytes beyond the
        # codepoint count, so the reported size must reflect UTF-8 byte length.
        reported = int(issues[0].message.split(" bytes")[0].split("(")[1].replace(",", ""))
        assert reported > 200


class TestPolicySizeTypeAmbiguity:
    """The size limit applied depends on a policy type that is often guessed.

    An RCP, an SCP and an inline policy are all structurally identical to an
    identity policy, so a bare ``validate`` run measures them against the
    managed limit (6,144) — looser than the RCP limit (5,120) and the inline
    user/group limits (2,048 / 5,120). Policies in that window passed CI and
    then failed on apply. When the type was guessed rather than declared, the
    check warns.
    """

    @pytest.fixture
    def check(self):
        return PolicySizeCheck()

    @pytest.fixture
    def fetcher(self):
        return AWSServiceFetcher()

    @staticmethod
    def _policy_of_size(target_bytes: int) -> IAMPolicy:
        """Build an identity-shaped policy whose compact JSON exceeds target_bytes."""
        statements: list[Statement] = []
        while True:
            statements.append(
                Statement(
                    Sid=f"Sid{len(statements):04d}",
                    Effect="Allow",
                    Action=["s3:GetObject"],
                    Resource=["arn:aws:s3:::bucket/*"],
                )
            )
            policy = IAMPolicy(Version="2012-10-17", Statement=list(statements))
            dumped = policy.model_dump(by_alias=True, exclude_none=True)
            if len(json.dumps(dumped, separators=(",", ":")).encode("utf-8")) > target_bytes:
                return policy

    @pytest.mark.asyncio
    @pytest.mark.parametrize("source", ["auto-detect", "default"])
    async def test_guessed_type_warns_when_stricter_limit_could_apply(self, check, fetcher, source):
        """5,330 bytes fits the managed limit but not the SCP/RCP or inline limits."""
        policy = self._policy_of_size(5200)
        config = CheckConfig(check_id="policy_size")

        issues = await check.execute_policy(
            policy,
            "policy.json",
            fetcher,
            config,
            policy_type="IDENTITY_POLICY",
            policy_type_source=source,
        )

        assert len(issues) == 1
        issue = issues[0]
        assert issue.issue_type == "policy_size_type_ambiguous"
        assert issue.severity == "warning"
        # Generic: names the stricter limits rather than singling out one type.
        assert "2,048" in issue.message
        assert "--policy-type" in issue.suggestion

    @pytest.mark.asyncio
    @pytest.mark.parametrize("source", ["cli-flag", "config-glob"])
    async def test_declared_type_never_warns(self, check, fetcher, source):
        """A declared type is authoritative — the limit applied is the right one."""
        policy = self._policy_of_size(5200)
        config = CheckConfig(check_id="policy_size")

        issues = await check.execute_policy(
            policy,
            "policy.json",
            fetcher,
            config,
            policy_type="IDENTITY_POLICY",
            policy_type_source=source,
        )

        assert issues == []

    @pytest.mark.asyncio
    async def test_yaml_policy_type_override_never_warns(self, check, fetcher):
        """An explicit `checks.policy_size.config.policy_type` is a declaration too."""
        policy = self._policy_of_size(5200)
        config = CheckConfig(check_id="policy_size", config={"policy_type": "managed"})

        issues = await check.execute_policy(
            policy,
            "policy.json",
            fetcher,
            config,
            policy_type="IDENTITY_POLICY",
            policy_type_source="auto-detect",
        )

        assert issues == []

    @pytest.mark.asyncio
    async def test_small_guessed_policy_does_not_warn(self, check, fetcher):
        """Under every applicable limit — nothing to warn about."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Sid="A", Effect="Allow", Action="s3:GetObject", Resource="*")],
        )
        config = CheckConfig(check_id="policy_size")

        issues = await check.execute_policy(
            policy,
            "policy.json",
            fetcher,
            config,
            policy_type="IDENTITY_POLICY",
            policy_type_source="default",
        )

        assert issues == []

    @pytest.mark.asyncio
    async def test_over_applied_limit_reports_error_only(self, check, fetcher):
        """Past the applied limit the error stands alone — no duplicate advisory."""
        policy = self._policy_of_size(6200)
        config = CheckConfig(check_id="policy_size")

        issues = await check.execute_policy(
            policy,
            "policy.json",
            fetcher,
            config,
            policy_type="IDENTITY_POLICY",
            policy_type_source="default",
        )

        assert len(issues) == 1
        assert issues[0].issue_type == "policy_size_exceeded"
        assert issues[0].severity == "error"

    @pytest.mark.asyncio
    async def test_strictest_applied_limit_does_not_warn(self, check, fetcher):
        """A trust policy already uses the strictest limit — no stricter one to flag."""
        policy = self._policy_of_size(1500)
        config = CheckConfig(check_id="policy_size")

        issues = await check.execute_policy(
            policy,
            "trust.json",
            fetcher,
            config,
            policy_type="TRUST_POLICY",
            policy_type_source="auto-detect",
        )

        assert issues == []

    @pytest.mark.asyncio
    async def test_undeclared_boundary_policy_warns_end_to_end(self, tmp_path):
        """Integration: the prod escape. Bare `validate` warns; declaring errors."""
        from iam_validator.core.policy_checks import validate_policies
        from iam_validator.core.policy_loader import PolicyLoader

        statements = []
        while True:
            statements.append(
                {
                    "Sid": f"Deny{len(statements):04d}",
                    "Effect": "Deny",
                    "Action": ["s3:GetObject"],
                    "Resource": "*",
                    "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-abcdefghij"}},
                }
            )
            raw = {"Version": "2012-10-17", "Statement": statements}
            if len(json.dumps(raw, separators=(",", ":")).encode("utf-8")) > 5200:
                break

        path = tmp_path / "scp.json"
        path.write_text(json.dumps(raw))
        policies = PolicyLoader().load_from_paths([str(path)], recursive=False)

        # No --policy-type: the type is guessed, so the stricter limits are flagged.
        results = await validate_policies(policies)
        size_issues = [i for r in results for i in r.issues if i.check_id == "policy_size"]
        assert [i.issue_type for i in size_issues] == ["policy_size_type_ambiguous"]

        # Declared as an RCP: the real 5,120-byte limit applies and the error fires.
        results = await validate_policies(policies, policy_type="RESOURCE_CONTROL_POLICY")
        size_issues = [i for r in results for i in r.issues if i.check_id == "policy_size"]
        assert [i.issue_type for i in size_issues] == ["policy_size_exceeded"]
        assert "5,120 bytes" in size_issues[0].message

        # Declared as an SCP: 10,240 bytes since 2026-05-15, so it fits.
        results = await validate_policies(policies, policy_type="SERVICE_CONTROL_POLICY")
        size_issues = [i for r in results for i in r.issues if i.check_id == "policy_size"]
        assert size_issues == []


class TestOrganizationsWhitespaceCounting:
    """AWS Organizations counts whitespace unless the console saved the policy.

    From the Organizations quota reference: "If you save the policy by using the
    AWS Management Console, extra white space ... is removed and not counted. If
    you save the policy using an SDK operation or the AWS CLI, then the policy is
    saved exactly as you provided and no automatic removal of characters occurs."

    Terraform, the CLI and every SDK submit the document verbatim, so for an SCP
    or RCP the file's own formatting counts against the limit. IAM is the
    opposite — it never counts whitespace — so identity policies keep the
    compact measurement.
    """

    @pytest.fixture
    def check(self):
        return PolicySizeCheck()

    @pytest.fixture
    def fetcher(self):
        return AWSServiceFetcher()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="policy_size")

    @staticmethod
    def _write_indented(tmp_path, name: str, compact_target: int):
        """Write a pretty-printed policy whose compact form is under the target."""
        statements = []
        while True:
            statements.append(
                {
                    "Sid": f"Deny{len(statements):04d}",
                    "Effect": "Deny",
                    "Action": ["s3:GetObject"],
                    "Resource": "*",
                    "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-abcdefghij"}},
                }
            )
            raw = {"Version": "2012-10-17", "Statement": statements}
            if len(json.dumps(raw, separators=(",", ":")).encode("utf-8")) > compact_target:
                break

        path = tmp_path / name
        path.write_text(json.dumps(raw, indent=2))
        compact = len(json.dumps(raw, separators=(",", ":")).encode("utf-8"))
        written = len(path.read_bytes())
        assert written > compact, "fixture must actually be indented"
        return path, raw, compact, written

    @pytest.mark.asyncio
    async def test_scp_measured_as_written(self, check, fetcher, config, tmp_path):
        """Compact fits 10,240; the indented document that Terraform submits does not."""
        path, raw, compact, written = self._write_indented(tmp_path, "scp.json", 6500)
        assert compact < 10240 < written

        issues = await check.execute_policy(
            policy=IAMPolicy.model_validate(raw),
            policy_file=str(path),
            fetcher=fetcher,
            config=config,
            policy_type="SERVICE_CONTROL_POLICY",
            raw_policy_dict=raw,
        )

        assert len(issues) == 1
        assert issues[0].issue_type == "policy_size_exceeded"
        assert f"{written:,} bytes" in issues[0].message
        assert "as written" in issues[0].message
        # The compact size is surfaced so a user who minifies can see the headroom.
        assert f"{compact:,}" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_rcp_measured_as_written(self, check, fetcher, config, tmp_path):
        path, raw, compact, written = self._write_indented(tmp_path, "rcp.json", 3200)
        assert compact < 5120 < written

        issues = await check.execute_policy(
            policy=IAMPolicy.model_validate(raw),
            policy_file=str(path),
            fetcher=fetcher,
            config=config,
            policy_type="RESOURCE_CONTROL_POLICY",
            raw_policy_dict=raw,
        )

        assert [i.issue_type for i in issues] == ["policy_size_exceeded"]

    @pytest.mark.asyncio
    async def test_identity_policy_still_ignores_whitespace(self, check, fetcher, config, tmp_path):
        """IAM does not count whitespace — the same file must not be flagged."""
        path, raw, compact, written = self._write_indented(tmp_path, "managed.json", 4000)
        assert compact < 6144 < written

        issues = await check.execute_policy(
            policy=IAMPolicy.model_validate(raw),
            policy_file=str(path),
            fetcher=fetcher,
            config=config,
            policy_type="IDENTITY_POLICY",
            policy_type_source="cli-flag",
            raw_policy_dict=raw,
        )

        assert issues == []

    @pytest.mark.asyncio
    async def test_scp_without_a_file_falls_back_to_compact(self, check, fetcher, config):
        """An SDK caller validating a dict has no document on disk to measure."""
        statements = [
            {
                "Sid": f"Deny{i:04d}",
                "Effect": "Deny",
                "Action": ["s3:GetObject"],
                "Resource": "*",
            }
            for i in range(200)
        ]
        raw = {"Version": "2012-10-17", "Statement": statements}

        issues = await check.execute_policy(
            policy=IAMPolicy.model_validate(raw),
            policy_file="<dict>",
            fetcher=fetcher,
            config=config,
            policy_type="SERVICE_CONTROL_POLICY",
            raw_policy_dict=raw,
        )

        compact = len(json.dumps(raw, separators=(",", ":")).encode("utf-8"))
        if compact <= 10240:
            assert issues == []
        else:
            assert f"{compact:,} bytes" in issues[0].message

    @pytest.mark.asyncio
    async def test_yaml_scp_falls_back_to_compact(self, check, fetcher, config, tmp_path):
        """A YAML source is not the document AWS receives — measure the JSON form."""
        raw = {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "A", "Effect": "Deny", "Action": ["s3:*"], "Resource": "*"}],
        }
        path = tmp_path / "scp.yaml"
        path.write_text("# " + "padding " * 3000 + "\n")

        issues = await check.execute_policy(
            policy=IAMPolicy.model_validate(raw),
            policy_file=str(path),
            fetcher=fetcher,
            config=config,
            policy_type="SERVICE_CONTROL_POLICY",
            raw_policy_dict=raw,
        )

        # The padded YAML file is far over 10,240 bytes; the policy itself is tiny.
        assert issues == []


class TestPolicySizeDebugLogging:
    """One greppable line per policy explaining which limit was applied.

    When a policy that AWS rejected for size passed validation, the question is
    always "which limit did it measure against, and where did that limit come
    from?" — this makes it answerable from a single debug run.
    """

    @pytest.fixture
    def check(self):
        return PolicySizeCheck()

    @pytest.fixture
    def fetcher(self):
        return AWSServiceFetcher()

    @pytest.mark.asyncio
    async def test_debug_line_reports_applied_limit(self, check, fetcher, caplog):
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Sid="A", Effect="Allow", Action="s3:GetObject", Resource="*")],
        )
        config = CheckConfig(check_id="policy_size")

        with caplog.at_level(logging.DEBUG, logger="iam_validator.checks.policy_size"):
            await check.execute_policy(
                policy, "ro.json", fetcher, config, policy_type="IDENTITY_POLICY", policy_type_source="cli-flag"
            )

        assert "limit_key=managed limit=6144 limit_source=policy-type" in caplog.text
        assert "measured=compact" in caplog.text
        assert "file=ro.json" in caplog.text

    @pytest.mark.asyncio
    async def test_debug_line_reports_config_override_as_the_source(self, check, fetcher, caplog):
        """A looser limit set in config is the first thing to check — name it."""
        policy = IAMPolicy(
            Version="2012-10-17",
            Statement=[Statement(Sid="A", Effect="Allow", Action="s3:GetObject", Resource="*")],
        )
        config = CheckConfig(check_id="policy_size", config={"policy_type": "inline_role"})

        with caplog.at_level(logging.DEBUG, logger="iam_validator.checks.policy_size"):
            await check.execute_policy(policy, "ro.json", fetcher, config, policy_type="IDENTITY_POLICY")

        assert "limit_key=inline_role limit=10240 limit_source=check-config" in caplog.text

    @pytest.mark.asyncio
    async def test_debug_line_reports_as_written_measurement(self, check, fetcher, caplog, tmp_path):
        raw = {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "A", "Effect": "Deny", "Action": ["s3:*"], "Resource": "*"}],
        }
        path = tmp_path / "scp.json"
        path.write_text(json.dumps(raw, indent=2))
        config = CheckConfig(check_id="policy_size")

        with caplog.at_level(logging.DEBUG, logger="iam_validator.checks.policy_size"):
            await check.execute_policy(
                IAMPolicy.model_validate(raw),
                str(path),
                fetcher,
                config,
                policy_type="SERVICE_CONTROL_POLICY",
                raw_policy_dict=raw,
            )

        assert "measured=as-written" in caplog.text
        assert f"policy_size={len(path.read_bytes())}" in caplog.text

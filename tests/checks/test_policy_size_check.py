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
    """An SCP has the identity-policy shape and an RCP the ``Principal: "*"`` resource-policy shape.

    Neither can be auto-detected, so an undeclared one is measured against the
    managed limit. The check warns only when the look-alike Organizations type's
    own limit would be exceeded.
    """

    @pytest.fixture
    def check(self):
        return PolicySizeCheck()

    @pytest.fixture
    def fetcher(self):
        return AWSServiceFetcher()

    @staticmethod
    def _raw_of_size(target_bytes: int, *, rcp_shaped: bool = False) -> dict:
        statements: list[dict] = []
        while True:
            if rcp_shaped:
                statement = {
                    "Sid": f"Deny{len(statements):04d}",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["s3:GetObject"],
                    "Resource": "*",
                    "Condition": {"StringNotEqualsIfExists": {"aws:SourceOrgID": "o-abcdefghij"}},
                }
            else:
                statement = {
                    "Sid": f"Sid{len(statements):04d}",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::bucket/*"],
                }
            statements.append(statement)
            raw = {"Version": "2012-10-17", "Statement": statements}
            if len(json.dumps(raw, separators=(",", ":")).encode("utf-8")) > target_bytes:
                return raw

    async def _run(self, check, fetcher, raw, *, policy_type, source, policy_file="policy.json", config=None):
        return await check.execute_policy(
            IAMPolicy.model_validate(raw),
            policy_file,
            fetcher,
            config or CheckConfig(check_id="policy_size"),
            policy_type=policy_type,
            policy_type_source=source,
            raw_policy_dict=raw,
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("target", [2100, 5200])
    async def test_identity_policy_under_scp_limit_does_not_warn(self, check, fetcher, target):
        """Inline limits are per-entity aggregates and opt-in, so they are not guessed at."""
        raw = self._raw_of_size(target)

        issues = await self._run(check, fetcher, raw, policy_type="IDENTITY_POLICY", source="default")

        assert issues == []

    @pytest.mark.asyncio
    async def test_rcp_shaped_resource_policy_over_rcp_limit_warns(self, check, fetcher):
        raw = self._raw_of_size(5200, rcp_shaped=True)

        issues = await self._run(check, fetcher, raw, policy_type="RESOURCE_POLICY", source="auto-detect")

        assert len(issues) == 1
        issue = issues[0]
        assert issue.issue_type == "policy_size_type_ambiguous"
        assert issue.severity == "warning"
        assert "5,120-byte limit" in issue.message
        assert "--policy-type RESOURCE_CONTROL_POLICY" in issue.suggestion

    @pytest.mark.asyncio
    async def test_non_rcp_resource_policy_does_not_warn(self, check, fetcher):
        """A bucket policy scoping its ARNs is not an RCP look-alike."""
        raw = self._raw_of_size(5200, rcp_shaped=True)
        for statement in raw["Statement"]:
            statement["Resource"] = "arn:aws:s3:::bucket/*"

        issues = await self._run(check, fetcher, raw, policy_type="RESOURCE_POLICY", source="auto-detect")

        assert issues == []

    @pytest.mark.asyncio
    async def test_identity_policy_over_scp_limit_as_written_warns(self, check, fetcher, tmp_path):
        """Compact fits the managed limit; the indented file exceeds the SCP limit Organizations applies."""
        raw = self._raw_of_size(5800)
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(raw, indent=8))
        written = len(path.read_bytes())
        assert written > 10240

        issues = await self._run(
            check, fetcher, raw, policy_type="IDENTITY_POLICY", source="default", policy_file=str(path)
        )

        assert [i.issue_type for i in issues] == ["policy_size_type_ambiguous"]
        assert f"{written:,} bytes as written" in issues[0].message
        assert "--policy-type SERVICE_CONTROL_POLICY" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_compact_measurement_silences_as_written_ambiguity(self, check, fetcher, tmp_path):
        raw = self._raw_of_size(5800)
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(raw, indent=8))
        config = CheckConfig(check_id="policy_size", config={"organizations_measurement": "compact"})

        issues = await self._run(
            check,
            fetcher,
            raw,
            policy_type="IDENTITY_POLICY",
            source="default",
            policy_file=str(path),
            config=config,
        )

        assert issues == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("source", ["cli-flag", "config-glob"])
    async def test_declared_type_never_warns(self, check, fetcher, source):
        raw = self._raw_of_size(5200, rcp_shaped=True)

        issues = await self._run(check, fetcher, raw, policy_type="RESOURCE_POLICY", source=source)

        assert issues == []

    @pytest.mark.asyncio
    async def test_yaml_policy_type_override_never_warns(self, check, fetcher):
        raw = self._raw_of_size(5200, rcp_shaped=True)
        config = CheckConfig(check_id="policy_size", config={"policy_type": "managed"})

        issues = await self._run(
            check, fetcher, raw, policy_type="RESOURCE_POLICY", source="auto-detect", config=config
        )

        assert issues == []

    @pytest.mark.asyncio
    async def test_custom_size_limits_without_candidate_key_do_not_crash(self, check, fetcher):
        raw = self._raw_of_size(5200, rcp_shaped=True)
        config = CheckConfig(check_id="policy_size", config={"size_limits": {"managed": 6144}})

        issues = await self._run(
            check, fetcher, raw, policy_type="RESOURCE_POLICY", source="auto-detect", config=config
        )

        assert issues == []

    @pytest.mark.asyncio
    async def test_small_guessed_policy_does_not_warn(self, check, fetcher):
        raw = self._raw_of_size(100, rcp_shaped=True)

        issues = await self._run(check, fetcher, raw, policy_type="RESOURCE_POLICY", source="auto-detect")

        assert issues == []

    @pytest.mark.asyncio
    async def test_over_applied_limit_reports_error_only(self, check, fetcher):
        raw = self._raw_of_size(6200, rcp_shaped=True)

        issues = await self._run(check, fetcher, raw, policy_type="RESOURCE_POLICY", source="auto-detect")

        assert [(i.issue_type, i.severity) for i in issues] == [("policy_size_exceeded", "error")]

    @pytest.mark.asyncio
    async def test_trust_policy_does_not_warn(self, check, fetcher):
        raw = self._raw_of_size(1500)

        issues = await self._run(check, fetcher, raw, policy_type="TRUST_POLICY", source="auto-detect")

        assert issues == []

    @pytest.mark.asyncio
    async def test_undeclared_rcp_warns_end_to_end(self, tmp_path):
        """Bare `validate` warns; declaring RCP errors; declaring SCP fits."""
        from iam_validator.core.policy_checks import validate_policies
        from iam_validator.core.policy_loader import PolicyLoader

        path = tmp_path / "rcp.json"
        path.write_text(json.dumps(self._raw_of_size(5200, rcp_shaped=True), separators=(",", ":")))
        policies = PolicyLoader().load_from_paths([str(path)], recursive=False)

        results = await validate_policies(policies)
        size_issues = [i for r in results for i in r.issues if i.check_id == "policy_size"]
        assert [i.issue_type for i in size_issues] == ["policy_size_type_ambiguous"]

        results = await validate_policies(policies, policy_type="RESOURCE_CONTROL_POLICY")
        size_issues = [i for r in results for i in r.issues if i.check_id == "policy_size"]
        assert [i.issue_type for i in size_issues] == ["policy_size_exceeded"]
        assert "5,120 bytes" in size_issues[0].message

        results = await validate_policies(policies, policy_type="SERVICE_CONTROL_POLICY")
        size_issues = [i for r in results for i in r.issues if i.check_id == "policy_size"]
        assert size_issues == []

    @pytest.mark.asyncio
    async def test_undeclared_mid_size_identity_policy_is_silent_end_to_end(self, tmp_path):
        from iam_validator.core.policy_checks import validate_policies
        from iam_validator.core.policy_loader import PolicyLoader

        path = tmp_path / "identity.json"
        path.write_text(json.dumps(self._raw_of_size(3400), indent=2))
        policies = PolicyLoader().load_from_paths([str(path)], recursive=False)

        results = await validate_policies(policies)

        assert [i for r in results for i in r.issues if i.check_id == "policy_size"] == []


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

    @pytest.mark.asyncio
    async def test_compact_measurement_opt_out(self, check, fetcher, tmp_path):
        path, raw, compact, written = self._write_indented(tmp_path, "scp.json", 6500)
        assert compact < 10240 < written
        config = CheckConfig(check_id="policy_size", config={"organizations_measurement": "compact"})

        issues = await check.execute_policy(
            policy=IAMPolicy.model_validate(raw),
            policy_file=str(path),
            fetcher=fetcher,
            config=config,
            policy_type="SERVICE_CONTROL_POLICY",
            raw_policy_dict=raw,
        )

        assert issues == []

    @pytest.mark.asyncio
    async def test_utf8_bom_is_not_counted(self, check, fetcher, config, tmp_path):
        raw = {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "A", "Effect": "Deny", "Action": ["s3:*"], "Resource": "*"}],
        }
        document = json.dumps(raw).encode("utf-8")
        path = tmp_path / "rcp.json"
        path.write_bytes(b"\xef\xbb\xbf" + document)
        config = CheckConfig(check_id="policy_size", config={"size_limits": {"rcp": len(document)}})

        issues = await check.execute_policy(
            policy=IAMPolicy.model_validate(raw),
            policy_file=str(path),
            fetcher=fetcher,
            config=config,
            policy_type="RESOURCE_CONTROL_POLICY",
            raw_policy_dict=raw,
        )

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

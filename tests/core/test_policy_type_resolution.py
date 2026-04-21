"""Tests for the per-file policy_type resolution pipeline in validate_policies.

Covers:
- Resolution priority (CLI flag > config glob > auto-detect > default).
- Debug log format (``source=cli-flag|config-glob|auto-detect|default``).
- Mixed-directory integration: correct ``policy_size`` limit per file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from iam_validator.core.config.config_loader import ValidatorConfig
from iam_validator.core.models import IAMPolicy, Statement
from iam_validator.core.policy_checks import _resolve_policy_type, validate_policies


def _trust_policy() -> IAMPolicy:
    return IAMPolicy(
        Version="2012-10-17",
        Statement=[
            Statement(
                Effect="Allow",
                Principal={"Service": "lambda.amazonaws.com"},
                Action="sts:AssumeRole",
            )
        ],
    )


def _identity_policy() -> IAMPolicy:
    return IAMPolicy(
        Version="2012-10-17",
        Statement=[
            Statement(
                Effect="Allow",
                Action="s3:GetObject",
                Resource="arn:aws:s3:::bucket/*",
            )
        ],
    )


def _resource_policy() -> IAMPolicy:
    return IAMPolicy(
        Version="2012-10-17",
        Statement=[
            Statement(
                Effect="Allow",
                Principal="*",
                Action="s3:GetObject",
                Resource="arn:aws:s3:::public/*",
            )
        ],
    )


def _scp_policy() -> IAMPolicy:
    """SCP looks structurally identical to an identity policy."""
    return IAMPolicy(
        Version="2012-10-17",
        Statement=[
            Statement(
                Effect="Deny",
                Action="iam:DeleteRole",
                Resource="*",
            )
        ],
    )


def _rcp_policy() -> IAMPolicy:
    return IAMPolicy(
        Version="2012-10-17",
        Statement=[
            Statement(
                Effect="Deny",
                Action="s3:GetObject",
                Resource="*",
                Principal="*",
            )
        ],
    )


# ---------------------------------------------------------------------------
# Unit tests: _resolve_policy_type
# ---------------------------------------------------------------------------


class TestResolvePolicyTypePriority:
    def test_cli_flag_takes_precedence_over_everything(self):
        """CLI flag forces IDENTITY_POLICY even on trust-shaped content with matching glob."""
        config = ValidatorConfig({"policy_types": [{"pattern": "**/trust/*.json", "type": "TRUST_POLICY"}]})
        resolved, source, pattern = _resolve_policy_type(
            _trust_policy(),
            "policies/trust/role.json",
            "IDENTITY_POLICY",
            config,
        )
        assert resolved == "IDENTITY_POLICY"
        assert source == "cli-flag"
        assert pattern is None

    def test_glob_mapping_used_when_flag_absent(self):
        """No CLI flag + matching glob → glob wins over content auto-detect."""
        config = ValidatorConfig({"policy_types": [{"pattern": "**/scp/*.json", "type": "SERVICE_CONTROL_POLICY"}]})
        resolved, source, pattern = _resolve_policy_type(
            _scp_policy(),
            "policies/scp/org.json",
            None,
            config,
        )
        assert resolved == "SERVICE_CONTROL_POLICY"
        assert source == "config-glob"
        assert pattern == "**/scp/*.json"

    def test_autodetect_used_when_flag_and_glob_absent(self):
        """No flag, no glob, trust-shaped content → TRUST_POLICY via auto-detect."""
        config = ValidatorConfig({})
        resolved, source, pattern = _resolve_policy_type(
            _trust_policy(),
            "policies/assume-role.json",
            None,
            config,
        )
        assert resolved == "TRUST_POLICY"
        assert source == "auto-detect"
        assert pattern is None

    def test_default_identity_when_nothing_matches(self):
        """No flag, no glob, no Principal → IDENTITY_POLICY / source=default."""
        config = ValidatorConfig({})
        resolved, source, pattern = _resolve_policy_type(
            _identity_policy(),
            "policies/readonly.json",
            None,
            config,
        )
        assert resolved == "IDENTITY_POLICY"
        assert source == "default"
        assert pattern is None

    def test_glob_pattern_at_top_level_matches(self):
        """``**/scp/*.json`` also matches ``scp/org.json`` at root."""
        config = ValidatorConfig({"policy_types": [{"pattern": "**/scp/*.json", "type": "SERVICE_CONTROL_POLICY"}]})
        resolved, source, _ = _resolve_policy_type(_scp_policy(), "scp/org.json", None, config)
        assert resolved == "SERVICE_CONTROL_POLICY"
        assert source == "config-glob"


# ---------------------------------------------------------------------------
# Debug logging via caplog
# ---------------------------------------------------------------------------


def _write_policy(tmp_path: Path, name: str, policy_dict: dict) -> Path:
    file_path = tmp_path / name
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(json.dumps(policy_dict))
    return file_path


@pytest.mark.asyncio
async def test_debug_log_for_cli_flag(tmp_path, caplog):
    """Explicit flag emits ``source=cli-flag``."""
    policy_file = _write_policy(
        tmp_path,
        "trust.json",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    )

    caplog.set_level(logging.DEBUG, logger="iam_validator.core.policy_checks")
    await validate_policies(
        [(str(policy_file), _trust_policy(), json.loads(policy_file.read_text()))],
        policy_type="TRUST_POLICY",
    )

    matches = [r for r in caplog.records if "source=cli-flag" in r.getMessage()]
    assert len(matches) == 1
    assert "policy_type=TRUST_POLICY" in matches[0].getMessage()
    assert f"file={policy_file.name}" in matches[0].getMessage()


@pytest.mark.asyncio
async def test_debug_log_for_auto_detect(tmp_path, caplog):
    """No flag + trust-shaped content emits ``source=auto-detect``."""
    policy_file = _write_policy(
        tmp_path,
        "role-trust.json",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    )

    caplog.set_level(logging.DEBUG, logger="iam_validator.core.policy_checks")
    await validate_policies(
        [(str(policy_file), _trust_policy(), json.loads(policy_file.read_text()))],
    )

    matches = [r for r in caplog.records if "source=auto-detect" in r.getMessage()]
    assert len(matches) == 1
    assert "policy_type=TRUST_POLICY" in matches[0].getMessage()


@pytest.mark.asyncio
async def test_debug_log_for_glob_match(tmp_path, caplog):
    """Glob-matched file emits ``source=config-glob pattern_present=true pattern_len=N``."""
    policies_dir = tmp_path / "policies" / "scp"
    policies_dir.mkdir(parents=True)
    policy_file = policies_dir / "org.json"
    scp = _scp_policy()
    raw = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "iam:DeleteRole", "Resource": "*"}],
    }
    policy_file.write_text(json.dumps(raw))

    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text("policy_types:\n  - pattern: '**/scp/*.json'\n    type: SERVICE_CONTROL_POLICY\n")

    caplog.set_level(logging.DEBUG, logger="iam_validator.core.policy_checks")
    await validate_policies(
        [(str(policy_file), scp, raw)],
        config_path=str(config_file),
    )

    matches = [r for r in caplog.records if "source=config-glob" in r.getMessage()]
    assert len(matches) == 1
    msg = matches[0].getMessage()
    assert "policy_type=SERVICE_CONTROL_POLICY" in msg
    assert "pattern_present=true" in msg
    assert f"pattern_len={len('**/scp/*.json')}" in msg
    assert f"file={policy_file.name}" in msg


@pytest.mark.asyncio
async def test_debug_log_for_default(tmp_path, caplog):
    """Fall-through (no flag, no glob, no Principal) emits ``source=default``."""
    policy_file = _write_policy(
        tmp_path,
        "readonly.json",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*",
                }
            ],
        },
    )

    caplog.set_level(logging.DEBUG, logger="iam_validator.core.policy_checks")
    await validate_policies(
        [(str(policy_file), _identity_policy(), json.loads(policy_file.read_text()))],
    )

    matches = [r for r in caplog.records if "source=default" in r.getMessage()]
    assert len(matches) == 1
    assert "policy_type=IDENTITY_POLICY" in matches[0].getMessage()


# ---------------------------------------------------------------------------
# Integration: mixed-type directory, verify per-file policy_size limits
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mixed_directory_resolves_type_per_file(tmp_path):
    """A single run over identity+trust+SCP+RCP resolves each correctly.

    The orchestrator picks one of: CLI flag / glob / auto-detect / default per
    file, and each ``PolicyValidationResult.policy_type`` reflects the
    resolved value. No CLI flag is supplied.
    """
    # Arrange: four policies in distinct directories.
    identity_dir = tmp_path / "identity"
    trust_dir = tmp_path / "trust-policies"
    scp_dir = tmp_path / "scp"
    rcp_dir = tmp_path / "rcp"
    for d in (identity_dir, trust_dir, scp_dir, rcp_dir):
        d.mkdir()

    identity_file = identity_dir / "ro.json"
    trust_file = trust_dir / "assume.json"
    scp_file = scp_dir / "deny.json"
    rcp_file = rcp_dir / "rcp.json"

    identity_raw = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}],
    }
    trust_raw = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    scp_raw = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "iam:DeleteRole", "Resource": "*"}],
    }
    rcp_raw = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Principal": "*",
            }
        ],
    }

    for path, payload in (
        (identity_file, identity_raw),
        (trust_file, trust_raw),
        (scp_file, scp_raw),
        (rcp_file, rcp_raw),
    ):
        path.write_text(json.dumps(payload))

    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text(
        "policy_types:\n"
        "  - pattern: '**/scp/*.json'\n"
        "    type: SERVICE_CONTROL_POLICY\n"
        "  - pattern: '**/rcp/*.json'\n"
        "    type: RESOURCE_CONTROL_POLICY\n"
    )

    policies = [
        (str(identity_file), _identity_policy(), identity_raw),
        (str(trust_file), _trust_policy(), trust_raw),
        (str(scp_file), _scp_policy(), scp_raw),
        (str(rcp_file), _rcp_policy(), rcp_raw),
    ]

    # Act
    results = await validate_policies(policies, config_path=str(config_file))

    # Assert: each result carries the resolved per-file policy_type.
    resolved_by_file = {r.policy_file: r.policy_type for r in results}
    assert resolved_by_file[str(identity_file)] == "IDENTITY_POLICY"
    assert resolved_by_file[str(trust_file)] == "TRUST_POLICY"
    assert resolved_by_file[str(scp_file)] == "SERVICE_CONTROL_POLICY"
    assert resolved_by_file[str(rcp_file)] == "RESOURCE_CONTROL_POLICY"

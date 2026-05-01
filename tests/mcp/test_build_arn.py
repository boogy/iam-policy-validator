"""Tests for the rewritten ``build_arn`` MCP tool.

The tool now consults the live AWSServiceFetcher via ``query_arn_formats``.
We monkeypatch that single function with a stub returning canned templates so
tests run hermetically (no network, no caches).
"""

from types import SimpleNamespace
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from iam_validator.mcp import server


@pytest.fixture
def stub_ctx():
    """Minimal ctx the tool will pass to get_shared_fetcher (returns None — fetcher is bypassed)."""
    return SimpleNamespace(request_context=None)


@pytest.fixture
def patch_arn_formats(monkeypatch):
    """Return a function that registers a canned response for query_arn_formats."""

    def _patch(formats: list[dict[str, Any]]):
        async def _fake(service: str, fetcher: Any = None) -> list[dict[str, Any]]:  # noqa: ARG001
            return formats

        # build_arn imports query_arn_formats from this module at call time.
        monkeypatch.setattr("iam_validator.mcp.tools.query.query_arn_formats", _fake, raising=True)

    return _patch


# ---------------------------------------------------------------------------
# 1. Single-placeholder template (s3 bucket)
# ---------------------------------------------------------------------------


async def test_single_placeholder_via_placeholders_dict(stub_ctx, patch_arn_formats):
    patch_arn_formats(
        [
            {
                "resource_type": "bucket",
                "arn_formats": ["arn:${Partition}:s3:::${BucketName}"],
            }
        ]
    )
    result = await server.build_arn(
        service="s3",
        resource_type="bucket",
        ctx=stub_ctx,
        placeholders={"BucketName": "my-bucket"},
    )
    assert result["valid"] is True
    assert result["arn"] == "arn:aws:s3:::my-bucket"
    assert result["unfilled_placeholders"] == []


# ---------------------------------------------------------------------------
# 2. Multi-placeholder template (eks access-entry, all values provided)
# ---------------------------------------------------------------------------


async def test_multi_placeholder_template_fully_filled(stub_ctx, patch_arn_formats):
    template = (
        "arn:${Partition}:eks:${Region}:${Account}:access-entry/"
        "${ClusterName}/${IamIdentityType}/${IamIdentityAccountID}/"
        "${IamIdentityName}/${UUID}"
    )
    patch_arn_formats([{"resource_type": "access-entry", "arn_formats": [template]}])
    result = await server.build_arn(
        service="eks",
        resource_type="access-entry",
        ctx=stub_ctx,
        region="us-east-1",
        account_id="123456789012",
        placeholders={
            "ClusterName": "prod",
            "IamIdentityType": "user",
            "IamIdentityAccountID": "123456789012",
            "IamIdentityName": "alice",
            "UUID": "abcd-1234",
        },
    )
    assert result["valid"] is True
    assert result["unfilled_placeholders"] == []
    assert "${" not in result["arn"]
    assert "prod" in result["arn"] and "alice" in result["arn"]


# ---------------------------------------------------------------------------
# 3. Multi-placeholder template, missing values → valid=False with detail
# ---------------------------------------------------------------------------


async def test_multi_placeholder_missing_returns_unfilled(stub_ctx, patch_arn_formats):
    template = "arn:${Partition}:eks:${Region}:${Account}:access-entry/${ClusterName}/${UUID}"
    patch_arn_formats([{"resource_type": "access-entry", "arn_formats": [template]}])
    result = await server.build_arn(
        service="eks",
        resource_type="access-entry",
        ctx=stub_ctx,
        region="us-east-1",
        account_id="123456789012",
        placeholders={"ClusterName": "prod"},
    )
    assert result["valid"] is False
    assert "${UUID}" in result["unfilled_placeholders"]
    assert any("Unfilled placeholders" in note for note in result["notes"])


# ---------------------------------------------------------------------------
# 4. Bad partition → ToolError (input-validation, not data-incomplete)
# ---------------------------------------------------------------------------


async def test_bad_partition_raises_tool_error(stub_ctx, patch_arn_formats):
    patch_arn_formats([{"resource_type": "bucket", "arn_formats": ["arn:${Partition}:s3:::${BucketName}"]}])
    with pytest.raises(ToolError, match="Unsupported partition"):
        await server.build_arn(
            service="s3",
            resource_type="bucket",
            ctx=stub_ctx,
            partition="aws-bogus",
        )


async def test_unknown_resource_type_raises_tool_error(stub_ctx, patch_arn_formats):
    patch_arn_formats([{"resource_type": "bucket", "arn_formats": ["arn:${Partition}:s3:::${BucketName}"]}])
    with pytest.raises(ToolError, match="Unknown resource_type"):
        await server.build_arn(
            service="s3",
            resource_type="nonexistent",
            ctx=stub_ctx,
        )


# ---------------------------------------------------------------------------
# 5. Deprecated resource_name shortcut (single-placeholder + warning)
# ---------------------------------------------------------------------------


async def test_resource_name_deprecation(stub_ctx, patch_arn_formats, caplog):
    patch_arn_formats([{"resource_type": "bucket", "arn_formats": ["arn:${Partition}:s3:::${BucketName}"]}])
    import logging as _logging

    with caplog.at_level(_logging.WARNING, logger="iam_validator.mcp.server"):
        result = await server.build_arn(
            service="s3",
            resource_type="bucket",
            ctx=stub_ctx,
            resource_name="legacy-bucket",
        )

    assert result["valid"] is True
    assert result["arn"] == "arn:aws:s3:::legacy-bucket"
    assert any("deprecated" in record.message.lower() for record in caplog.records), (
        "deprecation warning must be emitted"
    )


# ---------------------------------------------------------------------------
# Partition acceptance (aws-eusc, aws-iso* etc.)
# ---------------------------------------------------------------------------


async def test_eusc_partition_accepted(stub_ctx, patch_arn_formats):
    patch_arn_formats([{"resource_type": "bucket", "arn_formats": ["arn:${Partition}:s3:::${BucketName}"]}])
    result = await server.build_arn(
        service="s3",
        resource_type="bucket",
        ctx=stub_ctx,
        placeholders={"BucketName": "my-bucket"},
        partition="aws-eusc",
    )
    assert result["valid"] is True
    assert result["arn"] == "arn:aws-eusc:s3:::my-bucket"
